#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utest.h"
#include "../include/wycheproof/aes_gcm.h"

#define MAX_TESTS 256
#define MAX_SUITES 42

// Struct to store test case and suite
typedef struct {
    int ivSize;
    int keySize;
    int tagSize;
    int numTests;
} TestSuite;

typedef struct {
    int tcId;
    char comment[256];
    char key[64];
    char iv[32];
    char aad[128];
    char msg[256];
    char ct[256];
    char tag[64];
    char result[16];
} AESTest;

// Global variables to hold current parsing state
AESTest tests[MAX_TESTS];
TestSuite suites[MAX_SUITES];
int suite_num = 0;
int test_count = 0;
char current_key[64];  // Holds the key name
int in_test_case = 0;  // Flag to track if we're inside a test case
int in_array = 0;

// YAJL Callback: Found a key (e.g., "tcId", "key", etc.)
static int handle_map_key(void *ctx, const unsigned char *key, size_t length) {
    (void)ctx;
    strncpy(current_key, (const char *)key, length);
    current_key[length] = '\0'; // Null-terminate
    return 1;
}

// YAJL Callback: Found a string value
static int handle_string(void *ctx, const unsigned char *val, size_t length) {
    (void)ctx;

    if (length > 256){
        length = 256;
    }

    if (!in_test_case) return 1; // Ignore if not inside "tests"

    char value[257];
    strncpy(&value[0], (const char *)val, length);
    value[length] = '\0'; // Null-terminate
    AESTest *test = &tests[test_count - 1]; // Current test case

    if (strcmp(current_key, "comment") == 0) strcpy(&test->comment[0], value);
    else if (strcmp(current_key, "key") == 0) strcpy(&test->key[0], value);
    else if (strcmp(current_key, "iv") == 0) strcpy(&test->iv[0], value);
    else if (strcmp(current_key, "aad") == 0) strcpy(&test->aad[0], value);
    else if (strcmp(current_key, "msg") == 0) strcpy(&test->msg[0], value);
    else if (strcmp(current_key, "ct") == 0) strcpy(&test->ct[0], value);
    else if (strcmp(current_key, "tag") == 0) strcpy(&test->tag[0], value);
    else if (strcmp(current_key, "result") == 0) strcpy(&test->result[0], value);
    
    return 1;
}

// YAJL Callback: Found an integer value (for tcId)
static int handle_integer(void *ctx, long long val) {
    (void)ctx;
    if (strcmp(current_key, "tcId") == 0) {
        tests[test_count].tcId = (int)val;
        test_count++;
        in_test_case = 1; // Mark that we're inside a test case
    }
    return 1;
}

// YAJL Callback: Found a floating-point number (e.g., for future extensions)
static int handle_double(void *ctx, double val) {
    (void)ctx;
    printf("Warning: Encountered a floating-point number: %f\n", val);
    return 1;
}

// YAJL Callback: Found a boolean value (true/false)
static int handle_boolean(void *ctx, int boolVal) {
    (void)ctx;
    char *boolStr = boolVal ? "true" : "false";

    if (strcmp(current_key, "result") == 0) {
        AESTest *test = &tests[test_count - 1];
        strncpy(test->result, boolStr, sizeof(test->result) - 1);
    }

    return 1;
}

// YAJL Callback: Found null value (can be extended for optional fields)
static int handle_null(void *ctx) {
    (void)ctx;
    return 1;
}

// YAJL Callback: Start of an object (e.g., a test case)
static int handle_start_map(void *ctx) {
    (void)ctx;
    return 1;
}

// YAJL Callback: End of an object
static int handle_end_map(void *ctx) {
    (void)ctx;
    in_test_case = 0; // Mark that we have exited a test case
    return 1;
}

// YAJL Callback: Start of an array
static int handle_start_array(void *ctx) {
    (void)ctx;
    in_array = 1;
    return 1;
}

// YAJL Callback: End of an array
static int handle_end_array(void *ctx) {
    (void)ctx;
    in_array = 0;
    return 1;
}

// YAJL Callback: Found a number (handles both int and float)
static int handle_number(void *ctx, const char *val, size_t length) {
    (void)ctx;
    char num_str[64];
    strncpy(num_str, val, length);
    num_str[length] = '\0';
    TestSuite *suite = &suites[suite_num];

    if (strchr(num_str, '.') != NULL) {
        double float_val = atof(num_str);
        printf("Warning: Found floating-point number %f in JSON\n", float_val);
    } else {
        int int_val = atoi(num_str);
        if (strcmp(current_key, "ivSize") == 0) {suite->ivSize = int_val;}
        else if (strcmp(current_key, "keySize") == 0) {suite->keySize = int_val;}
        else if (strcmp(current_key, "tagSize") == 0) {suite->tagSize = int_val;}
        else if (strcmp(current_key, "numTests") == 0) {suite->numTests = int_val; suite_num++;}
        else if (strcmp(current_key, "tcId") == 0) {
            tests[test_count].tcId = int_val;
            test_count++;
            in_test_case = 1;
        }
    }

    return 1;
}

// YAJL Callbacks Setup
static yajl_callbacks callbacks = {
    handle_null,           // null
    handle_boolean,        // boolean
    handle_integer,        // integer
    handle_double,         // double
    handle_number,
    handle_string,         // string
    handle_start_map,      // start map
    handle_map_key,        // map key
    handle_end_map,        // end map
    handle_start_array,    // start array
    handle_end_array      // end array
};

// Function to read JSON file
char *read_json_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *json_data = (char *)malloc(length + 1);
    if (!json_data) {
        perror("Memory allocation failed");
        fclose(file);
        return NULL;
    }

    fread(json_data, 1, length, file);
    fclose(file);
    json_data[length] = '\0'; // Ensure null termination

    return json_data;
}

UTEST(AES_GCM, HAPPY_PATH_TC_APPLY_WYCHEPROOF)
{
    const char *filename = "/home/jstar/Dev/cryptolib/test/include/wycheproof/aes_gcm.json";
    char *json_data = read_json_file(filename);
    void *ctx;
    int num_tests_ran = 0;

    printf("Read File: %s \n", filename);
    if (!json_data) {
        return;
    }

    // YAJL Parser Setup
    printf("Setting up YAJL...\n");
    yajl_handle hand = yajl_alloc(&callbacks, NULL, &ctx);
    yajl_status stat = yajl_parse(hand, (const unsigned char *)json_data, strlen(json_data));

    printf("YAJL set up!\n");
    if (stat != yajl_status_ok) {
        unsigned char *err = yajl_get_error(hand, 1, (const unsigned char *)json_data, strlen(json_data));
        fprintf(stderr, "Error: %s\n", err);
        yajl_free_error(hand, err);
        yajl_free(hand);
        free(json_data);
        //return 1;
    }

    yajl_complete_parse(hand);
    yajl_free(hand);
    free(json_data);

    // Print Parsed Test Cases
    printf("Parsed %d AES-GCM Test Cases:\n", test_count);

    remove("sa_save_file.bin");
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_INTERNAL, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_TRUE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, TC_OCF_NA, 1024,
    // AOS_FHEC_NA, AOS_IZ_NA, 0);
    GvcidManagedParameters_t TC_UT_Managed_Parameters = {
        0, 0x0003, 0, TC_HAS_FECF, AOS_FHEC_NA, AOS_IZ_NA, 0, TC_NO_SEGMENT_HDRS, 1024, TC_OCF_NA, 1};
    Crypto_Config_Add_Gvcid_Managed_Parameters(TC_UT_Managed_Parameters);
    Crypto_Init();
    
    SecurityAssociation_t *test_association;
    crypto_key_t *key = key_if->get_key(250);
    key->key_state = KEY_ACTIVE;
    key = key_if->get_key(250);
    key->key_state = KEY_ACTIVE;

    printf("Setting up SA...\n");
    sa_if->sa_get_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    sa_if->sa_get_from_spi(4, &test_association);
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ekid = 250;

    printf("Setting up ARSN...\n");
    test_association->shsnf_len = 1;
    test_association->arsn_len = 1;
    test_association->arsn[0] = 0x00;
    test_association->arsnw_len = 1;
    test_association->arsnw = 5;

    int tcid = 0;
    for (int j = 0; j < MAX_SUITES; j++)
    {
        printf("j = %d\n", j);
        key->key_len = suites[j].keySize / 8;
        printf("KeyLen: %d\n", key->key_len);
        if (key->key_len != 32) 
        {
            tcid += suites[j].numTests;  
            printf("TCID: %d\n", tcid + 1);
            continue;
        }
        for (int i = 0; i < suites[j].numTests; i++) 
        {
            printf("TCID: %d\n", tcid + 1);

            printf("Setting up Key...\n");
            key->key_len = suites[j].keySize / 8;
            
            convert_hexstring_to_byte_array(tests[tcid].key, (char*)key->value);
            for (int k = 0; k < (int)key->key_len; k++)
            {
                printf("KeyVal: %02x\n", (uint8_t)key->value[k]);
            }

            printf("Setting up IV...\n");
            test_association->shivf_len = suites[j].ivSize / 8;
            test_association->iv_len = suites[j].ivSize / 8;
            printf("IVLen: %d\n", test_association->iv_len);
            convert_hexstring_to_byte_array(tests[tcid].iv, (char*)test_association->iv);
            for (int k = 0; k < test_association->iv_len; k++)
            {
                printf("IVVal: %02x\n", test_association->iv[k]);
            }

            printf("Setting up Mac...\n");
            test_association->stmacf_len = suites[j].tagSize / 8;
            printf("MACLen: %d\n", test_association->stmacf_len);

            printf("Setting up ARSN...\n");
            test_association->shsnf_len = 1;
            test_association->arsn_len = 1;
            test_association->arsn[0] = 0x00;
            test_association->arsnw_len = 1;
            test_association->arsnw = 5;
            
            printf("Setting up Assert Val...\n");
            int assert_val;
            if (strcmp(tests[tcid].result, "invalid") == 0)
            {
                assert_val = 999;
            }
            else
            {
                assert_val = 0;
            }
            printf("Assert Val = %d\n", assert_val);
            
            printf("Setting up Test String...\n");
        
            char *frameLength = "002B00";
            char *second = "0004";
            // Test string
            char raw_tc_sdls_ping_h[1024]   = "2003";
            strncat(raw_tc_sdls_ping_h, frameLength, 6);
            printf("Packet: %s\n", raw_tc_sdls_ping_h);
            strncat(raw_tc_sdls_ping_h, second, 4);
            printf("Packet: %s\n", raw_tc_sdls_ping_h);
            strncat(raw_tc_sdls_ping_h, tests[tcid].iv, test_association->iv_len * 2);
            printf("Packet: %s\n", raw_tc_sdls_ping_h);
            // arsn??
            strncat(raw_tc_sdls_ping_h, tests[tcid].msg, 256);
            printf("Packet: %s\n", raw_tc_sdls_ping_h);
            strncat(raw_tc_sdls_ping_h, tests[tcid].tag, test_association->stmacf_len * 2);
            printf("Packet: %s\n", raw_tc_sdls_ping_h);

            char *raw_tc_sdls_ping_b   = NULL;
            int   raw_tc_sdls_ping_len = 0;
        
            hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);
        
            uint8_t *ptr_enc_frame = NULL;
            uint16_t enc_frame_len = 0;
            int32_t  return_val    = CRYPTO_LIB_SUCCESS;
            
            return_val =
                Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
            
            if (assert_val != 0)
            {
                printf(KRED "Expected to fail, but passed\n" RESET);
                ASSERT_NE(0, return_val);
            }
            else
            {
                ASSERT_EQ(assert_val, return_val);
            }
            num_tests_ran++;
        }
        tcid++;
    }
    printf("Number of Tests Ran: %d\n", num_tests_ran);
    Crypto_Shutdown();
}

UTEST_MAIN()
