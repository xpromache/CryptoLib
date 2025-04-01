#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utest.h"
#include "../include/wycheproof/aes_gcm.h"

#define MAX_TESTS 256

// Struct to store test case
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

    AESTest *test = &tests[test_count - 1]; // Current test case
    char value[257];
    strncpy(&value[0], (const char *)val, length);
    value[length] = '\0'; // Null-terminate

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

    if (strchr(num_str, '.') != NULL) {
        double float_val = atof(num_str);
        printf("Warning: Found floating-point number %f in JSON\n", float_val);
    } else {
        int int_val = atoi(num_str);
        if (strcmp(current_key, "tcId") == 0) {
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
    for (int i = 0; i < test_count; i++) {
        if(strlen(tests[i].aad) > 0) continue;
        printf("\nTest Case ID: %d\n", tests[i].tcId);
        printf("comment: %s\n", tests[i].comment);
        printf("key: %s\n", tests[i].key);
        printf("iv: %s\n", tests[i].iv);
        printf("aad: %s\n", tests[i].aad);
        printf("msg: %s\n", tests[i].msg);
        printf("ct: %s\n", tests[i].ct);
        printf("tag: %s\n", tests[i].tag);
        printf("result: %s\n", tests[i].result);
        printf("~~~~~~~~~~~~~~~~~~~~~~~~\n");

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

        printf("Setting up SA...\n");
        SecurityAssociation_t *test_association = NULL;
        test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
        sa_if->sa_get_from_spi(1, &test_association);
        test_association->sa_state = SA_NONE;
        sa_if->sa_get_from_spi(4, &test_association);
        test_association->sa_state = SA_OPERATIONAL;

        printf("Setting up Key...\n");
        test_association->ekid = 0;
        crypto_key_t *key = key_if->get_key(0);
        key->key_len = strlen(tests[i].key);
        for (int j = 0; j < (int)key->key_len; j++)
            key->value[j] = tests[i].key[j];

        printf("Setting up IV...\n");
        test_association->shivf_len = strlen(tests[i].iv);
        test_association->iv_len = strlen(tests[i].iv);
        for (int j = 0; j < test_association->iv_len; j++)
            test_association->iv[j] = tests[i].iv[j];

        printf("Setting up Mac...\n");
        test_association->stmacf_len = strlen(tests[i].tag);

        printf("Setting up ARSN...\n");
        test_association->arsnw_len = 1;
        test_association->arsnw = 5;
        
        printf("Setting up Assert Val...\n");
        int assert_val;
        if (strcmp(tests[i].result, "invalid") == 0)
        {
            assert_val = -1;
        }
        else
        {
            assert_val = 0;
        }
        
        printf("Setting up Test String...\n");
        // Test string
        char raw_tc_sdls_ping_h[1024]   = "20030015000004";
        strncat(raw_tc_sdls_ping_h, &tests[i].iv[0], test_association->iv_len);
        printf("Packet: %s\n", raw_tc_sdls_ping_h);
        strncat(raw_tc_sdls_ping_h, tests[i].msg, 256);
        printf("Packet: %s\n", raw_tc_sdls_ping_h);
        strncat(raw_tc_sdls_ping_h, tests[i].tag, test_association->stmacf_len);
        printf("Packet: %s\n", raw_tc_sdls_ping_h);

        char *raw_tc_sdls_ping_b   = NULL;
        int   raw_tc_sdls_ping_len = 0;
    
        hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);
    
        uint8_t *ptr_enc_frame = NULL;
        uint16_t enc_frame_len = 0;
        int32_t  return_val    = CRYPTO_LIB_SUCCESS;
        
        return_val =
            Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
        
        ASSERT_EQ(assert_val, return_val);
        Crypto_Shutdown();
        free(raw_tc_sdls_ping_b);
        free(test_association);
    }
    
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, 0);
}

UTEST_MAIN()
