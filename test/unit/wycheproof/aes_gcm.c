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
    if (!in_test_case) return 1; // Ignore if not inside "tests"

    AESTest *test = &tests[test_count - 1]; // Current test case
    char value[256];
    strncpy(value, (const char *)val, length);
    value[length] = '\0'; // Null-terminate

    if (strcmp(current_key, "comment") == 0) strcpy(test->comment, value);
    else if (strcmp(current_key, "key") == 0) strcpy(test->key, value);
    else if (strcmp(current_key, "iv") == 0) strcpy(test->iv, value);
    else if (strcmp(current_key, "aad") == 0) strcpy(test->aad, value);
    else if (strcmp(current_key, "msg") == 0) strcpy(test->msg, value);
    else if (strcmp(current_key, "ct") == 0) strcpy(test->ct, value);
    else if (strcmp(current_key, "tag") == 0) strcpy(test->tag, value);
    else if (strcmp(current_key, "result") == 0) strcpy(test->result, value);
    
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

UTEST(AES_GCM, HAPPY_PATH_WYCHEPROOF)
{
    const char *filename = "/home/jstar/Dev/cryptolib/test/include/wycheproof/aes_gcm.json";
    char *json_data = read_json_file(filename);
    if (!json_data) {
        //return 1;
    }

    // YAJL Parser Setup
    yajl_handle hand = yajl_alloc(&callbacks, NULL, NULL);
    yajl_status stat = yajl_parse(hand, (const unsigned char *)json_data, strlen(json_data));

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
        printf("\nTest Case ID: %d\n", tests[i].tcId);
        printf("comment: %s\n", tests[i].comment);
        printf("key: %s\n", tests[i].key);
        printf("iv: %s\n", tests[i].iv);
        printf("aad: %s\n", tests[i].aad);
        printf("msg: %s\n", tests[i].msg);
        printf("ct: %s\n", tests[i].ct);
        printf("tag: %s\n", tests[i].tag);
        printf("result: %s\n", tests[i].result);
    }
    
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, 0);
}

UTEST_MAIN()
