#include "crypto.h"
#include "wycheproof/aes_gcm.h"
#include "crypto.h"
#include "crypto_error.h"
#include "sa_interface.h"
#include "utest.h"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_JSON_SIZE 133600   // Adjust based on expected JSON size
#define MAX_TOKENS 8192       // Adjust based on JSON complexity

// Function to read JSON data from a file
char *read_json_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open file");
        return NULL;
    }

    char *json_data = (char *)malloc(MAX_JSON_SIZE);
    if (!json_data) {
        perror("Memory allocation failed");
        fclose(file);
        return NULL;
    }

    size_t bytes_read = fread(json_data, 1, MAX_JSON_SIZE - 1, file);
    json_data[bytes_read] = '\0';  // Ensure null termination

    fclose(file);
    return json_data;
}

// Function to extract JSON field values based on key
void extract_json_field(const char *json, jsmntok_t *tokens, int token_count, const char *key) {
    for (int i = 0; i < token_count - 1; i++) {
        if (tokens[i].type == JSMN_STRING && strncmp(json + tokens[i].start, key, tokens[i].end - tokens[i].start) == 0) {
            printf("%s: %.*s\n", key, tokens[i + 1].end - tokens[i + 1].start, json + tokens[i + 1].start);
        }
    }
}

// Function to print JSON key-value pairs properly
void print_json_field(const char *json, jsmntok_t *key_tok, jsmntok_t *val_tok) {
    if (val_tok->type == JSMN_STRING || val_tok->type == JSMN_PRIMITIVE) {
        printf("%.*s: %.*s\n",
               key_tok->end - key_tok->start, json + key_tok->start,
               val_tok->end - val_tok->start, json + val_tok->start);
    }
}

// Function to extract an integer from a JSON token
int extract_int_from_token(const char *json, jsmntok_t *tok) {
    char num_str[16];
    uint32_t len = tok->end - tok->start;
    if (len >= sizeof(num_str)) return -1;  // Prevent buffer overflow

    strncpy(num_str, json + tok->start, len);
    num_str[len] = '\0';

    return atoi(num_str);
}

int parse_tests(const char *json, jsmntok_t *tokens, int token_count, wycheproof_blk_json_object *tests, int max_tests);

// Function to extract a string from a JSON token
void extract_string(const char *json, jsmntok_t *tok, char *dest, size_t max_len) {
    size_t len = tok->end - tok->start;
    if (len >= max_len) len = max_len - 1;
    strncpy(dest, json + tok->start, len);
    dest[len] = '\0';
}

int parse_json() {
    const char *filename = "/home/jstar/Dev/cryptolib/test/include/wycheproof/aes_gcm.json";
    char *json = read_json_file(filename);
    if (!json) {
        return 1;  // Exit if file read failed
    }

    jsmn_parser parser;
    jsmntok_t tokens[MAX_TOKENS];

    jsmn_init(&parser);
    
    parse_tests(json, tokens, MAX_TOKENS, tests, 256);

    for(int i = 0; i < 256; i++){
        printf("Test ID: %d", tests->blk[i]->tcId);
    }

    free(json);
    return 0;
}

// Function to extract test cases into an array of structs
int parse_tests(const char *json, jsmntok_t *tokens, int token_count, wycheproof_blk_json_object *tests, int max_tests) {
    int test_index = 0;

    printf("inside parse_tests...\n");
    for (int i = 0; i < token_count; i++) {
        if (strncmp(json + tokens[i].start, "tcId", tokens[i].end - tokens[i].start) == 0) {
            if (test_index >= max_tests) {
                printf("break\n");
                break;  // Prevent overflow
            }

            wycheproof_json_object *test = tests->blk[test_index];  // Pointer to the current struct

            // Extract tcId
            test->tcId = atoi(json + tokens[i + 1].start);

            // Extract key-value pairs within this test case
            for (int j = i + 2; j < token_count - 1; j += 2) {
                if (tokens[j].type != JSMN_STRING) continue;

                else if (strncmp(json + tokens[j].start, "key", tokens[j].end - tokens[j].start) == 0)
                    extract_string(json, &tokens[j + 1], *test->key, sizeof(test->key));
                else if (strncmp(json + tokens[j].start, "iv", tokens[j].end - tokens[j].start) == 0)
                    extract_string(json, &tokens[j + 1], *test->iv, sizeof(test->iv));
                else if (strncmp(json + tokens[j].start, "aad", tokens[j].end - tokens[j].start) == 0)
                    extract_string(json, &tokens[j + 1], *test->aad, sizeof(test->aad));
                else if (strncmp(json + tokens[j].start, "msg", tokens[j].end - tokens[j].start) == 0)
                    extract_string(json, &tokens[j + 1], *test->msg, sizeof(test->msg));
                else if (strncmp(json + tokens[j].start, "ct", tokens[j].end - tokens[j].start) == 0)
                    extract_string(json, &tokens[j + 1], *test->ct, sizeof(test->ct));
                else if (strncmp(json + tokens[j].start, "tag", tokens[j].end - tokens[j].start) == 0)
                    extract_string(json, &tokens[j + 1], *test->tag, sizeof(test->tag));
                else if (strncmp(json + tokens[j].start, "result", tokens[j].end - tokens[j].start) == 0)
                    extract_string(json, &tokens[j + 1], *test->result, sizeof(test->result));

                // Stop when the next "tcId" appears
                if (tokens[j].type == JSMN_STRING &&
                    strncmp(json + tokens[j].start, "tcId", tokens[j].end - tokens[j].start) == 0) {
                    break;
                }
            }
        }
    }
    return test_index;
}


UTEST(AES_GCM, HAPPY_PATH_WYCHEPROOF)
{
    printf("start of UT...\n");
    remove("sa_save_file.bin");
    parse_json();
    // Setup & Initialize CryptoLib
    // Crypto_Init_TC_Unit_Test();
    // char *raw_tc_sdls_ping_h   = "20030015000080d2c70008197f0b00310000b1fe3128";
    // char *raw_tc_sdls_ping_b   = NULL;
    // int   raw_tc_sdls_ping_len = 0;

    // hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);

    // uint8_t *ptr_enc_frame = NULL;
    // uint16_t enc_frame_len = 0;

    // int32_t return_val = CRYPTO_LIB_ERROR;

    // return_val =
    //     Crypto_TC_ApplySecurity((uint8_t *)raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    // Crypto_Shutdown();
    // free(raw_tc_sdls_ping_b);
    // free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, 0);
}

UTEST_MAIN();