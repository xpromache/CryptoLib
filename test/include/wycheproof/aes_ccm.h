#ifndef WYCHEPROOF_UT_AES_CCM_H
#define WYCHEPROOF_UT_AES_CCM_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "crypto.h"
#include "shared_util.h"
#include "utest.h"
#include <stdio.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <yajl/yajl_parse.h>

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
    char iv[128];
    char aad[128];
    char msg[256];
    char ct[256];
    char tag[64];
    char result[16];
} AESTest;

AESTest tests[510];
TestSuite suites[102];

#ifdef __cplusplus
} /* Close scope of 'extern "C"' declaration which encloses file. */
#endif

#endif // WYCHEPROOF_UT_AES_CCM_H