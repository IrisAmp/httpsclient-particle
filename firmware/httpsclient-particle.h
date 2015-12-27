#pragma once

#include "application.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "matrixsslApi.h"
#include <string>

#define HTTPS_COMPLETE          1
#define HTTPS_ERROR            -1
#define ALLOW_ANON_CONNECTIONS  1
#define LOGGING_DEBUG

#define USE_RSA_CIPHER_SUITE
#define ID_RSA

int32_t httpsclientSetup(const char * host, const char * path);
int32_t sendHttpsRequest(std::string request);
void    httpsclientSetPath(const char * path);

#ifdef __cplusplus
}
#endif
