#ifndef VERUSHASHVERIFY_H
#define VERUSHASHVERIFY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void verushash2b2(char* input, char* output, int input_len);
void verushash2b2o(char* input, char* output, int input_len);
void verushash2b1(char* input, char* output, int input_len);
void verushash2b(char* input, char* output, int input_len);
void verushash2(char* input, char* output, int input_len);
void verushash(char* input, char* output, int input_len);

#ifdef __cplusplus
}
#endif

#endif