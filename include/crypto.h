#ifndef CRYPTO_H
#define CRYPTO_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

bool aes_encrypt(uint8_t *in, size_t in_len, const char *pwd, uint8_t **out, size_t *out_len);
bool aes_decrypt(uint8_t *in, size_t in_len, const char *pwd, uint8_t **out, size_t *out_len);

#endif