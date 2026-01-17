#ifndef STEGO_H
#define STEGO_H

#include <stddef.h>
#include <stdint.h>
#define KEY1_LEN 128   // must match everywhere
size_t encode_bmp_lsb(const char *in,const uint8_t *data,size_t len,const char *out,const char *key1,const char *extn);
size_t decode_bmp_lsb(const char *bmp,uint8_t *out,size_t max_len,char *key1_out,char *extn_out);
#endif