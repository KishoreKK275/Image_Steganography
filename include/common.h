#ifndef COMMON_H
#define COMMON_H

#define MAGIC_STRING "#*"
#define MAX_SECRET_BUF_SIZE 1
#define MAX_IMAGE_BUF_SIZE (MAX_SECRET_BUF_SIZE * 8)
#define MAX_FILE_SUFFIX 16       // support .docx, .pdf etc.
// #define KEY1_LEN 10             // random generated key length

#define SUCCESS 0
#define FAILURE 1

// Temporary carrier BMP used during conversion
#define TMP_CARRIER_BMP "__carrier_tmp.bmp"
// #define MAGIC_STRING "AUTO"

typedef enum
{
    TYPE_IMAGE,
} FileType;

FileType detect_file_type(const char *carrier);

#endif
