#ifndef HTTP_H
#define HTTP_H

#include "mongoose.h"
// static char *strndup(const char *src, size_t n);
void register_http_handlers(struct mg_mgr *mgr);
void handle_encode(struct mg_connection *c, struct mg_http_message *hm);
void handle_decode(struct mg_connection *c, struct mg_http_message *hm);

#endif