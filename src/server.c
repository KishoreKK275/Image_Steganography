#include "../include/mongoose.h"
#include "../include/http.h"
#include <stdio.h>
#include <stdlib.h>  // Add this for getenv()

// Remove the hardcoded PORT define

struct mg_mgr mgr;

static void server_handler(struct mg_connection *c, int ev, void *ev_data) {
    if (ev != MG_EV_HTTP_MSG) return;
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;

    if (mg_http_match_uri(hm, "/") || mg_http_match_uri(hm, "/*.html") ||
        mg_http_match_uri(hm, "/*.css") || mg_http_match_uri(hm, "/*.js")) {
        struct mg_http_serve_opts opts = { .root_dir = "server" };
        mg_http_serve_dir(c, hm, &opts);
        return;
    }

    if (mg_http_match_uri(hm, "/encode")) { handle_encode(c, hm); return; }
    if (mg_http_match_uri(hm, "/decode")) { handle_decode(c, hm); return; }

    mg_http_reply(c, 404, "", "Not Found\n");
}

int main(void) {
    mg_mgr_init(&mgr);
    
    // Dynamically get the port from environment (Render sets PORT)
    const char *port = getenv("PORT");
    if (!port) port = "8080";  // Default fallback for local testing
    char listen_addr[256];
    snprintf(listen_addr, sizeof(listen_addr), "0.0.0.0:%s", port);
    
    printf("Server running at http://%s\n", listen_addr);

    if (!mg_http_listen(&mgr, listen_addr, server_handler, NULL)) {
        fprintf(stderr, "Failed to bind\n");
        return 1;
    }

    for (;;) mg_mgr_poll(&mgr, 1000);
}