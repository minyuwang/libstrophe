#include <stdio.h>
#include <string.h>

#include <strophe.h>

static const char *g_peer_jid = NULL;
static const char *g_username = NULL;
static const char *g_password = NULL;

int handle_reply(xmpp_conn_t *const conn,
                 xmpp_stanza_t *const stanza,
                 void *const userdata)
{
    const char *type;
    (void)userdata;

    type = xmpp_stanza_get_type(stanza);
    if (strcmp(type, "result") == 0) {
       printf("Success\n");
    } else if (strcmp(type, "error") == 0) {
       fprintf(stderr, "ERROR: failed\n");
    } else {
      fprintf(stderr, "ERROR: unexpected type %s\n", type);
    }

    /* disconnect */
    xmpp_disconnect(conn);

    return 0;
}

void conn_handler(xmpp_conn_t *const conn,
                  const xmpp_conn_event_t status,
                  const int error,
                  xmpp_stream_error_t *const stream_error,
                  void *const userdata)
{
    xmpp_ctx_t *ctx = (xmpp_ctx_t *)userdata;
    xmpp_stanza_t *iq, *conn_request, *username, *password, *text;

    (void)error;
    (void)stream_error;

    if (status == XMPP_CONN_CONNECT) {
        char *uuid = xmpp_uuid_gen(ctx);

        fprintf(stderr, "DEBUG: connected\n");

        /* create iq stanza for request */
        iq = xmpp_iq_new(ctx, "get", uuid);

        //xmpp_stanza_set_from(iq, xmpp_conn_get_bound_jid(conn));
        xmpp_stanza_set_to(iq, g_peer_jid);

        conn_request = xmpp_stanza_new(ctx);
        xmpp_stanza_set_name(conn_request, "connectionRequest");
        xmpp_stanza_set_ns(conn_request, "urn:broadband-forum-org:cwmp:xmppConnReq-1-0");
        xmpp_stanza_add_child(iq, conn_request);
        xmpp_stanza_release(conn_request);

        username = xmpp_stanza_new(ctx);
        xmpp_stanza_set_name(username, "username");
        xmpp_stanza_add_child(conn_request, username);
        xmpp_stanza_release(username);

        text = xmpp_stanza_new(ctx);
        xmpp_stanza_set_text(text, g_username);
        xmpp_stanza_add_child(username, text);
        xmpp_stanza_release(text);

        password = xmpp_stanza_new(ctx);
        xmpp_stanza_set_name(password, "password");
        xmpp_stanza_add_child(conn_request, password);
        xmpp_stanza_release(password);

        text = xmpp_stanza_new(ctx);
        xmpp_stanza_set_text(text, g_password);
        xmpp_stanza_add_child(password, text);
        xmpp_stanza_release(text);

        /* set up reply handler */
        xmpp_id_handler_add(conn, handle_reply, uuid, ctx);

        /* send out the stanza */
        xmpp_send(conn, iq);

        /* release the stanza */
        xmpp_stanza_release(iq);
        xmpp_free(ctx, uuid);
    } else {
        fprintf(stderr, "DEBUG: disconnected\n");
        xmpp_stop(ctx);
    }
}

int main(int argc, char **argv)
{
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;
    xmpp_log_t *log;

    if (argc != 6) {
        fprintf(stderr, "Usage: cwmp_connect_request <jid> <jid_pass> <peer_jid> <username> <password>\n\n");
        return 1;
    }
    g_peer_jid = argv[3];
    g_username = argv[4];
    g_password = argv[5];

    /* initialize lib */
    xmpp_initialize();

    /* create a context */
    ctx = xmpp_ctx_new(NULL, xmpp_get_default_logger(XMPP_LEVEL_DEBUG));

    /* create a connection */
    conn = xmpp_conn_new(ctx);

    /* Deny plaintext connection */
    xmpp_conn_set_flags(conn, XMPP_CONN_FLAG_TRUST_TLS | XMPP_CONN_FLAG_MANDATORY_TLS);

    /* setup authentication information */
    xmpp_conn_set_jid(conn, argv[1]);
    xmpp_conn_set_pass(conn, argv[2]);

    /* initiate connection */
    xmpp_connect_client(conn, NULL, 0, conn_handler, ctx);

    /* start the event loop */
    xmpp_run(ctx);

    /* release our connection and context */
    xmpp_conn_release(conn);
    xmpp_ctx_free(ctx);

    /* shutdown lib */
    xmpp_shutdown();

    return 0;
}
