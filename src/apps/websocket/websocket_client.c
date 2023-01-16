/**
 * @file
 * websocket client
 *
 * @defgroup websocket websocket client
 * @ingroup apps
 * @verbinclude websocket_client.txt
 */

/*
 * Copyright (c) 2022 Timothy Graefe <tgraefe@javamata.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is contributed to the lwIP TCP/IP stack
 *
 * Author: Timothy Graefe <tgraefe@javamata.net>
 *
 *  Adapted from example HTTP code in SDK (copyright notice below)
 *
 *
 */

/*
 * Copyright (c) 2018 Simon Goldschmidt <goldsimon@gmx.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Simon Goldschmidt <goldsimon@gmx.de>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lwip/altcp.h"
#include "lwip/altcp_tcp.h"
#include "lwip/altcp_tls.h"
#include "lwip/dns.h"
#include "lwip/debug.h"
#include "lwip/mem.h"
#include "lwip/init.h"
#include "lwip/apps/http_client.h"
#include "lwip/apps/websocket_client.h"
#include "lws-sha1-base64.h"

#ifndef LWIP_ALTCP
#error "NEED LWIP_ALTCP"
#endif

#ifndef LWIP_ALTCP_TLS
#error "NEED LWIP_ALTCP_TLS"
#endif

#ifndef LWIP_DNS
#error "NEED LWIP_DNS"
#endif

// function trace for debugging
#define FNTRACE()   if(wsverbose) { printf("%s\n", __func__); }

#define WSOCK_POLL_INTERVAL         1
#define WSOCK_POLL_TIMEOUT          1000
#define WSOCK_CONTENT_LEN_INVALID   0xFFFFFFFF

static err_t wsock_tcp_recv(void *arg, struct altcp_pcb *pcb, struct pbuf *p, err_t r);
static void wsock_tcp_err(void *arg, err_t err);
static err_t wsock_tcp_poll(void *arg, struct altcp_pcb *pcb);
static err_t wsock_tcp_sent(void *arg, struct altcp_pcb *pcb, u16_t len);
static void wsock_invoke_app(wsock_state_t *pws, struct pbuf *pb);
static err_t wsock_connect_dns(wsock_state_t* pws, const char* srvname);

static int wsock_create_handshake(const char* host, const char *wspath, u16_t port,
                                  const char *keyhdr, int keylen,
                                  const char *auth, const char *orighdr, const char *prothdr,
                                  const char *xhdr, const char *xval,
                                  char *buf, size_t blen);

static void wsock_hexdump(unsigned char *buf, size_t len);

int wsverbose = 0;

/**
 *  Initialize the websocket state structure.  The memory for the structure
 *  must be allocated by the user and passed into this function.
 *
 *  @param  ssl_enabled     SSL enabled
 *  @param  ping_enabled    websocket ping enabled
 *  @param  message_handler user callback function
 *  @param  pws             pointer to user's memory
 */
err_t
wsock_init(wsock_state_t *pws, int ssl_enabled, int ping_enabled, wsapp_fn message_handler)
{
    FNTRACE();

    int     n;
    char    keybuf[WSOCK_KEY_BUF_SIZE], keyhash[WSOCK_KEY_HASH_SIZE];

    // Initialize the websocket state struct
    LWIP_ASSERT("pws != NULL", pws != NULL);
    bzero((char *)pws, sizeof(wsock_state_t));

    pws->ssl_enabled     = ssl_enabled;
    pws->ping_enabled    = ping_enabled;
    pws->message_handler = message_handler;

    if(pws->ssl_enabled)
    {
        const u8_t  *cert = NULL;
        size_t      cert_len = 0;

        // Client TLS config may optionally take a certificate authority and
        // certificate length.  For now, we do not have this.
        struct altcp_tls_config *pconf = altcp_tls_create_config_client(cert, cert_len);
        LWIP_ASSERT("pconf != NULL", pconf != NULL);

        // Allocate the TLS protocol control block.
        pws->pcb = altcp_tls_new(pconf, IPADDR_TYPE_ANY);
    }
    else // Allocate a non-SSL TCP protocol control block.
        pws->pcb = altcp_new(NULL);

    LWIP_ASSERT("pws->pcb != NULL", pws->pcb != NULL);

    // Generate a websocket key for the session - needed for both SSL and non-SSL.
    bzero(keybuf, sizeof(keybuf));
    bzero(keyhash, sizeof(keyhash));

    // read 16 random bytes into keyhash
    for(int i = 0; i <= 16; i++) keyhash[i] = rand();

    // generate the key string and store it in the session client_key
    lws_b64_encode_string(keyhash, 16, &(pws->client_key[0]), WSOCK_KEY_SIZE);
    pws->client_key[39] = '\0'; // enforce composed length below keybuf sizeof

    // generate the expected server response and store it in the ws state
    n = sprintf(keybuf, "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", pws->client_key);
    lws_SHA1((unsigned char *)keybuf, (unsigned int)n, (unsigned char *)keyhash);
    lws_b64_encode_string(keyhash, 20, &(pws->server_rsp[0]), WSOCK_KEY_SIZE);

    // Release the connection after idle timeout.
    pws->timeout_ticks = WSOCK_POLL_TIMEOUT;

    // Initialize the protocol control block.  The pcb function table is different
    // depending on whether a TLS or TCP control block was allocated.
    // Note that (wsock_state_t *pws) is the user argument.
    altcp_arg(pws->pcb,  pws);
    altcp_recv(pws->pcb, wsock_tcp_recv);
    altcp_err(pws->pcb,  wsock_tcp_err);
    altcp_poll(pws->pcb, wsock_tcp_poll, WSOCK_POLL_INTERVAL);
    altcp_sent(pws->pcb, wsock_tcp_sent);

    pws->state0          = PWS_STATE_INITD;
    pws->state1          = PWS_STATE_INITD;

    return ERR_OK;
}

// Provide a bearer token for authorization.
//const char *bearer_token = "my_bearer_token";

/**
 *  Open a websocket connection to a server.  'pws' must be allocated and
 *  initialized by the user, and passed into this function.
 *
 *  @param  pws     pointer to user's websocket state structure
 *  @param  srvname destination host
 *  @param  wspath  websocket sub-protocol (optional)
 *  @param  port    destination port
 */
err_t
wsock_connect(wsock_state_t *pws, const char *srvname, const char *wspath, u16_t port,
              const char *bearer_token, const char *subproto,
              const char *extrahdr,     const char *extrahdrval)
{
    FNTRACE();

    int     len;
    err_t   err;

    LWIP_ASSERT("pws != NULL", pws != NULL);
    LWIP_ASSERT("pws->pcb != NULL", pws->pcb != NULL);
    LWIP_ASSERT("pws->state0 == alloc'd", (pws->state0 == PWS_STATE_INITD));
    LWIP_ASSERT("pws->state1 == alloc'd", (pws->state1 == PWS_STATE_INITD));

    // Calculate the required length of the websocket GET/handshake request.
    // wsock_create_handshake()  returns the length, but nothing is copied since
    // NULL/0 were passed in the arguments.
    len = wsock_create_handshake(srvname, wspath, port,
                                 pws->client_key, strlen(pws->client_key),
                                 bearer_token,
                                 NULL,             // origin header - TODO this should be the local host
                                 subproto,         // sub-protocol header
                                 extrahdr,         // extra header
                                 extrahdrval,      // extra header value
                                 NULL, 0);         // user buffer

    if((len < 0) || (len > 0xFFFF))
        return ERR_VAL;

    if(wsverbose)
        printf("allocating handshake buffer: %d bytes\n", len);

    // Allocate the buffer; it cannot be chained.
    pws->request = pbuf_alloc(PBUF_RAW, (u16_t)(len + 1), PBUF_RAM);

    if(pws->request == NULL)
        return ERR_MEM;

    if(pws->request->next != NULL)
    {
        pbuf_free(pws->request);
        return ERR_MEM;
    }

    if(wsverbose)
        printf("==> ALLOC'D pbuf 1: %d bytes\n", len);

    pws->hdr_content_len = WSOCK_CONTENT_LEN_INVALID;
    pws->remote_port     = port;

    // Now create the request buffer - same call as before, but this time
    // pass in a pointer to a real buffer.  snprintf writes formatted data
    // into 'payload' and should return the same length as before.
    len = wsock_create_handshake(srvname, wspath, port,
                                 pws->client_key, strlen(pws->client_key),
                                 bearer_token,
                                 NULL,             // origin header - TODO this should be the local host
                                 subproto,         // sub-protocol header
                                 extrahdr,         // extra header
                                 extrahdrval,      // extra header value
                                 (char *)pws->request->payload, len + 1); // user buffer

    if(wsverbose)
        printf("HANDSHAKE: %s\n", pws->request->payload);

    // Finally, connect to the server and send the request.
    err = wsock_connect_dns(pws, srvname);
    if(err == ERR_OK)
        pws->tcp_state = WS_TCP_CONNECTING;

    return err;
}

/**
 *  Handle callback from the TCP layer
 *
 *  @param  arg user opaque pointer
 *  @param  pcb protocol control block (TCP/LWIP layer)
 *  @param  err ignore
 */
static err_t
wsock_tcp_connected(void *arg, struct altcp_pcb *pcb, err_t err)
{
    FNTRACE();
    LWIP_UNUSED_ARG(pcb);
    LWIP_UNUSED_ARG(err);

    err_t           txerr;
    wsock_state_t   *pws = (wsock_state_t*)arg;

    pws->tcp_state = WS_TCP_CONNECTED;

    // send the websocket handshake; last char is zero termination
    txerr = altcp_write(pws->pcb,
                        pws->request->payload,
                        pws->request->len - 1,
                        TCP_WRITE_FLAG_COPY);

    if (txerr != ERR_OK)
    {
        printf("altcp_write() failed: %s(%d)\n", err2str(txerr), txerr);
        return wsock_close(pws, WSOCK_RESULT_ERR_MEM, txerr);
    }

    // handshake was sent; we can free the request
    if(wsverbose)
        printf("==> FREE'ING pbuf\n");
    pbuf_free(pws->request);
    pws->request = NULL;

    // send data written to the socket
    altcp_output(pws->pcb);
    return ERR_OK;
}

/**
 *  Connect to host address
 *
 *  @param  pws     pointer to user's websocket state structure
 *  @param  ipaddr  host address
 */
static err_t
wsock_connect_addr(wsock_state_t *pws, const ip_addr_t *ipaddr)
{
    FNTRACE();
    err_t err;

    LWIP_ASSERT("pws != NULL", pws != NULL);
    LWIP_ASSERT("pws->pcb != NULL", pws->pcb != NULL);
    LWIP_ASSERT("pws->state0 == alloc'd", (pws->state0 == PWS_STATE_INITD));
    LWIP_ASSERT("pws->state1 == alloc'd", (pws->state1 == PWS_STATE_INITD));

    // fill in remote addr if needed
    if(ipaddr)
    {
        if(&pws->remote_addr != ipaddr)
        {
            printf("filling in remote_addr\n", (int)err);
            pws->remote_addr = *ipaddr;
        }
    }
    else
    {
        printf("null ipaddr\n");
        return ERR_MEM;
    }

    // Open the websocket connection via tcp_connect
    // altcp_connect() is the "application layer" tcp connect which allows
    // you to add a layer between your application and TCP, e.g., for TLS.
    // In either case, wsock_tcp_connected is the callback.
    if(wsverbose)
    {
        printf("attempting altcp_connect to %s://0x%0x:%d\n",
            (pws->ssl_enabled ? "wss" : "ws"),
            &pws->remote_addr,
            pws->remote_port);
    }

    err = altcp_connect(pws->pcb, &pws->remote_addr, pws->remote_port, wsock_tcp_connected);
    if (err == ERR_OK)
        return ERR_OK;

    printf("altcp_connect failed: %d\n", (int)err);
    return err;
}

/**
 *  DNS callback
 *
 *  If ipaddr is non-NULL, DNS resolution succeeded and the
 *  request can be sent,  otherwise it failed.
 *
 *  @param  hostname    destination host
 *  @param  ipaddr      destination IP
 *  @param  arg         opaque user pointer - used for pws
 */
static void
wsock_dns_found(const char* hostname, const ip_addr_t *ipaddr, void *arg)
{
    FNTRACE();

    err_t err;
    wsock_result_t result;

    wsock_state_t* pws = (wsock_state_t*)arg;

    LWIP_ASSERT("pws != NULL", pws != NULL);
    LWIP_ASSERT("pws->pcb != NULL", pws->pcb != NULL);
    LWIP_ASSERT("pws->state0 == alloc'd", (pws->state0 == PWS_STATE_INITD));
    LWIP_ASSERT("pws->state1 == alloc'd", (pws->state1 == PWS_STATE_INITD));

    if(wsverbose)
        printf("wsock_dns_found: hostname: %s\n", hostname);

    if (ipaddr != NULL)
    {
        err = wsock_connect_addr(pws, ipaddr);
        if (err == ERR_OK)
            return;

        result = WSOCK_RESULT_ERR_CONNECT;
    }
    else
    {
        printf("wsock_dns_found: failed to resolve hostname: %s\n", hostname);
        result = WSOCK_RESULT_ERR_HOSTNAME;
        err = ERR_ARG;
    }

    wsock_close(pws, result, err);
}

/**
 *  Use DNS to resolve the destination host IP
 *
 *  @param  pws     pointer to user's websocket state structure
 *  @param  srvname destination host
 */
static err_t
wsock_connect_dns(wsock_state_t* pws, const char* srvname)
{
    FNTRACE();
    err_t err;

    LWIP_ASSERT("pws != NULL", pws != NULL);
    LWIP_ASSERT("pws->pcb != NULL", pws->pcb != NULL);
    LWIP_ASSERT("pws->state0 == alloc'd", (pws->state0 == PWS_STATE_INITD));
    LWIP_ASSERT("pws->state1 == alloc'd", (pws->state1 == PWS_STATE_INITD));

    // Use LWIP DNS to get the destination IP; wsock_dns_found is the callback.
    err = dns_gethostbyname(srvname, &pws->remote_addr, wsock_dns_found, pws);

    if (err == ERR_OK)
    {
        printf("connecting valid IP\n");
        err = wsock_connect_addr(pws, &pws->remote_addr);
    }
    else if (err == ERR_INPROGRESS)
    {
        if(wsverbose) printf("DNS in progress\n");
        return ERR_OK;
    }
    printf("DNS unexpected error: %s\n", err2str(err));

    return err;
}

/**
 *  Close an open websocket connection
 *
 *  @param  result  used for trace only
 *  @param  err     used for trace only
 */
err_t wsock_close(wsock_state_t *pws, wsock_result_t result, err_t err)
{
    FNTRACE();

    LWIP_ASSERT("pws != NULL", pws != NULL);
    LWIP_ASSERT("pws->pcb != NULL", pws->pcb != NULL);
    LWIP_ASSERT("pws->state0 == alloc'd", (pws->state0 == PWS_STATE_INITD));
    LWIP_ASSERT("pws->state1 == alloc'd", (pws->state1 == PWS_STATE_INITD));

    err_t   close_err = err;

    // result and err are for trace only.
    if(wsverbose)
        printf("wsock_close() result: %s err: %s\n", wsock2str(result), err2str(err));

    // Free any buffers currently held by the wsock.
    if (pws->request != NULL)
    {
        printf("==> FREE'ING pbuf in wsock_close()\n");
        pbuf_free(pws->request);
        pws->request = NULL;
    }

    // Null the entire protocol control block
    if(pws->pcb)
    {
        altcp_arg(pws->pcb, NULL);
        altcp_recv(pws->pcb, NULL);
        altcp_err(pws->pcb, NULL);
        altcp_poll(pws->pcb, NULL, 0);
        altcp_sent(pws->pcb, NULL);

        // Close the connection via application layer TCP.
        if(altcp_close(pws->pcb) != ERR_OK)
        {
            altcp_abort(pws->pcb);
            close_err = ERR_ABRT;
        }

        pws->pcb = NULL;
    }

    pws->tcp_state = WS_TCP_CLOSED;
    pws->state0    = PWS_STATE_DONE;
    pws->state1    = PWS_STATE_DONE;
    return close_err;
}

/**
 *  Parse server response to the handshake (HTTP header response line 1)
 *
 *  @param  p                       received buffer (headers)
 *  @param  http_version            received HTTP version
 *  @param  http_status             received HTTP status
 *  @param  http_status_str_offset  offset of header into the received buffer
 */
static err_t
wsock_parse_response_status(struct pbuf *p,
                            u16_t *http_version,
                            u16_t *http_status,
                            u16_t *http_status_str_offset)
{
    u16_t end1 = pbuf_memfind(p, "\r\n", 2, 0);
    FNTRACE();
    if (end1 != 0xFFFF)
    {
        /* get parts of first line */
        u16_t space1, space2;
        space1 = pbuf_memfind(p, " ", 1, 0);
        if (space1 != 0xFFFF)
        {
            if ((pbuf_memcmp(p, 0, "HTTP/", 5) == 0)  && (pbuf_get_at(p, 6) == '.'))
            {
                char status_num[10];
                size_t status_num_len;

                /* parse http version */
                u16_t version = pbuf_get_at(p, 5) - '0';
                version <<= 8;
                version |= pbuf_get_at(p, 7) - '0';
                *http_version = version;

                /* parse http status number */
                space2 = pbuf_memfind(p, " ", 1, space1 + 1);
                if (space2 != 0xFFFF)
                {
                    *http_status_str_offset = space2 + 1;
                    status_num_len = space2 - space1 - 1;
                }
                else
                    status_num_len = end1 - space1 - 1;

                memset(status_num, 0, sizeof(status_num));

                if( pbuf_copy_partial(p, status_num,
                                      (u16_t) status_num_len, space1 + 1) == status_num_len)
                {
                    int status = atoi(status_num);
                    if ((status > 0) && (status <= 0xFFFF))
                    {
                        *http_status = (u16_t)status;
                        return ERR_OK;
                    }
                }
            }
        }
    }
    return ERR_VAL;
}

/**
 *  State machine to wait for HTTP headers - adapted for websocket.
 *
 *  Wait for all headers to be received, return their length and the
 *  content_length (if available)
 *
 *  @param  p                   received buffer (headers)
 *  @param  content_length      received content length header
 *  @param  total_header_len    total length of received headers
 */
static err_t
wsock_wait_headers(struct pbuf *p, u32_t *content_length, u16_t *total_header_len)
{
    FNTRACE();
    u16_t end1 = pbuf_memfind(p, "\r\n\r\n", 4, 0);

    if (end1 < (0xFFFF - 2))
    {
        /* all headers received */

        /* check if we have a content length (@todo: case insensitive?) */
        u16_t content_len_hdr;

        *content_length   = WSOCK_CONTENT_LEN_INVALID;
        *total_header_len = end1 + 4;

        content_len_hdr = pbuf_memfind(p, "Content-Length: ", 16, 0);
        if (content_len_hdr != 0xFFFF)
        {
            u16_t content_len_line_end = pbuf_memfind(p, "\r\n", 2, content_len_hdr);
            if (content_len_line_end != 0xFFFF)
            {
                char content_len_num[16];
                u16_t content_len_num_len = (u16_t)(content_len_line_end - content_len_hdr - 16);
                memset(content_len_num, 0, sizeof(content_len_num));

                if (pbuf_copy_partial(p, content_len_num, content_len_num_len, content_len_hdr + 16) == content_len_num_len)
                {
                    int len = atoi(content_len_num);
                    if ((len >= 0) && ((u32_t)len < WSOCK_CONTENT_LEN_INVALID))
                        *content_length = (u32_t)len;
                }
            }
        }
        return ERR_OK;
    }
    return ERR_VAL;
}

/**
 *  Check if a received message is a web socket protocol control message
 *
 *  @param  pws pointer to user's websocket state structure
 *  @param  pb  received buffer (websocket data)
 */
static int
wsock_controlmsg(wsock_state_t *pws, struct pbuf *pb)
{
    if(wsverbose) FNTRACE();

    LWIP_ASSERT("pws != NULL", pws != NULL);
    LWIP_ASSERT("pws->pcb != NULL", pws->pcb != NULL);
    LWIP_ASSERT("pws->state0 == alloc'd", (pws->state0 == PWS_STATE_INITD));
    LWIP_ASSERT("pws->state1 == alloc'd", (pws->state1 == PWS_STATE_INITD));

    char    *pktbuf = (char *) (pb->payload);
    uint8_t opcode  = pktbuf[0] & WSHDRBITS_OPCODE;
    uint8_t paylen  = pktbuf[1] & WSHDRBITS_PAYLOAD_LEN;

    if(opcode == OPCODE_PONG)
    {
        pws->pong_rcvd++;
        if(wsverbose)
            printf("ping/PONG: %d/%d\n\n", pws->ping_sent, pws->pong_rcvd);
        pws->pong_pending = 0;
        pws->ping_wait = WSPING_WAITS;
        return 1;
    }

    if(opcode == OPCODE_PING)
    {
        char *paybuf = pktbuf + WSHDRLEN_MIN;
        pws->ping_rcvd++;
        if(wsverbose)
            printf("PING/pong: %d/%d\n\n", pws->ping_rcvd, pws->pong_sent);

        // Consider ping from the server as good as a pong.
        pws->pong_pending = 0;
        pws->send_pong    = 1;

        // Copy the ping payload into our pong payload buffer.  It must
        // be masked and sent to the server in the response.
        if(paylen > WSPONG_MAX_PAYLOAD)
            pws->ponglen = 0;   // We can't support a large pong payload.
        else
            pws->ponglen = paylen;

        memcpy(&(pws->pong_payload[0]), paybuf, paylen);

        return 1;
    }

    if(opcode == OPCODE_CLOSE)
    {
        printf("received CLOSE from the websocket server\n");
        pws->pong_pending = 0;
        pws->send_pong = 0;
        pws->wsclose_rcvd = 1;
        return 1;
    }

    return 0;
}

/**
 *  Callback from the TCP layer - adapted from http client example
 *
 *  @param  arg user opaque pointer
 *  @param  pcb protocol control block
 *  @param  pb  received buffer
 *  @param  err TCP layer error
 */
static err_t
wsock_tcp_recv(void *arg, struct altcp_pcb *pcb, struct pbuf *pb, err_t err)
{
    if(wsverbose) FNTRACE();

    wsock_state_t* pws = (wsock_state_t*)arg;

    LWIP_ASSERT("pws != NULL", pws != NULL);
    LWIP_ASSERT("pws->pcb != NULL", pws->pcb != NULL);
    LWIP_ASSERT("pws->state0 == alloc'd", (pws->state0 == PWS_STATE_INITD));
    LWIP_ASSERT("pws->state1 == alloc'd", (pws->state1 == PWS_STATE_INITD));

    if( (err != ERR_OK) || (pb == NULL) )
    {
        // Unexpected error (possibly closed by other side)
        printf("unexpected error in wsock_tcp_recv()\n");
        printf("wsock_tcp_recv(): %d %p %p\n", err, pb, pws);
        if(pb != NULL)
        {
            // Inform TCP we have taken the data
            altcp_recved(pcb, pb->tot_len);
            pbuf_free(pb);
        }
        return wsock_close(pws, WSOCK_RESULT_ERR_UNKNOWN, ERR_OK);
    }

    if (pb == NULL)
    {
        printf("closing with null pbuf in wsock_tcp_recv()\n");
        return wsock_close(pws, WSOCK_RESULT_ERR_MEM, ERR_OK);
    }

    if(wsverbose)
        printf("pb len: %d\n", pb->tot_len);

    // There are 3 parsing states: (1) wait first line, (2) wait headers, and (3) rx data
    if (pws->parse_state != WSOCK_PARSE_RX_DATA)
    {
        // Not in the receive data state, therefore awaiting the first line or headers.
        // Normal case is the handshake response.  It should be a single message
        // with headers and nothing else.

        // This is the first parsing state.
        if (pws->parse_state == WSOCK_PARSE_WAIT_FIRST_LINE)
        {
            u16_t status_str_off;
            err_t err = wsock_parse_response_status(pb,
                                                    &pws->rx_http_version,
                                                    &pws->rx_status,
                                                    &status_str_off);
            if (err == ERR_OK)
            {
                // transition to waiting for headers
                pws->parse_state = WSOCK_PARSE_WAIT_HEADERS;
                printf("parse_state to WSOCK_PARSE_WAIT_HEADERS\n");
                printf("parse_state http status from server: %d\n", pws->rx_status);
            }
            else
                printf("parse_state failed in WSOCK_PARSE_WAIT_FIRST_LINE\n");
        }

        // This is the second parsing state.  Either passed through from above,
        // or called back after concatenating to the first headers.
        if (pws->parse_state == WSOCK_PARSE_WAIT_HEADERS)
        {
            u16_t total_header_len;
            err_t err = wsock_wait_headers(pb,
                                           &pws->hdr_content_len,
                                           &total_header_len);
            if (err == ERR_OK)
            {
                printf("parse_state ERR_OK in WSOCK_PARSE_WAIT_HEADERS\n");
                printf("tot_len: %d hdr_content_len: %d total_header_len: %d\n",
                       pb->tot_len, pws->hdr_content_len, total_header_len);

                altcp_recved(pcb, pb->tot_len);
                pbuf_free(pb);

                // There should be no data following headers.  At this point,
                // set the state to receive data and return.
                pws->parse_state = WSOCK_PARSE_RX_DATA;
                return ERR_OK;
            }
        }
    }

    // Connection is established and handshake completed.
    // Handle received data.
    if(pws->parse_state == WSOCK_PARSE_RX_DATA && (pb->tot_len > 0))
    {
        pws->rx_data_bytes += pb->tot_len;

        // received valid data; reset the timeout
        pws->timeout_ticks = WSOCK_POLL_TIMEOUT;
        if(!wsock_controlmsg(pws, pb))
        {
            // Hand off the message to the application layer.
            if(pws->message_handler)
                wsock_invoke_app(pws, pb);
            else
                printf("NO MESSAGE HANDLER FOR RECEIVED MESSAGE!!\n");
        }

        if(wsverbose)
            printf("freeing rcvd pbuf in wsock_tcp_recv()\n");

        // Inform TCP we have taken the data (and send TCP acks), and free the buffer.
        altcp_recved(pcb, pb->tot_len);
        pbuf_free(pb);
    }

    return ERR_OK;
}

/**
 *  Hand off received data to the application layer.
 *
 *  @param  pws pointer to user's websocket state structure
 *  @param  pb  received buffer (websocket data)
 */
static void
wsock_invoke_app(wsock_state_t *pws, struct pbuf *pb)
{
    if(wsverbose) FNTRACE();

    LWIP_ASSERT("pws != NULL", pws != NULL);
    LWIP_ASSERT("pws->pcb != NULL", pws->pcb != NULL);
    LWIP_ASSERT("pws->state0 == alloc'd", (pws->state0 == PWS_STATE_INITD));
    LWIP_ASSERT("pws->state1 == alloc'd", (pws->state1 == PWS_STATE_INITD));

    char    *pktbuf = (char *) (pb->payload);
    char    *paybuf = pktbuf + WSHDRLEN_MIN;
    uint8_t opcode  = pktbuf[0] & WSHDRBITS_OPCODE;
    uint8_t paylen  = pktbuf[1] & WSHDRBITS_PAYLOAD_LEN;

    if(opcode != OPCODE_TEXT)
    {
        printf("got invalid opcode: %d\n", opcode);
        return;
    }

    // tot_len is length of the received data
    if(paylen > pb->tot_len)
    {
        printf("got invalid size: %d bytes\n", paylen);
        return;
    }

    if( !(pb->tot_len > 0) )
    {
        printf("got invalid pbuf size: %d bytes\n", pb->tot_len);
        return;
    }

    if(wsverbose) printf("rcvd WS msg type: %s len %u\n", opcode2str(opcode), paylen);

    if(pws->message_handler)
        pws->message_handler(paybuf, paylen);
}


/**
 *  TCP error callback
 *
 *  @param  arg user opaque pointer
 *  @param  err TCP layer error
 */
static void
wsock_tcp_err(void *arg, err_t err)
{
    FNTRACE();
    wsock_state_t *pws = (wsock_state_t*)arg;

    printf("TCP closed unexpectedly: %s(%d)\n", err2str(err), err);
    wsock_close(pws, WSOCK_RESULT_ERR_CLOSED, err);
}

/*
 *
 *  Reference packet format from RFC 6455
 *

   0               1               2               3
   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
  +-+-+-+-+-------+-+-------------+-------------------------------+
  |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
  |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
  |N|V|V|V|       |S|             |   (if payload len==126/127)   |
  | |1|2|3|       |K|             |                               |
  +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
  |     Extended payload length continued, if payload len == 127  |
  + - - - - - - - - - - - - - - - +-------------------------------+
  |                               |Masking-key, if MASK set to 1  |
  +-------------------------------+-------------------------------+
  | Masking-key (continued)       |          Payload Data         |
  +-------------------------------- - - - - - - - - - - - - - - - +
  :                     Payload Data continued ...                :
  + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
  |                     Payload Data continued ...                |
  +---------------------------------------------------------------+

 */

/**
 *  websocket write interface
 *
 *  @param  pws     pointer to user's websocket state structure
 *  @param  buf     user's buffer with data to send
 *  @param  buflen  length of user's data
 *  @param  opcode  websocket protocol OP code
 */
err_t
wsock_write(wsock_state_t *pws, const char *buf, u16_t buflen, uint8_t opcode)
{
    if(wsverbose) FNTRACE();

    LWIP_ASSERT("pws != NULL", pws != NULL);
    LWIP_ASSERT("pws->pcb != NULL", pws->pcb != NULL);
    LWIP_ASSERT("pws->state0 == alloc'd", (pws->state0 == PWS_STATE_INITD));
    LWIP_ASSERT("pws->state1 == alloc'd", (pws->state1 == PWS_STATE_INITD));

    err_t   err;
    char    hdr[WSHDRLEN_MAX], *maskkey;
    size_t  hdrlen = WSHDRLEN_MIN, pktlen = 0;

    if((buflen > 0) && !buf)
        return ERR_VAL;

    if(pws->tcp_state != WS_TCP_CONNECTED)
    {
        printf("  wsock_write() tcp not connected (%d)\n", pws->tcp_state);
        return ERR_CONN;
    }

    // Generate the websocket header and calculate the length of the buffer
    // needed to hold both header and payload.

    // Header notes:
    // FIN/OPCODE/LEN - 2 bytes
    //      EXT LEN   - 0 bytes if LEN < 126
    //      EXT LEN   - 2 bytes if LEN == 126
    //      EXT LEN   - 8 bytes if LEN == 127
    // MASKING KEY    - 4 bytes if mask key is set (always true for client)
    // PAYLOAD DATA   - buflen bytes

    // Set OPCODE and mask bit.
    // OPCODE is always set the same way and MASK is always enabled for clients.
    hdr[0] = (WSHDRBITS_OPCODE & opcode);
    hdr[1] =  WSHDRBITS_MASKED;

    // Set FIN and length based on input buffer length.
    if(buflen <= WSLEN_SMALL)
    {
        hdr[0] |= WSHDRBITS_FIN;
        hdr[1] |= (WSHDRBITS_PAYLOAD_LEN & ((uint8_t) (buflen)) );
    }
    else if(buflen <= WSLEN_BIG)
    {
        hdrlen += WSHDRLEN_EXT16BITS;
        if(buflen < WSMSG_MAXSIZE)
            hdr[0] |= WSHDRBITS_FIN;
        hdr[1] |= WSHDRBITS_PAYLOAD_LEN_EXT16;
        uint16_t paylen = htons(buflen);
        memcpy(&hdr[WSHDRLEN_MIN], ((char *) &paylen), 2);
    }
    else
    {
        // Only support smaller payload sizes.
        printf("aborting due to oversize payload\n");
        return wsock_close(pws, WSOCK_RESULT_ERR_MEM, ERR_MEM);
    }

    // Generate the masking key
    maskkey = &hdr[hdrlen];
    for(int i = 0; i <= 4; i++) maskkey[i] = rand();
    hdrlen += WSHDRLEN_MASKKEY;

    // Final length of pbuf needed
    pktlen = hdrlen + buflen;

    // Allocate a request buffer, and write the data into the payload.
    pws->request = pbuf_alloc(PBUF_RAW, (u16_t)(pktlen), PBUF_RAM);
    if (pws->request == NULL)
    {
        printf("aborting due to pbuf_alloc() failed ...\n");
        return wsock_close(pws, WSOCK_RESULT_ERR_MEM, ERR_MEM);
    }

    if (pws->request->next != NULL)
    {
        // pbuf needs to be in one piece ...
        printf("aborting due to fragmented pbuf ...\n");
        return wsock_close(pws, WSOCK_RESULT_ERR_MEM, ERR_MEM);
    }

    if(wsverbose) printf("==> ALLOC'D pbuf 2 ...\n");

    // Copy the packet header into the pbuf request payload.
    memcpy(pws->request->payload, hdr, hdrlen);

    // Copy the masked buffer into the pbuf request payload, after the header.
    char *p = pws->request->payload + hdrlen;
    for(int i = 0; i < buflen; i++)
        p[i] = buf[i] ^ (maskkey[ i % 4 ]);

    // Set the request length.
    pws->request->len = pktlen;

    if(wsverbose)
    {
        printf("hdrlen: %u pktlen: %u buflen: %u\n", hdrlen, pktlen, buflen);
        wsock_hexdump(pws->request->payload, pktlen);
    }

    // write to the TCP layer
    err = altcp_write(pws->pcb, pws->request->payload, pws->request->len, TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK)
    {
        printf("altcp_write() failed - closing wsock\n");
        return wsock_close(pws, WSOCK_RESULT_ERR_UNKNOWN, err);
    }

    // success; free the request
    if(wsverbose)
        printf("==> FREE'ING pbuf\n");

    pbuf_free(pws->request);
    pws->request = NULL;

    altcp_output(pws->pcb);
    return ERR_OK;
}

/**
 *  TCP poll callback
 *
 *  Leveraged to trigger the websocket ping, if enabled.
 *
 *  @param  arg user opaque pointer
 *  @param  pcb protocol control block
 */
static err_t
wsock_tcp_poll(void *arg, struct altcp_pcb *pcb)
{
    if(wsverbose) FNTRACE();
    LWIP_UNUSED_ARG(pcb);
    err_t   err = ERR_OK;

    wsock_state_t* pws = (wsock_state_t*)arg;

    LWIP_ASSERT("pws != NULL", pws != NULL);
    LWIP_ASSERT("pws->pcb != NULL", pws->pcb != NULL);
    LWIP_ASSERT("pws->state0 == alloc'd", (pws->state0 == PWS_STATE_INITD));
    LWIP_ASSERT("pws->state1 == alloc'd", (pws->state1 == PWS_STATE_INITD));

    pws->tcp_polls++;

    // Close if the socket has been idle too long.
    if (pws->timeout_ticks > 0)
        pws->timeout_ticks--;
    if (!pws->timeout_ticks)
        return wsock_close(pws, WSOCK_RESULT_ERR_TIMEOUT, ERR_OK);

    if(pws->wsclose_rcvd)
        return wsock_close(pws, WSOCK_RESULT_FIN_CLOSED, ERR_OK);

    if(pws->tcp_state != WS_TCP_CONNECTED)
    {
        printf("wsock_tcp_poll TCP not connected\n");
        return ERR_OK;
    }

    // Send ping, if enabled.
    if(pws->ping_enabled && !pws->pong_pending)
    {
        if(pws->ping_wait > 0)
            pws->ping_wait--;
        else
        {
            pws->ping_wait = WSPING_WAITS;
            pws->pong_pending = 1;
            pws->ping_sent++;
            err = wsock_write(pws, NULL, 0, OPCODE_PING);
            if(err != ERR_OK)
                printf("sending ping failed\n");
        }
    }

    // If we have been pinged, send a pong.
    if(pws->send_pong)
    {
        pws->pong_sent++;
        pws->send_pong = 0;
        err = wsock_write(pws, &(pws->pong_payload[0]), pws->ponglen, OPCODE_PONG);
        if(err != ERR_OK)
            printf("sending ping failed\n");
    }

    // Don't return 'err' from above, or the TCP will close.
    return ERR_OK;
}

/** websocket client tcp sent callback */
static err_t
wsock_tcp_sent(void *arg, struct altcp_pcb *pcb, u16_t len)
{
    if(wsverbose) FNTRACE();

    // nothing to do here for now
    LWIP_UNUSED_ARG(arg);
    LWIP_UNUSED_ARG(pcb);
    LWIP_UNUSED_ARG(len);
    return ERR_OK;
}

// Create format strings for various headers in the websocket upgrade request.
const char *reqfmts  = "GET %s HTTP/1.1\r\n"            /* path                         */ \
                       "Host: %s:%d\r\n"                /* destination host             */ \
                       "Upgrade: websocket\r\n"         /* protocol upgrade headers     */ \
                       "Connection: Upgrade\r\n";       /* protocol upgrade headers     */
const char *authfmt  = "Authorization: bearer %s\r\n";  /* bearer token for auth        */
const char *extrafmt = "%s: %s\r\n";                    /* some other user header       */
const char *origfmt  = "Origin: bearer %s\r\n";         /* CSRF protection              */
const char *keyfmt   = "Sec-WebSocket-Key: %s\r\n";     /* calculated ws key            */
const char *protfmt  = "Sec-WebSocket-Protocol: %s\r\n";/* optional sub-protocol        */
const char *endfmt   = "Sec-WebSocket-Version: 13\r\n\r\n";

static int
wsock_create_handshake(const char* host, const char *wspath, u16_t port,
                       const char *keyhdr, int keylen,
                       const char *auth, const char *orighdr, const char *prothdr,
                       const char *xhdr, const char *xval,
                       char *buf, size_t blen)
{
    size_t  hslen = 0;

    // First, calculate the needed buffer size to hold the headers.

    // Required handshake header formats first
    hslen += snprintf(NULL, 0, reqfmts, wspath, host, port);

    // Calculate length for optional headers
    if(auth)         hslen += snprintf(NULL, 0, authfmt,  auth);
    if(xhdr && xval) hslen += snprintf(NULL, 0, extrafmt, xhdr, xval);
    if(orighdr)      hslen += snprintf(NULL, 0, origfmt,  orighdr);
    if(keyhdr)       hslen += snprintf(NULL, 0, keyfmt,   keyhdr);
    if(prothdr)      hslen += snprintf(NULL, 0, protfmt,  prothdr);

    // Use a common handshake header for the last format
    hslen += snprintf(NULL, 0, endfmt);

    // If we are only calculating length for the headers, then we're done.
    if(!buf) return hslen;

    // Now, exact same thing, but actually write to the buffer - only if
    // it is big enough.
    if(hslen > blen)
    {
        printf("header buffer too small\n");
        return -1;
    }

    sprintf(buf, reqfmts, wspath, host, port);

    if(auth)         sprintf(buf + strlen(buf), authfmt,  auth);
    if(xhdr && xval) sprintf(buf + strlen(buf), extrafmt, xhdr, xval);
    if(orighdr)      sprintf(buf + strlen(buf), origfmt,  orighdr);
    if(keyhdr)       sprintf(buf + strlen(buf), keyfmt,   keyhdr);
    if(prothdr)      sprintf(buf + strlen(buf), protfmt,  prothdr);

    sprintf(buf + strlen(buf), "%s", endfmt);

    return hslen;
}

// Utility functions
const char *wsstate2str(wsock_state_t *pws)
{
    if(!pws) return "WS_TCP_NULL";

    switch(pws->tcp_state)
    {
    case WS_TCP_CLOSED:     return "WS_TCP_CLOSED";
    case WS_TCP_CONNECTING: return "WS_TCP_CONNECTING";
    case WS_TCP_CONNECTED:  return "WS_TCP_CONNECTED";
    default:
        break;
    }
    return "WS_TCP_UNKNOWN";
}

const char *opcode2str(uint8_t opcode)
{
    switch(opcode)
    {
    case OPCODE_CONTINUATION:   return "OPCODE_CONTINUATION";
    case OPCODE_TEXT:           return "OPCODE_TEXT";
    case OPCODE_BINARY:         return "OPCODE_BINARY";
    case OPCODE_CLOSE:          return "OPCODE_CLOSE";
    case OPCODE_PING:           return "OPCODE_PING";
    case OPCODE_PONG:           return "OPCODE_PONG";
    default:
        break;
    }
    return "OPCODE_UNKNOWN";
}

const char *wsock2str(wsock_result_t resval)
{
    switch(resval)
    {
    case WSOCK_RESULT_OK:               return "WSOCK_RESULT_OK";
    case WSOCK_RESULT_ERR_UNKNOWN:      return "WSOCK_RESULT_ERR_UNKNOWN";
    case WSOCK_RESULT_ERR_CONNECT:      return "WSOCK_RESULT_ERR_CONNECT";
    case WSOCK_RESULT_ERR_HOSTNAME:     return "WSOCK_RESULT_ERR_HOSTNAME";
    case WSOCK_RESULT_ERR_CLOSED:       return "WSOCK_RESULT_ERR_CLOSED";
    case WSOCK_RESULT_ERR_TIMEOUT:      return "WSOCK_RESULT_ERR_TIMEOUT";
    case WSOCK_RESULT_ERR_SVR_RESP:     return "WSOCK_RESULT_ERR_SVR_RESP";
    case WSOCK_RESULT_ERR_MEM:          return "WSOCK_RESULT_ERR_MEM";
    case WSOCK_RESULT_LOCAL_ABORT:      return "WSOCK_RESULT_LOCAL_ABORT";
    case WSOCK_RESULT_ERR_CONTENT_LEN:  return "WSOCK_RESULT_ERR_CONTENT_LEN";
    default:
        break;
    }
    return "Invalid";
}

static void wsock_hexdump(unsigned char *buf, size_t len)
{
    for(int n = 0; n < len;)
    {
        unsigned int start = n, m;
        char line[80], *p = line;

        p += snprintf(p, 10, "%04X: ", start);

        for (m = 0; m < 16 && n < len; m++)
            p += snprintf(p, 5, "%02X ", buf[n++]);

        while (m++ < 16)
            p += snprintf(p, 5, "   ");

        p += snprintf(p, 6, "   ");

        for (m = 0; m < 16 && (start + m) < len; m++)
        {
            if (buf[start + m] >= ' ' && buf[start + m] < 127)
                *p++ = (char)buf[start + m];
            else
                *p++ = '.';
        }

        while (m++ < 16) *p++ = ' ';

        *p++ = '\n';
        *p = '\0';
        printf("%s", line);
    }
    printf("\n");
}

const char *err2str(err_t errval)
{
    switch(errval)
    {
    case ERR_OK         : return "ERR_OK";
    case ERR_MEM        : return "ERR_MEM";
    case ERR_BUF        : return "ERR_BUF";
    case ERR_TIMEOUT    : return "ERR_TIMEOUT";
    case ERR_RTE        : return "ERR_RTE";
    case ERR_INPROGRESS : return "ERR_INPROGRESS";
    case ERR_VAL        : return "ERR_VAL";
    case ERR_WOULDBLOCK : return "ERR_WOULDBLOCK";
    case ERR_USE        : return "ERR_USE";
    case ERR_ALREADY    : return "ERR_ALREADY";
    case ERR_ISCONN     : return "ERR_ISCONN";
    case ERR_CONN       : return "ERR_CONN";
    case ERR_IF         : return "ERR_IF";
    case ERR_ABRT       : return "ERR_ABRT";
    case ERR_RST        : return "ERR_RST";
    case ERR_CLSD       : return "ERR_CLSD";
    case ERR_ARG        : return "ERR_ARG";
    }
    return "UNK";
}

