#ifndef _WEBSOCKET_CLIENT_H
#define _WEBSOCKET_CLIENT_H

#if LWIP_TCP && LWIP_CALLBACK_API
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Websocket header format for reference.
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

#define WSHDRBITS_FIN               0x80
#define WSHDRBITS_OPCODE            0x0f
#define WSHDRBITS_MASKED            0x80
#define WSHDRBITS_PAYLOAD_LEN       0x7f
#define WSHDRBITS_PAYLOAD_LEN_EXT16 0x7e
#define WSHDRBITS_PAYLOAD_LEN_EXT64 0x7f

#define OPCODE_CONTINUATION 0x0
#define OPCODE_TEXT         0x1
#define OPCODE_BINARY       0x2
#define OPCODE_CLOSE        0x8
#define OPCODE_PING         0x9
#define OPCODE_PONG         0xA

#define WSLEN_SMALL         125     // 125 bytes => 7 bits (not 8), less 1
#define WSLEN_BIG           32768   // 32K bytes => 16 bits
#define WSMSG_MAXSIZE       1420    // ~ single packet size after headers
                                    // ip:20/tcp:32/ws:14 --> total:68

#define WSHDRLEN_MIN        2
#define WSHDRLEN_EXT16BITS  2
#define WSHDRLEN_EXT64BITS  8
#define WSHDRLEN_MASKKEY    4
#define WSHDRLEN_MAX        (WSHDRLEN_MIN + WSHDRLEN_EXT64BITS + WSHDRLEN_MASKKEY)

// ping/pong support
#define WSPING_WAITS        4
#define WSPONG_MSGSIZE      WSHDRLEN_MIN
#define WSPONG_MAX_PAYLOAD  32

typedef enum ewsock_result
{
    WSOCK_RESULT_OK              =  0,  /** web socket successfully opened */
    WSOCK_RESULT_ERR_UNKNOWN     =  1,  /** Unknown error */
    WSOCK_RESULT_ERR_CONNECT     =  2,  /** Connection to server failed */
    WSOCK_RESULT_ERR_HOSTNAME    =  3,  /** Failed to resolve server hostname */
    WSOCK_RESULT_ERR_CLOSED      =  4,  /** Connection unexpectedly closed by remote server */
    WSOCK_RESULT_ERR_TIMEOUT     =  5,  /** Connection timed out  */
    WSOCK_RESULT_ERR_SVR_RESP    =  6,  /** Server responded with an error code */
    WSOCK_RESULT_ERR_MEM         =  7,  /** Local memory error */
    WSOCK_RESULT_LOCAL_ABORT     =  8,  /** Local abort */
    WSOCK_RESULT_ERR_CONTENT_LEN =  9,  /** Content length mismatch */
    WSOCK_RESULT_FIN_CLOSED      = 10   /** normal websocket close from server */
} wsock_result_t;

#define WS_TCP_CLOSED       0
#define WS_TCP_CONNECTING   1
#define WS_TCP_CONNECTED    2

typedef enum ewsock_parse_state
{
    WSOCK_PARSE_WAIT_FIRST_LINE = 0,
    WSOCK_PARSE_WAIT_HEADERS,
    WSOCK_PARSE_RX_DATA
} wsock_parse_state_t;

#define WSOCK_KEY_SIZE      40
#define WSOCK_KEY_HASH_SIZE 40
#define WSOCK_KEY_BUF_SIZE  128

#define PWS_STATE_INITD     0xabcd0007
#define PWS_STATE_DONE      0xdcba0003

typedef err_t (*wsapp_fn) (char *buf, size_t len);

typedef struct _wsock_state
{
    unsigned int        state0;
    struct altcp_pcb    *pcb;
    ip_addr_t           remote_addr;
    u16_t               remote_port;
    int                 timeout_ticks;
    struct pbuf         *request;
    u16_t               rx_http_version;
    u16_t               rx_status;
    u32_t               rx_data_bytes;
    u32_t               hdr_content_len;
    wsock_parse_state_t parse_state;
    char                server_rsp[WSOCK_KEY_SIZE];
    char                client_key[WSOCK_KEY_SIZE];

    // web socket control parameters
    int                 tcp_polls;
    int                 ssl_enabled;
    int                 ping_enabled;
    int                 pong_pending;
    int                 ping_wait;
    int                 ping_sent;
    int                 ping_rcvd;
    int                 pong_sent;
    int                 pong_rcvd;
    int                 send_pong;
    char                pong_payload[WSPONG_MAX_PAYLOAD];
    int                 ponglen;
    int                 wsclose_rcvd;
    int                 tcp_state;
    wsapp_fn            message_handler;
    unsigned int        state1;
} wsock_state_t;

extern int wsverbose;

extern err_t wsock_init(wsock_state_t *pws, int ssl_enabled, int ping_enabled, wsapp_fn hndlr);
extern err_t wsock_connect(wsock_state_t *pws, const char *srvname, const char *wspath, u16_t port,
                           const char *bearer_token, const char *subproto,
                           const char *extrahdr, const char *extrahdrval);
extern err_t wsock_write(wsock_state_t *pws, const char *buf, u16_t buflen, uint8_t opcode);
extern err_t wsock_close(wsock_state_t *pws, wsock_result_t result, err_t err);
extern const char *wsstate2str(wsock_state_t *pws);
extern const char *opcode2str(uint8_t opcode);
extern const char *wsock2str(wsock_result_t resval);
extern const char *err2str(err_t errval);

#ifdef __cplusplus
}
#endif
#endif /* LWIP_TCP && LWIP_CALLBACK_API */
#endif /* _WEBSOCKET_CLIENT_H */
