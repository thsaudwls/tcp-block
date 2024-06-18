#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"
#include "mac.h"
#include "ip.h"

#define REDIRECT_MSG "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n"
#define BUF_SIZE 2048

void usage() {
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

#pragma pack(push, 1)
typedef struct EthIpTcpHdr {
    EthHdr ethHdr_;
    IpHdr ipHdr_;
    TcpHdr tcpHdr_;
} EthIpTcpHdr;
#pragma pack(pop)

typedef struct PseudoHdr {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_len;
} PseudoHdr;