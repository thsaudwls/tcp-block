#pragma once

#include <cstdint>
#include <arpa/inet.h>

#pragma pack(push, 1)
struct TcpHdr final {
	uint16_t sport; // Source port
	uint16_t dport; // Destination port
	uint32_t seqnum;  // Sequence Number
	uint32_t acknum;  // Acknowledgement number
	uint8_t reserved:4; // Reserved 	
	uint8_t th_off:4; // Header length
	uint8_t flags;  // packet flags
	uint16_t win;   // Window Size
	uint16_t check;   // Header Checksum
	uint16_t urgptr; // Urgent pointer

#define TH_FIN 0x01  /* finished send data */
#define TH_SYN 0x02  /* synchronize sequence numbers */
#define TH_RST 0x04  /* reset the connection */
#define TH_PUSH 0x08 /* push data to the app layer */
#define TH_ACK 0x10  /* acknowledge */
#define TH_URG 0x20  /* urgent! */


};
typedef TcpHdr *PTcpHdr;
#pragma pack(pop)