#pragma once
#include <stdint.h>
__pragma(pack(push, 1))
typedef struct _Ethernet_Header
{
    uint8_t eth_dst[0x6];
    uint8_t eth_src[0x6];
    uint16_t eth_type;
} Ethernet_Header;
typedef struct _IPv4_Header
{
    uint8_t ip_hl : 4;
    uint8_t ip_v : 4;
    uint8_t ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_p;
    uint16_t ip_sum;
    uint32_t ip_src;
    uint32_t ip_dst;
} IPv4_Header;
typedef struct _UDP_Header
{
    uint16_t udp_src;
    uint16_t udp_dst;
    uint16_t udp_len;
    uint16_t udp_sum;
} UDP_Header;
__pragma(pack(pop))
