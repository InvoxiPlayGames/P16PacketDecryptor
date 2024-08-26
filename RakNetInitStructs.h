#pragma once
#include <stdint.h>

__pragma(pack(push, 1))

#define RN_ID_OPEN_CONNECTION_REQUEST1 0x05

typedef struct _packetRequest1 {
    uint8_t offline_msg_id;
    uint8_t offline_msg_data_id[0x10];
    uint8_t protocol_version;
} packetRequest1;

#define RN_ID_OPEN_CONNECTION_REPLY1 0x06

typedef struct _packetReply1_Enc {
    uint8_t offline_msg_id;
    uint8_t offline_msg_data_id[0x10];
    uint8_t server_guid[0x8];
    uint8_t use_encryption;
    uint32_t cookie;
    uint8_t public_key[0x40];
    uint16_t mtu;
} packetReply1_Enc;

typedef struct _packetReply1_Dec {
    uint8_t offline_msg_id;
    uint8_t offline_msg_data_id[0x10];
    uint8_t server_guid[0x8];
    uint8_t use_encryption;
    uint16_t mtu;
} packetReply1_Dec;

#define RN_ID_OPEN_CONNECTION_REQUEST2 0x07

typedef struct _packetRequest2_Enc {
    uint8_t offline_msg_id;
    uint8_t offline_msg_data_id[0x10];
    uint32_t cookie;
    uint8_t has_challenge;
    uint8_t challenge[0x40];
    uint8_t ip_version;
    uint32_t server_ipv4;
    uint16_t server_port;
    uint16_t mtu;
    uint8_t client_guid[0x8];
} packetRequest2_Enc;

typedef struct _packetRequest2_Dec {
    uint8_t offline_msg_id;
    uint8_t offline_msg_data_id[0x10];
    uint8_t has_challenge;
    uint8_t ip_version;
    uint32_t server_ipv4;
    uint16_t server_port;
    uint16_t mtu;
    uint8_t client_guid[0x8];
} packetRequest2_Dec;

#define RN_ID_OPEN_CONNECTION_REPLY2 0x08

typedef struct _packetReply2_Enc {
    uint8_t offline_msg_id;
    uint8_t offline_msg_data_id[0x10];
    uint8_t server_guid[0x8];
    uint8_t ip_version;
    uint32_t client_ipv4;
    uint16_t client_port;
    uint16_t mtu;
    uint8_t use_encryption;
    uint8_t answer[0x80];
} packetReply2_Enc;

typedef struct _packetReply2_Dec {
    uint8_t offline_msg_id;
    uint8_t offline_msg_data_id[0x10];
    uint8_t server_guid[0x8];
    uint8_t ip_version;
    uint32_t client_ipv4;
    uint16_t client_port;
    uint16_t mtu;
    uint8_t use_encryption;
} packetReply2_Dec;

__pragma(pack(pop))
