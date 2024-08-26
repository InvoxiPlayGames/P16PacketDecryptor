// P16PacketDecryptor.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <list>

#include "P16AuthenticatedEncryption.h"
#include "cat/AllTunnel.hpp"
#include "catTunnelStruct.h"

#include "light_pcapng_ext.h"
#include "NetworkingStructs.h"
#include "RakNetInitStructs.h"
#include "ini.h"

bool GenerateSkeinKey(uint8_t* B, uint8_t* a, uint8_t* answer, cat::Skein* out_key)
{
    // initialise a client handshake object with the server's public key
    cat::ClientEasyHandshake chs;
    RawClientEasyHandshake1* chsraw = reinterpret_cast<RawClientEasyHandshake1*>(&chs); // accesses protected fields
    RawClientEasyHandshake2* chsraw2 = reinterpret_cast<RawClientEasyHandshake2*>(&chs); // accesses C++ classes
    if (!chs.Initialize(B))
    {
        return false;
    }

    // copy the private key into the handshake
    memcpy(chsraw->tun_client.a, a, 0x20);
    // generate the public key and neutral key
    cat::BigTwistedEdwards* math = chsraw2->tls_math;
    math->PtMultiply(chsraw->tun_client.G_MultPrecomp, 6, chsraw->tun_client.a, 0, chsraw->tun_client.A);
    math->PtNormalize(chsraw->tun_client.A, chsraw->tun_client.A);
    math->SaveAffineXY(chsraw->tun_client.A, ((uint8_t*)chsraw->tun_client.A_neutral), ((uint8_t*)chsraw->tun_client.A_neutral) + 32);

    // parse the server response to generate the key hash
    if (!chsraw2->tun_client.ProcessAnswer((cat::BigTwistedEdwards*)chsraw->tls_math, answer, 0x80, out_key))
    {
        return false;
    }
    return true;
}

void hexdump(const uint8_t* bytes, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02x", bytes[i]);
    printf("\n");
}

char* ip_to_str(uint32_t ip, char* buffer) {
    uint8_t *ip_bytes = (uint8_t*)&ip;
    sprintf(buffer, "%d.%d.%d.%d", ip_bytes[3], ip_bytes[2], ip_bytes[1], ip_bytes[0]);
    return buffer;
}

std::list<uint8_t *> key_list;

// https://stackoverflow.com/a/35452093
uint8_t* datahex(const char* string) {
    if (string == NULL)
        return NULL;
    size_t slength = strlen(string);
    if ((slength % 2) != 0) // must be even
        return NULL;
    size_t dlength = slength / 2;
    uint8_t* data = (uint8_t *)malloc(dlength);
    if (data == NULL)
        return NULL;
    memset(data, 0, dlength);
    size_t index = 0;
    while (index < slength) {
        char c = string[index];
        int value = 0;
        if (c >= '0' && c <= '9')
            value = (c - '0');
        else if (c >= 'A' && c <= 'F')
            value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
            value = (10 + (c - 'a'));
        else {
            free(data);
            return NULL;
        }
        data[(index / 2)] += value << (((index + 1) % 2) * 4);
        index++;
    }
    return data;
}

static int inihandler(void* user, const char* section, const char* name, const char* value) {
#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
    if (MATCH("KeyExchange", "ClientPrivateKey"))
    {
        if (strlen(value) == 64) {
            uint8_t* key_buf = datahex(value);
            if (key_buf != NULL) {
                key_list.push_back(key_buf);
            }
            else {
                return 0;
            }
        }
        else {
            return 0;
        }
    }
    return 1;
}

void write_modified_packet(light_pcapng_t* writer, light_packet_header *pkt_header,
    Ethernet_Header* eth, IPv4_Header* ip, UDP_Header* udp, uint8_t* new_data, size_t new_data_len) {

    light_packet_header new_pkt_header;
    IPv4_Header new_ip = { 0 };
    UDP_Header new_udp = { 0 };
    size_t total_new_size = new_data_len + sizeof(IPv4_Header) + sizeof(UDP_Header);

    // ethernet header doesn't need modifying and also doesn't always exist
    if (eth) {
        total_new_size += sizeof(Ethernet_Header);
    }

    // copy in the details from the original packet, we'll modify it later
    memcpy(&new_pkt_header, pkt_header, sizeof(new_pkt_header));
    memcpy(&new_ip, ip, sizeof(new_ip));
    memcpy(&new_udp, udp, sizeof(new_udp));

    // allocate the full packet buffer
    uint8_t* new_pkt_buf = (uint8_t *)malloc(total_new_size);
    if (new_pkt_buf == NULL) {
        printf("can't allocate! not saving!\n");
        return;
    }
    // copy everything into the new buffer
    size_t write_offset = 0;
    if (eth) {
        memcpy(new_pkt_buf + write_offset, eth, sizeof(Ethernet_Header));
        write_offset += sizeof(Ethernet_Header);
    }

    // fix up all the length values
    new_ip.ip_len = htons(total_new_size - write_offset);
    memcpy(new_pkt_buf + write_offset, &new_ip, sizeof(IPv4_Header));
    write_offset += sizeof(IPv4_Header);

    new_udp.udp_len = htons(total_new_size - write_offset);
    memcpy(new_pkt_buf + write_offset, &new_udp, sizeof(UDP_Header));
    write_offset += sizeof(UDP_Header);

    memcpy(new_pkt_buf + write_offset, new_data, new_data_len);
    write_offset += new_data_len;

    new_pkt_header.original_length = write_offset;
    new_pkt_header.captured_length = write_offset;
    light_write_packet(writer, &new_pkt_header, new_pkt_buf);

    free(new_pkt_buf);
}

typedef enum _SessionDecryptState {
    SESSION_NONE,
    SESSION_GOT_SERVER_KEY,
    SESSION_GOT_SERVER_CLIENT_KEY,
    SESSION_HANDSHAKE_SUCCESSFUL
};

uint8_t raknet_offline_data_id[0x10] = {
    0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78
};

int main(int argc, char **argv)
{
    if (argc < 4) {
        printf("usage: %s [input.pcapng] [keys.ini] [output.pcapng]", argv[0]);
        return 0;
    }

    if (ini_parse(argv[2], inihandler, NULL) < 0) {
        printf("Can't load keys from '%s'.\n", argv[2]);
        return 1;
    }

    light_pcapng_t* pcapng = light_pcapng_open_read(argv[1], LIGHT_FALSE);
    if (pcapng == NULL) {
        printf("Can't open '%s' for reading.\n", argv[1]);
        return 1;
    }

    light_pcapng_t* pcapng_writer = light_pcapng_open_write(argv[3], light_create_default_file_info());
    if (pcapng_writer == NULL) {
        printf("Can't open '%s' for writing.\n", argv[3]);
        return 1;
    }

#define CONTINUE_WRITE { light_write_packet(pcapng_writer, &pkt_header, orig_pkt_data); continue; }
#define WRITE_ORIGINAL light_write_packet(pcapng_writer, &pkt_header, orig_pkt_data)

    if (pcapng != NULL) {
        int index = 1;
        long firstpkt = 0;
        
        // raknet session state
        int state = SESSION_NONE;
        uint32_t client_ip = 0;
        uint16_t client_port = 0;
        uint32_t server_ip = 0;
        uint16_t server_port = 0;
        uint8_t public_key[0x40] = { 0 };
        uint8_t client_challenge[0x40] = { 0 };
        uint8_t server_answer[0x80] = { 0 };
        cat::Skein auth_key;
        P16AuthenticatedEncryption enc;

        while (1) {
            char ip_str_buf1[30];
            char ip_str_buf2[30];
            light_packet_header pkt_header;
            const uint8_t* pkt_data = NULL;
            int res = 0;

            res = light_get_next_packet(pcapng, &pkt_header, &pkt_data);
            if (!res)
                break;
            //if (index > 7)
            //    break;

            if (pkt_data != NULL) {
                if (firstpkt == 0)
                    firstpkt = pkt_header.timestamp.tv_sec;
                index++;
                const uint8_t* orig_pkt_data = pkt_data;

                // the ethernet header may not be present, depending on the capture
                Ethernet_Header* eth = NULL;
                if (pkt_header.data_link == 1) {
                    eth = (Ethernet_Header*)pkt_data;
                    // not an IPv4 packet, ignore
                    if (htons(eth->eth_type) != 0x0800)
                        CONTINUE_WRITE
                    pkt_data += sizeof(Ethernet_Header);
                }

                // make sure it's an IPv4 UDP packet
                IPv4_Header* ip = (IPv4_Header *)pkt_data;
                if (ip->ip_v != 4 || ip->ip_p != 17)
                    CONTINUE_WRITE
                pkt_data += (ip->ip_hl * 4);

                // pick out the source/dest IP/port from the UDP header
                UDP_Header* udp = (UDP_Header*)pkt_data;
                //printf("UDP- %s:%i -> %s:%i (%i bytes)\n", ip_to_str(ntohl(ip->ip_src), ip_str_buf1), ntohs(udp->udp_src),
                //    ip_to_str(ntohl(ip->ip_dst), ip_str_buf2), ntohs(udp->udp_dst), ntohs(udp->udp_len));

                // copy out the packet data into something we can modify
                pkt_data += sizeof(UDP_Header);
                uint16_t udp_payload_len = ntohs(udp->udp_len) - sizeof(UDP_Header);
                uint8_t* buf = (uint8_t *)malloc(udp_payload_len);
                if (buf == NULL) {
                    printf("out of memory!\n");
                    break;
                }
                memset(buf, 0, udp_payload_len);
                memcpy(buf, pkt_data, udp_payload_len);
                uint32_t buf_bytes = udp_payload_len;

                // check if it's an offline RakNet packet
                if (memcmp(pkt_data + 1, raknet_offline_data_id, sizeof(raknet_offline_data_id)) == 0)
                {
                    char print_prefix[200];
                    snprintf(print_prefix, sizeof(print_prefix), "[%i.%i - %s:%i -> %s:%i]",
                        pkt_header.timestamp.tv_sec - firstpkt, pkt_header.timestamp.tv_usec,
                        ip_to_str(ntohl(ip->ip_src), ip_str_buf1), ntohs(udp->udp_src),
                        ip_to_str(ntohl(ip->ip_dst), ip_str_buf2), ntohs(udp->udp_dst)
                        );
                    if (pkt_data[0] == RN_ID_OPEN_CONNECTION_REQUEST1)
                    {
                        packetRequest1* req = (packetRequest1*)pkt_data;
                        //printf("%s Client opening new RakNet connection\n", print_prefix);
                        client_ip = ntohl(ip->ip_src);
                        client_port = ntohs(udp->udp_src);
                        server_ip = ntohl(ip->ip_dst);
                        server_port = ntohl(udp->udp_dst);
                        state = SESSION_NONE;
                        WRITE_ORIGINAL;
                    }
                    else if (pkt_data[0] == RN_ID_OPEN_CONNECTION_REPLY1)
                    {
                        packetReply1_Enc* req = (packetReply1_Enc*)pkt_data;
                        if (req->use_encryption != 0)
                        {
                            //printf("%s Server requesting encrypted RakNet connection\n", print_prefix);
                            memcpy(public_key, req->public_key, sizeof(req->public_key));
                            state = SESSION_GOT_SERVER_KEY;

                            // write a response that implies the packet won't be encrypted into the pcap
                            packetReply1_Dec dec_req;
                            dec_req.offline_msg_id = req->offline_msg_id;
                            memcpy(dec_req.offline_msg_data_id, req->offline_msg_data_id, sizeof(dec_req.offline_msg_data_id));
                            memcpy(dec_req.server_guid, req->server_guid, sizeof(dec_req.server_guid));
                            dec_req.use_encryption = 0;
                            dec_req.mtu = req->mtu;
                            write_modified_packet(pcapng_writer, &pkt_header, eth, ip, udp, (uint8_t*)&dec_req, sizeof(dec_req));
                        }
                        else {
                            //printf("%s Server requesting unencrypted RakNet connection\n", print_prefix);
                            state = SESSION_NONE;
                            WRITE_ORIGINAL;
                        }
                    }
                    else if (pkt_data[0] == RN_ID_OPEN_CONNECTION_REQUEST2)
                    {
                        packetRequest2_Enc* req = (packetRequest2_Enc*)pkt_data;
                        if (req->has_challenge != 0)
                        {
                            printf("%s Client sending challenge to server\n", print_prefix);
                            memcpy(client_challenge, req->challenge, sizeof(req->challenge));
                            state = SESSION_GOT_SERVER_CLIENT_KEY;

                            // write a response that implies the packet won't be encrypted into the pcap
                            packetRequest2_Dec dec_req;
                            dec_req.offline_msg_id = req->offline_msg_id;
                            memcpy(dec_req.offline_msg_data_id, req->offline_msg_data_id, sizeof(dec_req.offline_msg_data_id));
                            memcpy(dec_req.client_guid, req->client_guid, sizeof(dec_req.client_guid));
                            dec_req.has_challenge = 0;
                            dec_req.server_ipv4 = req->server_ipv4;
                            dec_req.server_port = req->server_port;
                            dec_req.ip_version = req->ip_version;
                            dec_req.mtu = req->mtu;
                            write_modified_packet(pcapng_writer, &pkt_header, eth, ip, udp, (uint8_t*)&dec_req, sizeof(dec_req));
                        }
                        else {
                            printf("%s Client sending unauthenticated request\n", print_prefix);
                            state = SESSION_NONE;
                            WRITE_ORIGINAL;
                        }
                    }
                    else if (pkt_data[0] == RN_ID_OPEN_CONNECTION_REPLY2)
                    {
                        packetReply2_Enc* req = (packetReply2_Enc*)pkt_data;
                        if (req->use_encryption != 0)
                        {
                            memcpy(server_answer, req->answer, sizeof(req->answer));
                            std::list<uint8_t *>::iterator it;
                            bool found_key = false;
                            for (it = key_list.begin(); it != key_list.end(); ++it) {
                                if (GenerateSkeinKey(public_key, *it, server_answer, &auth_key))
                                {
                                    found_key = true;
                                    break;
                                }
                            }
                            if (found_key == false) {
                                printf("%s Couldn't decrypt server answer, not decrypting...\n", print_prefix);
                                state = SESSION_NONE;
                                WRITE_ORIGINAL;
                            }
                            if (!enc.Initialize(&auth_key, true))
                            {
                                printf("%s Couldn't key P16AuthenticatedEncryption, not decrypting...\n", print_prefix);
                                state = SESSION_NONE;
                                WRITE_ORIGINAL;
                            }
                            else {
                                printf("%s RakNet/P16 decryption key established!\n", print_prefix);
                                state = SESSION_HANDSHAKE_SUCCESSFUL;

                                // write a response that implies the packet won't be encrypted into the pcap
                                packetReply2_Dec dec_req;
                                dec_req.offline_msg_id = req->offline_msg_id;
                                memcpy(dec_req.offline_msg_data_id, req->offline_msg_data_id, sizeof(dec_req.offline_msg_data_id));
                                memcpy(dec_req.server_guid, req->server_guid, sizeof(dec_req.server_guid));
                                dec_req.use_encryption = 0;
                                dec_req.client_ipv4 = req->client_ipv4;
                                dec_req.client_port = req->client_port;
                                dec_req.ip_version = req->ip_version;
                                dec_req.mtu = req->mtu;
                                write_modified_packet(pcapng_writer, &pkt_header, eth, ip, udp, (uint8_t*)&dec_req, sizeof(dec_req));
                            }
                        }
                        else {
                            printf("RakNet client sending unauthenticated request\n");
                            WRITE_ORIGINAL;
                        }
                    }
                }
                else if (state = SESSION_HANDSHAKE_SUCCESSFUL && (
                    ((ntohl(ip->ip_dst) == server_ip && ntohl(ip->ip_src) == client_ip) ||
                     (ntohl(ip->ip_dst) == client_ip && ntohl(ip->ip_src) == server_ip)))
                ) {
                    //printf("    ");
                    bool is_c2s = ntohl(ip->ip_dst) == server_ip;
                    if (is_c2s)
                    {
                        if (enc.DecryptAsRemote(buf, buf_bytes))
                        {
                            write_modified_packet(pcapng_writer, &pkt_header, eth, ip, udp, buf, buf_bytes);
                        }
                        else
                        {
                            WRITE_ORIGINAL;
                        }
                    }
                    else {
                        if (enc.Decrypt(buf, buf_bytes))
                        {
                            write_modified_packet(pcapng_writer, &pkt_header, eth, ip, udp, buf, buf_bytes);
                        }
                        else
                        {
                            WRITE_ORIGINAL;
                        }
                    }
                }
                else {
                    WRITE_ORIGINAL;
                }
                free(buf);
            }
        }
    }

    light_pcapng_close(pcapng);
    light_pcapng_close(pcapng_writer);


    return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
