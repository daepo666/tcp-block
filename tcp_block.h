#pragma once

#include <pcap.h>
#include <stdint.h>
#include <string>

#include "my_struct.h"

#define ETH_IP 0x0800
#define IP_TCP 6

#define TCP_FIN 0x01
#define TCP_RST 0x04
#define TCP_ACK 0x10

typedef struct block_info {
    pcap_t *handle;
    int raw_sock;
    uint8_t my_mac[6];
    std::string pattern;
} block_info;

int get_my_mac(const char *dev, uint8_t mac[6]);
uint16_t cal_checksum(uint8_t *buf, int len);
uint16_t tcp_checksum(ipv4_header *ip, tcp_header *tcp, uint8_t *data, int data_len);
int filter_compare(uint8_t *data, int data_len, const std::string &pattern);
void send_block(block_info *info, ethernet_header *org_eth, ipv4_header *org_ip, tcp_header *org_tcp, int data_len);
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
