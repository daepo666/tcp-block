#include "tcp_block.h"

#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>

static const char block_data[] =
    "HTTP/1.0 302 Redirect\r\n"
    "Location: http://warning.or.kr\r\n"
    "\r\n";

int get_my_mac(const char *dev, uint8_t mac[6]) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0) 
        return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);

    return 0;
}

uint16_t cal_checksum(uint8_t *buf, int len) {
    uint32_t sum = 0;

    for (int i = 0; i+1< len; i+=2) { // len이 짝수일때
        uint16_t word = (buf[i] << 8) + buf[i + 1];
        sum += word;
    }
    if (len & 1) {
        uint16_t word = buf[len - 1] << 8;
        sum += word;
    }

    while (sum >0xffff) {
        sum = (sum &0xffff) + (sum >>16);
    }
    uint16_t checksum = htons((uint16_t)(0xffff- sum));
    return checksum;
}

uint16_t tcp_checksum(ipv4_header *ip, tcp_header *tcp, uint8_t *data, int data_len) {
    uint8_t temp[0x1000];
    int pos = 0;
    uint16_t tcp_len = htons(sizeof(tcp_header) + data_len);

    memcpy(temp + pos, ip->src_ip, 4);
    pos += 4;
    memcpy(temp + pos, ip->dst_ip, 4);
    pos += 4;

    temp[pos] =0;
    pos++;
    temp[pos] = IP_TCP;
    pos++;

    memcpy(temp + pos, &tcp_len, 2);
    pos += 2;
    memcpy(temp + pos, tcp, sizeof(tcp_header));
    pos += sizeof(tcp_header);

    if (data_len > 0) {
        memcpy(temp + pos, data, data_len);
        pos += data_len;
    }
    uint16_t checksum = cal_checksum(temp, pos);
    return checksum;
}

int filter_compare(uint8_t *data, int data_len, const std::string &pattern) {
    if (data_len <= 0 || pattern.empty()){
        return 0;
    }
    std::string payload((char *)data, data_len);

    if (payload.find(pattern) == std::string::npos)
        return 0;
    return 1;
}

void send_block(block_info *info, ethernet_header *origin_eth, ipv4_header *origin_ip, tcp_header *origin_tcp, int data_len) {
    //save original seq , acck
    uint32_t origin_seq = ntohl(origin_tcp->sequence_num);
    uint32_t origin_ack = ntohl(origin_tcp->ack_num);
    uint32_t next_seq = origin_seq + data_len;

    //make rst packet space 
    uint8_t rst_packet[sizeof(ethernet_header) + sizeof(ipv4_header) + sizeof(tcp_header)];
    memset(rst_packet, 0, sizeof(rst_packet));

    //make pointers.
    ethernet_header *rst_eth = (ethernet_header *)rst_packet;
    ipv4_header *rst_ip = (ipv4_header *)(rst_packet + sizeof(ethernet_header));
    tcp_header *rst_tcp = (tcp_header *)(rst_packet + sizeof(ethernet_header) + sizeof(ipv4_header));

    //fill mac info
    memcpy(rst_eth->dst_MAC, origin_eth->dst_MAC, 6);
    memcpy(rst_eth->src_MAC, info->my_mac, 6);
    rst_eth->ethernet_type = htons(ETH_IP);

    //fill ip infos ipv4
    rst_ip->version_ihl = 0x45;
    rst_ip->total_len = htons(sizeof(ipv4_header) + sizeof(tcp_header));
    rst_ip->ttl = origin_ip->ttl;
    rst_ip->protocol = IP_TCP;

    memcpy(rst_ip->src_ip, origin_ip->src_ip, 4);
    memcpy(rst_ip->dst_ip, origin_ip->dst_ip, 4);

    rst_ip->header_checksum = cal_checksum((uint8_t *)rst_ip, sizeof(ipv4_header));

    rst_tcp->src_port = origin_tcp->src_port;
    rst_tcp->dst_port = origin_tcp->dst_port;
    rst_tcp->sequence_num = htonl(next_seq);
    rst_tcp->ack_num = htonl(origin_ack);

    uint16_t rst_flag = 0x5 * 0x1000;
    rst_flag += TCP_RST;
    rst_flag += TCP_ACK;
    rst_tcp->dataoffset_reversed_flags = htons(rst_flag);
    rst_tcp->checksum =tcp_checksum(rst_ip, rst_tcp, NULL, 0);

    //rst can be sended by pcap. but fin is not
    pcap_sendpacket(info->handle, rst_packet, sizeof(rst_packet));


    //now fin
    uint8_t fin_packet[1500];
    memset(fin_packet, 0, sizeof(fin_packet));

    int block_len = strlen(block_data);
    int fin_len = sizeof(ipv4_header) + sizeof(tcp_header) + block_len;
    ipv4_header *fin_ip = (ipv4_header *)fin_packet;
    tcp_header *fin_tcp = (tcp_header *)(fin_packet + sizeof(ipv4_header));
    uint8_t *fin_data = fin_packet + sizeof(ipv4_header) + sizeof(tcp_header);

    memcpy(fin_data, block_data, block_len);
    //ip infos
    fin_ip->version_ihl = 0x45;
    fin_ip->total_len = htons(fin_len);
    fin_ip->ttl = 0x80;
    fin_ip->protocol = IP_TCP;

    memcpy(fin_ip->src_ip, origin_ip->dst_ip, 4);
    memcpy(fin_ip->dst_ip, origin_ip->src_ip, 4);

    fin_ip->header_checksum = cal_checksum((uint8_t *)fin_ip, sizeof(ipv4_header));
    //fill tcp infos
    fin_tcp->src_port = origin_tcp->dst_port;
    fin_tcp->dst_port= origin_tcp->src_port;
    fin_tcp->sequence_num= htonl(origin_ack);
    fin_tcp->ack_num = htonl(next_seq);

    uint16_t fin_flag = 0x5 * 0x1000;
    fin_flag +=TCP_FIN;
    fin_flag +=TCP_ACK;
    fin_tcp->dataoffset_reversed_flags =htons(fin_flag);
    fin_tcp->checksum =tcp_checksum(fin_ip, fin_tcp, fin_data, block_len);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family =AF_INET;
    memcpy(&addr.sin_addr.s_addr, origin_ip->src_ip, 4);
    // no pcap!!
    sendto(info->raw_sock, fin_packet, fin_len, 0, (struct sockaddr *)&addr, sizeof(addr));
}

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    block_info *info = (block_info *)user;
    ethernet_header *eth = (ethernet_header *)packet;

    if (header->caplen < sizeof(ethernet_header) + sizeof(ipv4_header) + sizeof(tcp_header)){
        return; // error check
    }
    if (ntohs(eth->ethernet_type) != ETH_IP){
        return;
    }
    ipv4_header *ip = (ipv4_header*)(packet +sizeof(ethernet_header));
    if (ip->protocol != IP_TCP){
        return;
    }
    
    int ip_len = (ip->version_ihl &0xf)<< 2;
    int ip_total_len = ntohs(ip->total_len);
    tcp_header *tcp = (tcp_header *)(packet + sizeof(ethernet_header) + ip_len);
    int tcp_field = ntohs(tcp->dataoffset_reversed_flags);
    int tcp_len = (tcp_field >>12) <<2;
    int data_len = ip_total_len - ip_len - tcp_len;

    if (data_len <= 0)
        return;

    uint8_t *data = (uint8_t *)tcp +tcp_len;

    if (filter_compare(data, data_len, info->pattern) == 0){
        return;
    }
    send_block(info, eth, ip,tcp, data_len);
    return;
}