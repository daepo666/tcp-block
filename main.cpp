#include <pcap.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "tcp_block.h"

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("syntax: %s <interface> <pattern>\n", argv[0]);
        return -1;
    }

    block_info info;
    info.handle = NULL;
    info.raw_sock = -1; //before initialize
    memset(info.my_mac, 0, sizeof(info.my_mac));
    info.pattern = argv[2];

    if (get_my_mac(argv[1], info.my_mac) < 0) {
        perror("get_my_mac error!");
        return -1;
    }

    info.raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (info.raw_sock < 0) {
        perror("raw socket error!");
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    info.handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
    if (info.handle == NULL) {
        printf("error messagge: %s\n", errbuf);
        close(info.raw_sock);
        return -1;
    }

    pcap_loop(info.handle, 0, packet_handler, (u_char *)&info);

    pcap_close(info.handle);
    close(info.raw_sock);

    return 0;
}
