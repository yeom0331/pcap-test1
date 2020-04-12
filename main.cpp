#include "pcap_test.h"
#include <algorithm>
using namespace std;

void usage() {
  printf("syntax: pcap-test <interface>\n");
  printf("sample: pcap-test wlan0\n");
}

void print_MAC(const u_int8_t *mac) {
    for(int i=0; i<6; i++) {
        printf("%02x", mac[i]);
        if(i<5) {
        printf(":");
        }
    }
    printf("\n");
}

void print_IP(const u_int8_t *ipaddr) {
    for(int i=0; i<4; i++) {
        printf("%d", ipaddr[i]);
        if(i<3) {
        printf(".");
        }
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        struct libnet_ethernet_hdr *eth;
        struct libnet_ipv4_hdr *iph;
        struct libnet_tcp_hdr *tcph;

        eth = (struct libnet_ethernet_hdr *)packet;
        u_int16_t ether_type = ntohs(eth->ether_type);

        if(ether_type == ETHERTYPE_IP) {
            iph = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
            if(iph->ip_p == IPPROTO_TCP) {
                printf("Src MAC = ");
                print_MAC(eth->ether_shost);
                printf("dst MAC = ");
                print_MAC(eth->ether_dhost);

                printf("Src IP = ");
                print_IP(iph->ip_src);
                printf("Dst IP = ");
                print_IP(iph->ip_dst);

                int ip_hl = (iph->ip_hl)*4;
                

                tcph = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + ip_hl);

                printf("Src PORT = %d\n", ntohs(tcph->th_sport));
                printf("Dst PORT = %d\n", ntohs(tcph->th_dport));
                
                int th_off = (tcph->th_x2)*4;
                int payload_len = ntohs(iph->ip_len) - ip_hl - th_off;
                int print_len = min(payload_len, 16);
                for(int i=0; i<print_len; i++) {
                    printf("%02x ", packet[sizeof(struct libnet_ethernet_hdr) + ip_hl + th_off + i]);

                }
                printf("\n\n");
            }
        }
    }
    pcap_close(handle);
}
