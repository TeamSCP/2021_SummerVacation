#include <pcap.h>
//#include <stdbool.h>
#include <stdio.h>

#include<stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>



#define true 1
#define false 0
#define NULL 0

struct ether_header *ep;
struct ip *iph;
struct tcphdr *tcph;


void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param  = {
    .dev_ = NULL
};

int parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }

    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;


    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
    int num = 0;
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        ep = (struct ether_header *)packet;
        printf("%u bytes captured, len : %u, res : %d, %dth packet \n", header->caplen, header->len, res,num);
        printf("type : %u\n",ep->ether_type);
        printf("dst : %02x:%02x:%02x:%02x:%02x:%02x\n",ep->ether_dhost[0],ep->ether_dhost[1],ep->ether_dhost[2],ep->ether_dhost[3],ep->ether_dhost[4],ep->ether_dhost[5]);
        printf("src : %02x:%02x:%02x:%02x:%02x:%02x\n",ep->ether_shost[0],ep->ether_shost[1],ep->ether_shost[2],ep->ether_shost[3],ep->ether_shost[4],ep->ether_shost[5]);
        num++;
    }

    pcap_close(pcap);
} 