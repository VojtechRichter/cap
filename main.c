#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define ETHER_HEADER_SIZE 14

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    printf("packet captured!\n");

    struct ip *iph = (struct ip *)(packet + 14);
    printf("Captured a packet with IP: %s\n", inet_ntoa(iph->ip_src));
    if (iph->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + iph->ip_hl * 4);
        printf("Source port: %d\n", ntohs(tcph->th_sport));
        printf("Destination port: %d\n", ntohs(tcph->th_dport));
    } else if (iph->ip_p == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(packet + 14 + iph->ip_hl * 4);
        printf("Source port: %d\n", ntohs(udph->uh_sport));
        printf("Destination port: %d\n", ntohs(udph->uh_dport));
    }
}

void dispatch_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet_bytes)
{
    struct ip *ip_header = (struct ip *)(packet_bytes + ETHER_HEADER_SIZE);

    printf("source address: %s\n", inet_ntoa(ip_header->ip_src));
}

int main()
{
    const char *dev = "enp4s0";
    char errbuf[PCAP_ERRBUF_SIZE * 2];

    if (pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf) != 0) {
        fprintf(stderr, "pcap_init error: %s\n", errbuf);

        return 1;
    }

    pcap_t *cap_handle = pcap_create(dev, errbuf);
    if (cap_handle == NULL) {
        fprintf(stderr, "packet_create error: %s\n", errbuf);

        return 1;
    }

    if (pcap_set_immediate_mode(cap_handle, 1) != 0) {
        fprintf(stderr, "pcap_set_immediate_mode error, perhaps the handle is already activated?\n");

        return 1;
    }

    if (pcap_activate(cap_handle) != 0) {
        fprintf(stderr, "pcap_activate error: %s\n", pcap_geterr(cap_handle));
        pcap_close(cap_handle);

        return 1;
    }

    // filtering
    /*
    struct bpf_program bpf = {0};
    if (pcap_compile(cap_handle, &bpf, "tcp and udp", 0, 0) == PCAP_ERROR) {
        fprintf(stderr, "pcap_compile error: %s\n", pcap_geterr(cap_handle));
    }

    if (pcap_setfilter(cap_handle, &bpf) != 0) {
        fprintf(stderr, "pcap_setfilter error: %s\n", pcap_geterr(cap_handle));
    }
    */

    int packets_processed = pcap_dispatch(cap_handle, 1, dispatch_callback, NULL);

    pcap_close(cap_handle);

    return 0;
}
