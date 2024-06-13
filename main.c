#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <inttypes.h>

#define ETHER_HEADER_SIZE 14

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
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

struct PacketLog {
    const char *src_addr;
    uint16_t src_port;

    const char *dest_addr;
    uint16_t dest_port;

    const char *protocol;
};

void log_packet(struct PacketLog packet_log)
{
    printf("\t---------------------------------------------------\n");
    printf("\t|  ");
    printf("Source address");
    printf("  | ");
    printf("Destination address");
    printf(" | ");
    printf("Protocol");
    printf(" |\n");

    printf("\t|  %s", packet_log.src_addr);
    printf(" |   %s", packet_log.dest_addr);
    printf("   |  ");
    printf(" %s", packet_log.protocol);
    printf("    |\n");

    printf("\t---------------------------------------------------\n\n");
}

void dispatch_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet_bytes)
{
    struct ip *ip_header = (struct ip *)(packet_bytes + ETHER_HEADER_SIZE);

    struct PacketLog plog = {
        .src_addr = inet_ntoa(ip_header->ip_src),
        .dest_addr = inet_ntoa(ip_header->ip_dst)
    };

    switch (ip_header->ip_p) {
        case IPPROTO_UDP: {
            plog.protocol = "UDP";

            struct udphdr *udph = (struct udphdr *)(packet_bytes + ETHER_HEADER_SIZE + ip_header->ip_hl * 4);
            plog.src_port = ntohs(udph->uh_sport);
            plog.dest_port = ntohs(udph->uh_dport);
        } break;

        case IPPROTO_TCP: {
            plog.protocol = "TCP";

            struct tcphdr *tcph = (struct tcphdr *)(packet_bytes + ETHER_HEADER_SIZE + ip_header->ip_hl * 4);
            plog.src_port = ntohs(tcph->th_sport);
            plog.dest_port = ntohs(tcph->th_dport);
        } break;

        case IPPROTO_SCTP: {
            plog.protocol = "SCTP";
        } break;

        case IPPROTO_UDPLITE: {
            plog.protocol = "UDPLITE";
        } break;

        default: {
            fprintf(stderr, "Unsupported IP protocol: %d\n", ip_header->ip_p);
            return;
        }
    }

    log_packet(plog);
}

void log_command_usage()
{
    printf("\tsudo ./cap [Network device]\n");
}

int main(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "Missing network device argument\n");
        log_command_usage();

        return 1;
    }

    const char *dev = argv[1];
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

    struct bpf_program bpf = {0};
    bpf_u_int32 net;
    if (pcap_compile(cap_handle, &bpf, "ip", 0, net) == PCAP_ERROR) {
        fprintf(stderr, "pcap_compile error: %s\n", pcap_geterr(cap_handle));
        return 1;
    }

    if (pcap_setfilter(cap_handle, &bpf) != 0) {
        fprintf(stderr, "pcap_setfilter error: %s\n", pcap_geterr(cap_handle));
        return 1;
    }

    int packets_processed = pcap_loop(cap_handle, 0, dispatch_callback, NULL);

    pcap_freecode(&bpf);
    pcap_close(cap_handle);

    return 0;
}
