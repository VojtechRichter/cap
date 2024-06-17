#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <inttypes.h>

#define CAP_VERSION "0.0.1"

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

void log_cap_version()
{
    printf("cap version %s\n", (const char *)CAP_VERSION);
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
    printf("usage: sudo ./cap [-i network_interface] [-c receive_packet_count] [-v | --version]\n");
    printf("See 'cap help' for a list of available commands\n");
    log_cap_version();
}

int filter_packets(pcap_t *handle, const char *filter_exp)
{
    struct bpf_program bpf = {0};
    if (pcap_compile(handle, &bpf, filter_exp, 0, 0) == PCAP_ERROR) {
        fprintf(stderr, "pcap_compile error: %s\n", pcap_geterr(handle));

        return 1;
    }

    if (pcap_setfilter(handle, &bpf) != 0) {
        fprintf(stderr, "pcap_setfilter error: %s\n", pcap_geterr(handle));

        return 1;
    }

    pcap_freecode(&bpf);

    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        log_command_usage();

        return 1;
    }

    // 0 == fetch forever
    uint32_t packet_limit = 0;

    char *net_interface;

    if (argc > 3) {
        for (uint8_t i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "-i")) {
                if (argv[i + 1] != NULL) {
                    printf("setting net interface!!\n");
                    net_interface = strcpy(net_interface, argv[i + 1]);
                } else {
                    fprintf(stderr, "No network interface provided for option '-i'\n");
                }
            } else if (!strcmp(argv[i], "-v")) {
                log_cap_version();
            } else if (!strcmp(argv[i], "-c")) {
                if (argv[i + 1] != NULL) {
                    packet_limit = (uint32_t)atoi(argv[i + 1]);
                } else {
                    fprintf(stderr, "No number specified for option '-c'\n");
                }
            }
        }
    }

    printf("supplied arguments: ");
    for (uint8_t i = 0; i < argc; i++) {
        printf("%s ", argv[i]);
    }
    printf("\n");
    printf("Using following cap config:\n");
    printf("network interface: %s\n", net_interface);
    printf("packet limit: %d\n\n", packet_limit);

    char errbuf[PCAP_ERRBUF_SIZE * 2];

    if (pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf) != 0) {
        fprintf(stderr, "pcap_init error: %s\n", errbuf);

        return 1;
    }

    pcap_t *cap_handle = pcap_create(net_interface, errbuf);
    if (cap_handle == NULL) {
        fprintf(stderr, "packet_create error: %s\n", errbuf);

        return 1;
    }

    if (pcap_set_immediate_mode(cap_handle, 1) != 0) {
        fprintf(stderr, "pcap_set_immediate_mode error, perhaps the handle is already activated?\n");

        return 1;
    }

    if (pcap_activate(cap_handle) != 0) {
        fprintf(stderr, "cap error: %s\n", pcap_geterr(cap_handle));
        pcap_close(cap_handle);

        return 1;
    }

    if (filter_packets(cap_handle, "ip") != 0) {
        return 1;
    }

    int result = pcap_loop(cap_handle, packet_limit, dispatch_callback, NULL);
    if (result == PCAP_ERROR) {
        fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(cap_handle));

        return 1;
    }

    pcap_close(cap_handle);

    return 0;
}
