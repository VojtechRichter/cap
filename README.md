# cap - link layer network traffic sniffer
Cap uses the pcap library to intercept all link layer traffic, which is mostly ethernet frames. These frames are disassemled into headers and packets for each ip protocol (supported ones and TCP, UDP, SCTP, UDPLITE).

## Usage

```bash
sudo ./cap [-d network_interface] [-c receive_packet_count] [-v | --version]
```
