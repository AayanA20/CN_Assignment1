#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <unordered_map>
#include <iostream>
#include <fstream>
#include <limits.h>
#define MAX_PACKETS 980000
using namespace std;
unordered_map<string, int> src_flows;
unordered_map<string, int> dst_flows;
unordered_map<string, int> data_transferred;
unordered_map<string, bool> unique_pairs;
int total_packets = 0;
int total_data = 0;
int min_size = INT_MAX;
int max_size = 0;
double avg_size = 0;
double start_time = 0;
double end_time = 0;
ofstream size_file("packet_sizes.txt");

void process_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14);
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));
    int packet_size = header->len;
    total_packets++;
    total_data += packet_size; 
    if (packet_size < min_size) min_size = packet_size;
    if (packet_size > max_size) max_size = packet_size;
    avg_size = (double)total_data / total_packets;
    if (size_file.is_open()) {
        size_file << packet_size << endl;
    }
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
    int src_port = ntohs(tcp_header->th_sport);
    int dst_port = ntohs(tcp_header->th_dport);
    string src = string(src_ip) + ":" + to_string(src_port);
    string dst = string(dst_ip) + ":" + to_string(dst_port);
    string pair = src + " -> " + dst;
    unique_pairs[pair] = true;
    src_flows[src_ip]++;
    dst_flows[dst_ip]++;
    data_transferred[pair] += packet_size;
    if (total_packets == 1) start_time = header->ts.tv_sec + header->ts.tv_usec / 1e6;
    end_time = header->ts.tv_sec + header->ts.tv_usec / 1e6;
}

void display_results() {
    printf("\n Packet Statistics:\n");
    printf("  - Total Packets: %d\n", total_packets);
    printf("  - Total Data Transferred: %d bytes\n", total_data);
    printf("  - Min Packet Size: %d bytes\n", min_size);
    printf("  - Max Packet Size: %d bytes\n", max_size);
    printf("  - Avg Packet Size: %.2f bytes\n", avg_size);
    printf("\n Unique Source-Destination Pairs: %lu\n", unique_pairs.size());
    for (const auto &pair : unique_pairs) {
        printf("  %s", pair.first.c_str());
    }
    printf("\n Source IP Flows:\n");
    for (const auto &entry : src_flows) {
        printf("  %s: %d flows, ", entry.first.c_str(), entry.second);
    }

    printf("\n Destination IP Flows:\n");
    for (const auto &entry : dst_flows) {
        printf("  %s: %d flows, ", entry.first.c_str(), entry.second);
    }
    string max_pair;
    int max_transfer = 0;
    for (const auto &entry : data_transferred) {
        if (entry.second > max_transfer) {
            max_transfer = entry.second;
            max_pair = entry.first;
        }
    }
    printf("\nMaximum Data Transferred:\n");
    printf("  - Pair: %s\n", max_pair.c_str());
    printf("  - Data: %d bytes\n", max_transfer);
    double duration = end_time - start_time;
    double pps = total_packets / duration;
    double mbps = (total_data * 8) / (duration * 1e6);
    printf("\n Speed Analysis:\n");
    printf("  - Packets Per Second (PPS): %.2f\n", pps);
    printf("  - Capture Rate: %.2f Mbps\n", mbps);

    printf("\nPacket capture complete! Run 'python3 plot_histogram.py' to generate the histogram.\n");
}

void capture_packets(const char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr header;
    const u_char *packet;

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Error opening interface %s: %s\n", interface, errbuf);
        exit(EXIT_FAILURE);
    }

    printf(" Capturing packets on interface: %s\n", interface);

    while (total_packets < MAX_PACKETS) {
        packet = pcap_next(handle, &header);
        if (packet == NULL) continue;
        process_packet(&header, packet);
    }

    pcap_close(handle);
    size_file.close();
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <network_interface>\n", argv[0]);
        return 1;
    }

    const char *network_interface = argv[1];

    capture_packets(network_interface);
    display_results();

    return 0;
}
