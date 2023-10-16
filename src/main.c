#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "pcap/pcap.h"
#include "pthread/pthread.h"

typedef uint32_t ipv4_addr_t;

typedef struct {
  uint8_t addr[6];
} mac_addr_t;

/// Ethernet header, 14 octets.
typedef struct {
  /// Destination MAC address
  mac_addr_t dst_mac;
  /// Source MAC address
  mac_addr_t src_mac;
  /// Ether type or length
  uint16_t ether_type;
} ethernet_header_t;

/// Ethernet type for IPv4
#define ETHER_TYPE_IPV4 0x0800
/// Ethernet type for IPv6
#define ETHER_TYPE_IPV6 0x86DD
/// Ethernet type for ARP
#define ETHER_TYPE_ARP 0x0806

/// IPv4 header, 20 octets.
///
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Ver  |  IHL  |   DSCP    |ECN|          Total Length         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Identification        |Flags|      Fragment Offset    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Time to Live |    Protocol   |        Header Checksum        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Source Address                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Destination Address                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// Most significant byte first.
typedef struct {
  /// Internet header length
  uint8_t ihl : 4;
  /// Version
  uint8_t version : 4;
  /// Type of service, ECN
  uint8_t ecn : 2;
  /// Type of service, DSCP
  uint8_t dscp : 6;
  /// Total length
  uint16_t total_length;
  /// Identification
  uint16_t identification;
  /// Flags and fragmentation offset
  uint16_t fragmentation;
  /// Time to live
  uint8_t ttl;
  /// Protocol
  uint8_t protocol;
  /// Header checksum
  uint16_t checksum;
  /// Source address
  ipv4_addr_t src_addr;
  /// Destination address
  ipv4_addr_t dst_addr;
} ipv4_header_t;

/// Thread-shared variable for user input, indicating keep running or not
bool keep_running = true;

/// Listen for user input in a separate thread.
void* listen_quit(void* args) {
  while (keep_running) {
    char c = getchar();
    if (c == 'q') {
      keep_running = false;
    }
  }
  return NULL;
}

void callback(
  uint8_t* args,
  const struct pcap_pkthdr* header,
  const uint8_t* packet
) {
  // if user input 'q', stop capturing
  if (!keep_running) {
    printf("stopping...\n");
    pcap_breakloop((pcap_t*)args);
  }

  for (size_t i = 0; i < 50; i++) {
    printf("=");
  }
  printf("\n");

  printf(
    "timestamp: \033[32m%s.%06d\033[39m\n",
    // ignore newline
    strtok(ctime((const time_t*)&header->ts.tv_sec), "\n"), header->ts.tv_usec
  );

  printf("pktlen:    \033[32m%d\033[39m\n", header->len);
  printf("comment:   \033[32m%s\033[39m\n", header->comment);

  for (size_t i = 0; i < 50; i++) {
    printf("-");
  }
  printf("\n");

  ethernet_header_t* ethernet_header = (ethernet_header_t*)packet;

  printf("Ethernet header\n");
  printf(
    "  dst mac:     \033[94m%02x:%02x:%02x:%02x:%02x:%02x\033[39m\n",
    ethernet_header->dst_mac.addr[0], ethernet_header->dst_mac.addr[1],
    ethernet_header->dst_mac.addr[2], ethernet_header->dst_mac.addr[3],
    ethernet_header->dst_mac.addr[4], ethernet_header->dst_mac.addr[5]
  );

  printf(
    "  src mac:     \033[94m%02x:%02x:%02x:%02x:%02x:%02x\033[39m\n",
    ethernet_header->src_mac.addr[0], ethernet_header->src_mac.addr[1],
    ethernet_header->src_mac.addr[2], ethernet_header->src_mac.addr[3],
    ethernet_header->src_mac.addr[4], ethernet_header->src_mac.addr[5]
  );

  uint16_t ether_type = ntohs(ethernet_header->ether_type);

  printf("  type/length: \033[94m0x%04x\033[39m\n", ether_type);

  for (size_t i = 0; i < 50; i++) {
    printf("-");
  }
  printf("\n");

  // Interpret the payload
  const uint8_t* payload = packet + sizeof(ethernet_header_t);

  switch (ether_type) {
    case ETHER_TYPE_IPV4: {
      ipv4_header_t* ipv4_header = (ipv4_header_t*)payload;

      uint8_t version = ipv4_header->version;
      uint8_t ihl = ipv4_header->ihl;
      uint8_t dscp = ipv4_header->dscp;
      uint8_t ecn = ipv4_header->ecn;

      uint16_t total_length = ntohs(ipv4_header->total_length);
      uint16_t identification = ntohs(ipv4_header->identification);

      uint16_t fragmentation = ntohs(ipv4_header->fragmentation);

      uint8_t ttl = ipv4_header->ttl;
      uint8_t protocol = ipv4_header->protocol;

      uint16_t checksum = ntohs(ipv4_header->checksum);

      ipv4_addr_t src_addr = ntohl(ipv4_header->src_addr);
      ipv4_addr_t dst_addr = ntohl(ipv4_header->dst_addr);

      printf("IPv4 header\n");
      printf("  ver:            \033[94m%d\033[39m\n", version);
      printf("  ihl:            \033[94m%d\033[39m\n", ihl);
      printf("  dscp:           \033[94m%d\033[39m\n", dscp);
      printf("  ecn:            \033[94m%d\033[39m\n", ecn);
      printf("  total length:   \033[94m%d\033[39m\n", total_length);
      printf("  identification: \033[94m0x%04x\033[39m\n", identification);
      printf("  fragmentation:  \033[94m0x%04x\033[39m\n", fragmentation);
      printf("  ttl:            \033[94m%d\033[39m\n", ttl);
      printf("  protocol:       \033[94m%d\033[39m\n", protocol);
      printf("  checksum:       \033[94m0x%04x\033[39m\n", checksum);
      printf(
        "  src addr:       \033[94m%d.%d.%d.%d\033[39m\n",
        (src_addr >> 24) & 0xFF, (src_addr >> 16) & 0xFF,
        (src_addr >> 8) & 0xFF, (src_addr >> 0) & 0xFF
      );
      printf(
        "  dst addr:       \033[94m%d.%d.%d.%d\033[39m\n",
        (dst_addr >> 24) & 0xFF, (dst_addr >> 16) & 0xFF,
        (dst_addr >> 8) & 0xFF, (dst_addr >> 0) & 0xFF
      );

      break;
    }
    case ETHER_TYPE_IPV6: {
      printf("IPv6 packet\n");
      break;
    }
    case ETHER_TYPE_ARP: {
      printf("ARP packet\n");
      break;
    }
    default: {
      printf("other ether type: %04x\n", ether_type);
      break;
    }
  }
}

int main(int argc, char* argv[]) {
  // check size of structs
  printf("sizeof(ethernet_header_t) = %lu\n", sizeof(ethernet_header_t));
  printf("sizeof(ipv4_header_t) = %lu\n", sizeof(ipv4_header_t));
  // just for sure
  assert(sizeof(ethernet_header_t) == 14);
  assert(sizeof(ipv4_header_t) == 20);

  // device list
  pcap_if_t* alldevs;
  // error buffer
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf);

  // get the device list
  // `pcap_findalldevs_ex` is not supported on macOS, so use `pcap_findalldevs`
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "error in pcap_findalldevs_ex: %s\n", errbuf);
    return 1;
  }

  // total number of devices
  size_t device_count = 0;
  // print device list
  for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
    printf("%3lu %20s %s\n", device_count, d->name, d->description);
    device_count++;
  }

  printf("total: %lu devices\n", device_count);

  // choose one device to capture
  size_t device_number;
  printf("enter device number: ");
  scanf("%lu", &device_number);

  if (device_number >= device_count) {
    fprintf(stderr, "invalid device number\n");
    return 1;
  }

  // get device
  pcap_if_t* device = alldevs;
  for (size_t i = 0; i < device_number; i++) {
    device = device->next;
  }

  printf("selected device: %s\n", device->name);

  pcap_t* handle = pcap_create(device->name, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "error in pcap_create: %s\n", errbuf);
    return 1;
  }
  // promiscuous mode, all packets are received regardless of the address
  pcap_set_promisc(handle, 1);
  // 65535 bytes, maximum size of a packet to capture
  // reference: `man pcap`
  // > `A snapshot length of 65535 should be sufficient, on most if not all
  // > networks, to capture all the data available from the packet.`
  pcap_set_snaplen(handle, 65535);
  // timeout, 1000ms
  pcap_set_timeout(handle, 1000);

  if (pcap_activate(handle) != 0) {
    fprintf(stderr, "error in pcap_activate: %s\n", pcap_geterr(handle));
    return 1;
  }

  // device list is no longer needed
  pcap_freealldevs(alldevs);

  int packet_count = 0;
  printf("enter packet count: ");
  scanf("%d", &packet_count);

  if (packet_count <= 0) {
    // start listening for user inputs
    pthread_t thread;
    pthread_create(&thread, NULL, listen_quit, NULL);
  }

  // start capturing
  pcap_loop(handle, packet_count, callback, (uint8_t*)handle);
  // close the session
  pcap_close(handle);

  return 0;
}
