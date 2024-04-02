#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

struct tcpheader {
  u_short tcp_sport;               /* source port */
  u_short tcp_dport;               /* destination port */
  u_int   tcp_seq;                 /* sequence number */
  u_int   tcp_ack;                 /* acknowledgement number */
  u_char  tcp_offx2;               /* data offset, rsvd */
  u_char  tcp_flags;
  u_short tcp_win;                 /* window */
  u_short tcp_sum;                 /* checksum */
  u_short tcp_urp;                 /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;
  struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
  struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);

  printf("      S MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));   
  printf("      D MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost)); 

  printf("       S IP: %s\n", inet_ntoa(ip->iph_sourceip));   
  printf("       D IP: %s\n", inet_ntoa(ip->iph_destip));    
    
  printf("     S Port: %d\n", ntohs(tcp->tcp_sport));   
  printf("     D Port: %d\n", ntohs(tcp->tcp_dport));   

  printf("\n");
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

  // Step 3: Capture packets
  pcap_loop(handle, 0, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}