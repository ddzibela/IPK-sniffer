/**
 * This document is Copyright 2002 Tim Carstens. All rights reserved. Redistribution and use, with or without modification, are permitted provided that the following conditions are met:
 *
 *    1.    Redistribution must retain the above copyright notice and this list of conditions.
 *    2.    The name of Tim Carstens may not be used to endorse or promote products derived from this document without specific prior written permission.
 *
 *   Insert 'wh00t' for the BSD license here
 *
 * @author Tim Carstens
 *         timcarst at yahoo dot com
 * @author Guy Harris
 *         guy at alum dot mit dot edu
 * @author modified by Denis Dzibela
 *         xdzibe00
 */
#include <stdint.h>

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

	/* Ethernet DLT_EN10MB header */
	struct sniff_ethernet {
		uint8_t ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		uint8_t ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		uint16_t ether_type; /* IP? ARP? RARP? etc */
	};

	/* IPv4 header */
	struct sniff_ip {
		uint8_t ip_vhl;		/* version << 4 | header length >> 2 */
		uint8_t ip_tos;		/* type of service */
		uint16_t ip_len;		/* total length */
		uint16_t ip_id;		/* identification */
		uint16_t ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* don't fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		uint8_t ip_ttl;		/* time to live */
		uint8_t ip_p;		/* protocol */
		uint16_t ip_sum;		/* checksum */
		unsigned long ip_src,ip_dst; /* source and dest address */
	};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* ARP header */
	struct sniff_arp {
		uint16_t arp_htype;	/* Hardware type */
		uint16_t arp_ptype;	/* Protocol type */
		uint8_t arp_hlen;	/* HW address length */
		uint8_t arp_plen;	/* Protocol address length */
		uint16_t arp_oper;	/* Operation */
		uint8_t arp_sha[ETHER_ADDR_LEN]; /* Sender HW address */
		uint8_t arp_spa[2]; /* Sender protocol address */
		uint8_t arp_tha[ETHER_ADDR_LEN]; /* Target HW address */
		uint8_t arp_tpa[2]; /* Target protocol address */
	};

	/* IPv6 header */

	/* TCP header */
	typedef unsigned int tcp_seq;

	struct sniff_tcp {
		uint16_t th_sport;	/* source port */
		uint16_t th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		uint8_t th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		uint8_t th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		uint16_t th_win;		/* window */
		uint16_t th_sum;		/* checksum */
		uint16_t th_urp;		/* urgent pointer */
	};

	/* UDP header */
	struct sniff_udp {
		uint16_t ud_sport;	/* source port */
		uint16_t ud_dport;	/* destination port */
		uint16_t ud_len;	/* length */
		uint16_t ud_sum;	/* checksum */
	};

	/* ICMP header */
	struct sniff_icmp {
		uint8_t ic_type;	/* ICMP Type */
		uint8_t ic_code;	/* ICMP subtype */
		uint16_t ic_sum;	/* checksum */
		uint32_t ic_rest;	/* rest of header */
	};