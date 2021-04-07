#pragma once
#include<Winsock2.h>
#pragma comment(lib, "ws2_32.lib")
struct pcap_hdr_s {
    unsigned int magic_number;     // magic number 
    unsigned short version_major;  // major version number 
    unsigned short version_minor;  // minor version number 
    int  thiszone;                 // GMT to local correction 
    unsigned int sigfigs;          // accuracy of timestamps 
    unsigned int snaplen;          // max length of captured packets, in octets 
    unsigned int network;          // data link type 
};

struct pcap_pkthdr {        // структура заголовка всего пакета 
    struct timeval ts;	    // time stamp    
    unsigned int caplen;	// length of portion present 
    unsigned int len;	    // length of this packet (off wire) 
};

