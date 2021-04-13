#pragma once
#include<Winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <stdio.h>
using namespace std;

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


struct Link                        //структура заголовка Ethernet    Ethernet header struct
{
    unsigned char ether_dhost[6];  //MAC адрес получателя           MAC dest address
    unsigned char ether_shost[6];  //MAC адрес отправителя          MAC source address
    unsigned short ether_type;     //тип протокола сетевого уровня  next level protocol    
};

struct Internet_ip {                //структура заголовка Internet    Internet  header struct
    unsigned char ip_vhl;		   // Версия ip протокола и длина заголовка(*4)  ip protocol version
    unsigned char ip_tos;		   // тип обслуживания   type of service
    unsigned short ip_len;		   // общий размер всего пакета   the size of the packet
    unsigned short ip_id;		   // идентификационный номер пакета при разбивке файла на части   identification
    unsigned short ip_off;		   // fragment offset field   
#define IP_RF 0x8000		       // флаг- зарезервированный фрагмент    reserved fragment flag 
#define IP_DF 0x4000		       // флаг- можно ли фрагментировать      don't fragment flag
#define IP_MF 0x2000		       // флаг- будут и еще фрагменты         more fragments flag
#define IP_OFFMASK 0x1fff	       // маска для фрагментирования битов    mask for fragmenting bits
    unsigned char ip_ttl;		   // time to live
    unsigned char ip_p;		       // протокол след уровня                next level protocol
    unsigned short ip_sum;		   // чексумма                            checksum
    unsigned char ip_src[4];       //  адрес отправления                  source address
    unsigned char ip_dst[4];       //  адрес назначения                   dest address
};

struct Transport_tcp {           //структура заголовка TCP    TCP  header struct

    unsigned short src_port;	// номер порта отправителя                 source port
    unsigned short dst_port;	// номер порта получателя                  destination port
    unsigned long th_seq;		// номер пакета в последовательности       sequence number
    unsigned long th_ack;		// номер подтверждения                     acknowledgement number
    unsigned char th_offx2;	    // длина заголовка (4 бита) TCP_Length = (tcp->th_offx2) >>4     data offset
    unsigned char th_flags;     //флаги    flags
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    unsigned short th_win;		//окно                      window
    unsigned short sum;		    //чексумма                  checksum
    unsigned short th_urp;		//экстренный указатель      urgent pointer  
};

bool Handle_Ethernet(Link& ethernet, FILE* ptrFile);   //working with ethernet protocol header
