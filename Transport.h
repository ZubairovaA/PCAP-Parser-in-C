#pragma once
#include<Winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <stdio.h>
# include <vector>

using namespace std;

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


struct Handshake {
    unsigned short src_port;	// номер порта отправителя                 source port
    unsigned short dst_port;	// номер порта получателя                  destination portint 
    unsigned long sequence_number=0; 
    int Contact = 0;    
    int Finish = 0;
    unsigned long Ack_number = 0;
};

void Handle_TCP(Transport_tcp& TCP, Handshake* Sessions, int& Handshakes_Sucsess, int & index, int& Array_Size);   //Checking if there are any handshakes in the file
