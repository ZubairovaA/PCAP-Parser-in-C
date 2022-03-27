#pragma once
#include"Headers.h"

struct Handshake {
    unsigned short src_port;	// номер порта отправителя                 source port
    unsigned short dst_port;	// номер порта получателя                  destination portint 
    unsigned int sequence_number = 0;
    int Contact = 0;
    int Finish = 0;
    unsigned int Ack_number = 0;
};

void Handle_TCP(Transport_tcp& TCP, Handshake* Sessions, int& Handshakes_Sucsess, int& index, int& Array_Size);   //Checking if there are any handshakes in the file
