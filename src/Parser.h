#pragma once
#include <iostream>
#include "Headers.h"
#include "Handshake.h"

class Parser
{
public:
 Parser() {}
 void CountSessions(FILE* ptrFile, Handshake* Sessions, int& Array_Size);

 private:
  Link ethernet;            //the struct of the Ethernet protocol header
  pcap_pkthdr ptk_header;   // the struct of the packet header
  Internet_ip ip;           //the struct of the IP protocol header
  Transport_tcp TCP;        //the struct of the TCP protocol header
 int index = 0;
 int Handshakes_Sucsess = 0;
 int Unfinished_Sessions = 0;
 int Unstarnadt_Sessions = 0;

 void Parse(FILE* ptrFile, Handshake* Sessions, int& Array_Size);
 int Unfinished(Handshake* Sessions, int& index);
 int Unstandart_Finished(Handshake* Sessions, int& index);
};

