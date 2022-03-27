#include "Parser.h"

void Parser::CountSessions(FILE* ptrFile, Handshake* Sessions, int& Array_Size)
{
 Parse(ptrFile, Sessions, Array_Size);
 if (index > 0)
 {
  Unfinished_Sessions = Unfinished(Sessions, index);
  Unstarnadt_Sessions = Unstandart_Finished(Sessions, index);

  printf("The.pcap file includes: \n");
  printf("Handshakes: %d.\n", Handshakes_Sucsess);
  printf("Unfinished sessions: %d.\n", Unfinished_Sessions);
  printf("Unstarnadt sessions: %d.\n", Unstarnadt_Sessions);
 }
 else
 {
  printf("There are no handshakes in the .pcap file.\n");
 }
}

void Parser::Parse(FILE* ptrFile, Handshake* Sessions, int& Array_Size)
{
 int pkt_offset = 24;           // the pcap file header
 int x = 1;
 while (fseek(ptrFile, pkt_offset, SEEK_SET) == 0)
 {
  if (fread(&ptk_header, 16, 1, ptrFile) == 0)    //read pcap packet header 16 bytes
  {
   return;
  }

  if (fread(&ethernet, 14, 1, ptrFile) == 0) //read ethernet header
  {
   return;
  }

  bool Continue = Handle_Ethernet(ethernet, ptrFile);
  if (Continue == true)
  {
   continue;
  }

  if (fread(&ip, 14, 1, ptrFile) == 0)          //read internet header
  {
   return;
  }
  int ipSize = 4 * (ip.ip_vhl & 0x0F);               //counting the IP header length 

  fseek(ptrFile, ipSize - 14, SEEK_CUR);        //moving to the source port in TCP header

  if (ip.ip_p == IPPROTO_TCP)
  {
   if (fread(&TCP, 20, 1, ptrFile) == 0)    //read pcap packet head
   {
    return;
   }
   int TCP_Length = 4 * (TCP.th_offx2 >> 4);
   fseek(ptrFile, TCP_Length - 20, SEEK_CUR);        //move pointer to the payload

   Handle_TCP(TCP, Sessions, Handshakes_Sucsess, index, Array_Size);
  }
  x++;
  pkt_offset += 16 + ptk_header.caplen;
 }
}

int Parser::Unfinished(Handshake* Sessions, int& index)
{
 int count = 0;
 for (int i = 0; i < index; i++)
 {
  if (Sessions[i].Contact != 3)
  {
   count++;
  }
 }
 return count;
}

int Parser::Unstandart_Finished(Handshake* Sessions, int& index)
{
 int count = 0;
 for (int i = 0; i < index; i++)
 {
  if (Sessions[i].Finish != 2)
   count++;
 }
 return count;
}
