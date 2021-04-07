#include "Transport.h"
#include<Winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <stdio.h>
#include <vector>

using namespace std;

static void Search_Sessions (Transport_tcp &TCP, vector <Handshake>& Sessions, int& Handshakes_Sucsess)
{
	if(ntohl(TH_SYN) == 1 && ntohl(TCP.th_seq) == 0 && ntohl(TH_ACK) == 0)       //the first step of the handshake
    {
        Sessions.push_back(Handshake{ TCP.src_port, TCP.dst_port, 1 });
    }

    else if (ntohl(TH_SYN) == 1 && ntohl(TCP.th_ack) == 1 && ntohl(TH_ACK) == 1)   // the second step of the handshake
    {
     for (int i = 0; i < sizeof(Sessions); i++)
      {
        if ((Sessions[i].dst_port == TCP.src_port) && (Sessions[i].src_port == TCP.dst_port))
           {
             Sessions[i].Contact = 2;
             break;
            }
      }
    }

    else if (ntohl(TCP.th_seq) == 1 && ntohl(TCP.th_ack) == 1 && ntohl(TH_ACK) == 1)  //the third step of the handshake
     {
       for (int i = 0; i < sizeof(Sessions); i++)
          {
            if ((Sessions[i].dst_port == TCP.dst_port) && (Sessions[i].src_port == TCP.src_port))
              {
                Sessions[i].Contact = 3;
                break;
               }
          }
            Handshakes_Sucsess++;
     }


     else if (ntohl(TH_FIN) == 1 && ntohl(TH_ACK) == 0)   // finish the session 
    {
         for (int i = 0; i < sizeof(Sessions); i++)
         {
            if ((Sessions[i].dst_port == TCP.dst_port) && (Sessions[i].src_port == TCP.src_port))
             {
               Sessions[i].Finish = 1;
               break;
             }
            else if ((Sessions[i].dst_port == TCP.src_port) && (Sessions[i].src_port == TCP.dst_port))
             {
              Sessions[i].Finish = 2;
              break;
             }
         }
     }

}


void Handle_TCP(Transport_tcp& TCP, vector <Handshake>& Sessions, int& Handshakes_Sucsess)
{
    Search_Sessions(TCP, Sessions, Handshakes_Sucsess);
}