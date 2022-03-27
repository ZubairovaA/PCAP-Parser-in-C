#include "Handshake.h"
#include"Headers.h"

static void Search_Sessions(Transport_tcp& TCP, Handshake* Sessions, int& Handshakes_Sucsess, int& index, int& Array_Size)
{
 union BIT_FIELD {
  struct BITS {
   unsigned FIN : 1;
   unsigned SYN : 1;
   unsigned RST : 1;
   unsigned PUSH : 1;
   unsigned ACK : 1;
   unsigned URG : 1;
   unsigned ECE : 1;
   unsigned CWR : 1;
  } bits;
  unsigned char value;
 } flags;

 flags.value = TCP.th_flags;

    if (flags.bits.SYN == 1 && flags.bits.ACK == 0)       //the first step of the handshake
    {
        Sessions[index] = { TCP.src_port, TCP.dst_port, TCP.th_seq, 1 };
        index++;
        if (index >= Array_Size) {
            Array_Size *= 2;
            Sessions = (Handshake*)realloc(Sessions, Array_Size * sizeof(Handshake));
            if (Sessions == NULL)
            {
                printf("Error: can't reallocate memory");
                exit(2);
            }
        }
    }
    else if (flags.bits.SYN == 1 && flags.bits.ACK == 1)   // the second step of the handshake
    {
        for (int i = 0; i < index; i++)
        {
            if ((Sessions[i].dst_port == TCP.src_port) && (Sessions[i].src_port == TCP.dst_port) && (ntohl(TCP.th_ack) == (Sessions[i].sequence_number + 1)))
            {
                Sessions[i].sequence_number += 1;
                Sessions[i].Ack_number = TCP.th_seq;
                Sessions[i].Contact = 2;
                break;
            }
        }
    }
    else if (flags.bits.SYN == 0 && flags.bits.ACK == 1)  //the third step of the handshake
    {
        for (int i = 0; i < index; i++)
        {
            if ((Sessions[i].dst_port == TCP.dst_port) && (Sessions[i].src_port == TCP.src_port) && (ntohl(TCP.th_seq) == Sessions[i].sequence_number))
            {
                Sessions[i].Contact = 3;
                break;
            }
        }
        Handshakes_Sucsess++;
    }
    else if (flags.bits.FIN == 1 && flags.bits.ACK == 0)   // finish the session 
    {
        for (int i = 0; i < index; i++)
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


void Handle_TCP(Transport_tcp& TCP, Handshake* Sessions, int& Handshakes_Sucsess, int& index, int& Array_Size)
{
    Search_Sessions(TCP, Sessions, Handshakes_Sucsess, index, Array_Size);
}
