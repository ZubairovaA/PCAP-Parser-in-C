// tcpsesscount.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.


#include <iostream>
#include<fstream>
#include <typeinfo>
#include<Winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <stdio.h>
#include"PCAP_Headers.h"
#include"Link.h"
#include"Internet.h"
#include"Transport.h"

using namespace std;

void Parse(FILE* ptrFile, Link& ethernet, pcap_pkthdr& ptk_header, Internet_ip& ip, long & pkt_offset, Transport_tcp& TCP, Handshake* Sessions, int & Handshakes_Sucsess, int& index)
{
    
    while (fseek(ptrFile, pkt_offset, SEEK_SET) == 0)
    {
        if (fread(&ptk_header, 16, 1, ptrFile) == 0) //read pcap packet header 16 bytes
        {
            if (feof(ptrFile)) printf("Premature end of file.\n");   // if the end of the file ia reached
            break;
        }

        if (fread(&ethernet, 14, 1, ptrFile) == 0) //read ethernet header
        {
            if (feof(ptrFile)) printf("Premature end of file.\n");   // if the end of the file ia reached

            break;
        }

        bool Continue = Handle_Ethernet(ethernet, ptrFile);
        if (Continue == true) 
        {
            continue;
        }

        if (fread(&ip, sizeof(ip), 1, ptrFile) == 0) //read internet header
        {
            if (feof(ptrFile)) printf("Premature end of file.\n");

            break;
        }
        if (ip.ip_p == IPPROTO_TCP) 
        {
            if (fread(&TCP, sizeof(TCP), 1, ptrFile) == 0) //read pcap packet head
            {
                if (feof(ptrFile)) printf("Premature end of file.\n");
                break;
            }

            Handle_TCP(TCP, Sessions, Handshakes_Sucsess, index);        
        }

        pkt_offset += 16 + ptk_header.caplen;
    }
}
    

    int Unfinished (Handshake* Sessions, int& index)
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

    int Unstandart_Finished(Handshake* Sessions, int& index)
    {
        int count = 0;
        for (int i = 0; i < index; i++)
        {
            if(Sessions[i].Finish!=2)
            count++;
        }
        return count;
    }

int main()
{
    Link ethernet ;           //the struct of the Ethernet protocol header
    pcap_pkthdr ptk_header;   // the struct of the packet header
    Internet_ip ip;           //the struct of the IP protocol header
    Transport_tcp TCP;        //the struct of the TCP protocol header
    FILE* ptrFile;            // the pointer to the file for reading
    errno_t err;              //opening with mistake
    const char* fname = "local_fix_sample.pcap";
    int Handshakes_Sucsess = 0;
    int Unfinished_Sessions = 0;
    int Unstarnadt_Sessions = 0;
    long pkt_offset = 24;           // the offset
    Handshake Sessions [500];    // started hanshakes
    int index = 0;               //index for the array

    err = fopen_s(&ptrFile, fname, "rb");

    if (err == 0)
    {
        Parse(ptrFile, ethernet, ptk_header, ip, pkt_offset, TCP, Sessions, Handshakes_Sucsess, index);
        if (index > 0)      
        {
            Unfinished_Sessions = Unfinished(Sessions, index);
            Unstarnadt_Sessions = Unstandart_Finished(Sessions, index);
            
            printf ("The.pcap file includes: \n");
            printf("Handshakes: %d.\n", Handshakes_Sucsess);
            printf("Unfinished sessions: %d.\n", Unfinished_Sessions);
            printf("Unstarnadt sessions: %d.\n", Unstarnadt_Sessions);
        }  
        else 
        {
            printf ("There are no handshakes in the .pcap file.\n");
         
        }
        
        err = fclose(ptrFile);
    }
    else 
    {
        printf ("Mistake\n");
    }


    
     if( ptrFile)
   {
      err = fclose( ptrFile );
      if ( err == 0 )
      {
         printf( "The file 'crt_fopen_s.c' was closed\n" );
      }
   }
   

    return 0;
}

// Запуск программы: CTRL+F5 или меню "Отладка" > "Запуск без отладки"
// Отладка программы: F5 или меню "Отладка" > "Запустить отладку"

// Советы по началу работы 
//   1. В окне обозревателя решений можно добавлять файлы и управлять ими.
//   2. В окне Team Explorer можно подключиться к системе управления версиями.
//   3. В окне "Выходные данные" можно просматривать выходные данные сборки и другие сообщения.
//   4. В окне "Список ошибок" можно просматривать ошибки.
//   5. Последовательно выберите пункты меню "Проект" > "Добавить новый элемент", чтобы создать файлы кода, или "Проект" > "Добавить существующий элемент", чтобы добавить в проект существующие файлы кода.
//   6. Чтобы снова открыть этот проект позже, выберите пункты меню "Файл" > "Открыть" > "Проект" и выберите SLN-файл.
