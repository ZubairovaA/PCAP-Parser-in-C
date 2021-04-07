#pragma once
#include<Winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <stdio.h>

struct Link                        //��������� ��������� Ethernet    Ethernet header struct
{
    unsigned char ether_dhost[6];  //MAC ����� ����������           MAC dest address
    unsigned char ether_shost[6];  //MAC ����� �����������          MAC source address
    unsigned short ether_type;     //��� ��������� �������� ������  next level protocol    
};

bool Handle_Ethernet(Link& ethernet, FILE* ptrFile);   //working with ethernet protocol header
