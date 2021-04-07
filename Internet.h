#pragma once
#include<Winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <stdio.h>

using namespace std;

struct Internet_ip {                //��������� ��������� Internet    Internet  header struct
    unsigned char ip_vhl;		   // ������ ip ��������� � ����� ���������(*4)  ip protocol version
    unsigned char ip_tos;		   // ��� ������������   type of service
    unsigned short ip_len;		   // ����� ������ ����� ������   the size of the packet
    unsigned short ip_id;		   // ����������������� ����� ������ ��� �������� ����� �� �����   identification
    unsigned short ip_off;		   // fragment offset field   
#define IP_RF 0x8000		       // ����- ����������������� ��������    reserved fragment flag 
#define IP_DF 0x4000		       // ����- ����� �� ���������������      don't fragment flag
#define IP_MF 0x2000		       // ����- ����� � ��� ���������         more fragments flag
#define IP_OFFMASK 0x1fff	       // ����� ��� ���������������� �����    mask for fragmenting bits
    unsigned char ip_ttl;		   // time to live
    unsigned char ip_p;		       // �������� ���� ������                next level protocol
    unsigned short ip_sum;		   // ��������                            checksum
    unsigned char ip_src[4];       //  ����� �����������                  source address
    unsigned char ip_dst[4];       //  ����� ����������                   dest address
};




