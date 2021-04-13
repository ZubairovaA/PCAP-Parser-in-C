#include "Headers.h"
#include<Winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <stdio.h>

using namespace std;

static void VLAN_Protocol(Link& ethernet, FILE* ptrFile) {   //Checking for the VLAN protocol
    if (ntohs(ethernet.ether_type) == 0x8100) {    // checking for the VLAN tag  
        fseek(ptrFile, 2, SEEK_CUR);               //if there is the VLAN tag, mooving the pointer for the 4 bytes to determinate the beginning of the ether type 
        fread(&ethernet.ether_type, 2, 1, ptrFile);
    }
}

static bool Check_IP_Protocol(Link& ethernet, FILE* ptrFile) {
    if (ntohs(ethernet.ether_type) != 0x0800)   //if the internet layer protocol is the Internet Protocol Verion 4
    {
        return true;
    }
    else
    {
        return false;
    }
}

bool Handle_Ethernet(Link& ethernet, FILE* ptrFile) {
    VLAN_Protocol(ethernet, ptrFile);
    return  Check_IP_Protocol(ethernet, ptrFile);
}

