// TCP_Sessions.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
#include <iostream>
#include <fstream>
#include <malloc.h>
#include "Headers.h"
#include "Handshake.h"
#include "Parser.h"

using namespace std;

int main()
{
    FILE* ptrFile;            // the pointer to the file for reading
    errno_t err;              //opening with mistake
    const char* fname = "C:/Users/iranm/Desktop/PCAP-Parser-in-C-main/src/dump_sorm.pcap";
    int Array_Size = 100;
    Handshake* Sessions = (Handshake*)malloc(Array_Size * sizeof(Handshake));    // started hanshakes
    if (Sessions == NULL)
    {
        exit(-1);
    }
    err = fopen_s(&ptrFile, fname, "rb");

    if (err == 0)
    {
        Parser parser;
        parser.CountSessions(ptrFile, Sessions, Array_Size);
        free(Sessions);
        err = fclose(ptrFile);
    }
    else
    {
        free(Sessions);
        printf("Mistake\n");
    }

    if (ptrFile)
    {
        err = fclose(ptrFile);
        if (err == 0)
        {
            printf("The file 'crt_fopen_s.c' was closed\n");
        }
    }
    return 0;
}

