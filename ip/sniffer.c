/*
author          Oliver Blaser
date            01.02.2026
copyright       GPL-3.0 - Copyright (c) 2026 Oliver Blaser
*/

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../common.h"
#include "../socket-helper.h"

#ifdef _WIN32

#include <io.h>
#include <sys/types.h>
#include <winsock2.h>
#include <WS2tcpip.h>

#include <Windows.h>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif // _MSC_VER

#else // _WIN32

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <unistd.h>

#endif // _WIN32



typedef _Bool bool_t;



static bool_t isPhyoipPacket(const uint8_t* ipPacket, size_t size);



int main(int argc, char** argv)
{
    int err;
    char xtosBuffer[100];

    uint16_t filterIpProtocol = 0;
    bool_t filterPHYoIP = false;

    if (argc > 1)
    {
        const char* const arg1 = argv[1];

        if (0 == strncmp(arg1, "ICMP", 5)) { filterIpProtocol = IPPROTO_ICMP; }
        else if (0 == strncmp(arg1, "TCP", 4)) { filterIpProtocol = IPPROTO_TCP; }
        else if (0 == strncmp(arg1, "UDP", 4)) { filterIpProtocol = IPPROTO_UDP; }
        else if (0 == strncmp(arg1, "PHYoIP", 7)) // see https://github.com/PHYoIP
        {
            filterIpProtocol = 0;
            filterPHYoIP = true;
        }
        else
        {
            char str[200];
            strcpy(str, "unknown protocol \"");
            strcat(str, arg1);
            strcat(str, "\"");

            printError(str);
            return EC_ERROR;
        }
    }

#ifndef _WIN32
    if (filterIpProtocol == 0) { printWarning("missing protocol filter"); }
#endif



#ifdef _WIN32
    enableVirtualTerminalProcessing();

    WSADATA wsaData;
    err = WSAStartup(0x0202, &wsaData);
    if (err)
    {
        printWSError("WSAStartup() failed", err);
        cleanupWinsock();
        return EC_ERROR;
    }
#endif // _WIN32

    const int sockfd = socket(AF_INET, SOCK_RAW,
#ifdef _WIN32
                              IPPROTO_IP
#else
                              filterIpProtocol
#endif
    );
    if (sockfd < 0)
    {
#ifdef _WIN32
        printWSError("socket() failed", WSAGetLastError());
        cleanupWinsock();
#else
        printErrno("socket() failed", errno);
#endif
        return EC_SOCK;
    }

    struct sockaddr_in srvaddr;
    memset(&srvaddr, 0, sizeof(srvaddr));

    srvaddr.sin_family = AF_INET;
    srvaddr.sin_port = htons(0);
    srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    err = bind(sockfd, (struct sockaddr*)(&srvaddr), sizeof(srvaddr));
    if (err)
    {
#ifdef _WIN32
        printWSError("bind() failed", WSAGetLastError());
        err = closesocket(sockfd);
        if (err) { printWSError("closesocket(sockfd) failed", WSAGetLastError()); }
        cleanupWinsock();
#else
        printErrno("bind() failed", errno);
        close(sockfd);
#endif
        return EC_BIND;
    }

    uint8_t sockData[256 * 1024];
    struct sockaddr_storage sockSrcAddr;
    socklen_t sockSrcAddrSize = sizeof(sockSrcAddr);

    while (1)
    {
        const ssize_t sockDataSize = recvfrom(sockfd, sockData, sizeof(sockData), 0, (struct sockaddr*)(&sockSrcAddr), &sockSrcAddrSize);

        if (sockDataSize < 0)
        {
#ifdef _WIN32
            printWSError("recvfrom() failed", WSAGetLastError());
            err = closesocket(sockfd);
            if (err) { printWSError("closesocket(sockfd) failed", WSAGetLastError()); }
            cleanupWinsock();
#else
            printErrno("recvfrom() failed", errno);
            err = close(sockfd);
            if (err) { printErrno("close() failed", errno); }
#endif

            return EC_ERROR;
        }
        else
        {
            const struct iphdr* const ipHeader = (const struct iphdr*)(sockData);
            const uint8_t ipIhl = ipHeader->ihl;
            const size_t ipHeaderSize = ipIhl * 4u;
            const uint8_t ipProtocol = ipHeader->protocol;

            if ((filterIpProtocol != 0) && (filterIpProtocol != ipProtocol)) { continue; }
            if (filterPHYoIP && !isPhyoipPacket(sockData, sockDataSize)) { continue; }

            printf("\n" SGR_BLUE "  --=====| " SGR_BBLUE " %s " SGR_BLUE " |=====--" SGR_DEFAULT "\n",
                   sockaddrtos(&sockSrcAddr, xtosBuffer, sizeof(xtosBuffer)));

#if 0
            printf(SGR_BBLACK "packet size: %zi\n", sockDataSize);
            hexDump(sockData, sockDataSize);
            printf(SGR_DEFAULT "\n");
            fflush(stdout);
#endif

            printIpPacket(sockData, sockDataSize);
        }
    }

#ifdef _WIN32
    err = closesocket(sockfd);
    if (err) { printWSError("closesocket(sockfd) failed", WSAGetLastError()); }
    cleanupWinsock();
#else
    err = close(sockfd);
    if (err) { printErrno("close(sockfd) failed", errno); }
#endif

    return 0;
}



bool_t isPhyoipPacket(const uint8_t* ipPacket, size_t size)
{
    const uint8_t* phyoipData = NULL;

    const struct iphdr* const ipHeader = (const struct iphdr*)(ipPacket);
    const uint8_t ipIhl = ipHeader->ihl;
    const size_t ipHeaderSize = ipIhl * 4u;
    const uint8_t ipProtocol = ipHeader->protocol;
    const uint8_t* const ipData = ipPacket + ipHeaderSize;
    const size_t ipDataSize = size - ipHeaderSize;

    if (ipProtocol == IPPROTO_TCP)
    {
        const uint8_t* const data = ipData;
        const size_t size = ipDataSize;

        const struct tcphdr* const tcpHeader = (const struct tcphdr*)(data);
        const uint8_t tcpDataOff = tcpHeader->th_off;
        const size_t tcpHeaderSize = tcpDataOff * 4u;
        const uint8_t* const tcpData = data + tcpHeaderSize;
        const size_t tcpDataSize = size - tcpHeaderSize;
        const uint8_t* const padData = data + tcpHeaderSize + tcpDataSize; // potential padding
        const size_t padDataSize = size - tcpHeaderSize - tcpDataSize;     // potential padding

        phyoipData = tcpData;
    }
    else if (ipProtocol == IPPROTO_UDP)
    {
        const uint8_t* const data = ipData;
        const size_t size = ipDataSize;

        const struct udphdr* const udpHeader = (const struct udphdr*)(data);
        const size_t udpHeaderSize = 8;
        const uint16_t udpLength = ntohs(udpHeader->uh_ulen);
        const uint8_t* const udpData = data + udpHeaderSize;
        const size_t udpDataSize = udpLength - udpHeaderSize;
        const uint8_t* const padData = data + udpHeaderSize + udpDataSize; // potential padding
        const size_t padDataSize = size - udpHeaderSize - udpDataSize;     // potential padding

        phyoipData = udpData;
    }
    else { return false; }



    for (size_t i = 0; i < 10; ++i)
    {
        if (0 == strncmp((const char*)(phyoipData + i), "PHYoIP", 6)) { return true; }
    }

    return false;
}
