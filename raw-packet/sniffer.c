/*
author          Oliver Blaser
date            07.04.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../common.h"
#include "../socket-helper.h"

#include <net/ethernet.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <unistd.h>



int main(int argc, char** argv)
{
    char xtosBuffer[100];

    uint16_t protocol = ETH_P_ALL;

    if (argc > 1)
    {
        const char* const arg1 = argv[1];

        if (0 == strncmp(arg1, "IP", 3)) { protocol = ETH_P_IP; }
        else if (0 == strncmp(arg1, "ARP", 4)) { protocol = ETH_P_ARP; }
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



    const int sockfd = socket(AF_PACKET, SOCK_RAW, htons(protocol));
    if (sockfd < 0)
    {
        printErrno("failed to create socket", errno);
        return EC_SOCK;
    }

    uint8_t sockData[ETH_FRAME_LEN + 4 /* VLAN Extended Header */];
    struct sockaddr_storage sockSrcAddr;
    socklen_t sockSrcAddrSize = sizeof(sockSrcAddr);

    while (1)
    {
        const ssize_t sockDataSize = recvfrom(sockfd, sockData, sizeof(sockData), 0, (struct sockaddr*)(&sockSrcAddr), &sockSrcAddrSize);

        if (sockDataSize < 0)
        {
            printErrno("recvfrom() failed", errno);
            close(sockfd);
            return EC_ERROR;
        }
        else
        {
            printf("\n" SGR_BLUE "  --=====| " SGR_BBLUE " %s " SGR_BLUE " |=====--" SGR_DEFAULT "\n",
                   sockaddrtos(&sockSrcAddr, xtosBuffer, sizeof(xtosBuffer)));

#if 0
            printf(SGR_BBLACK "packet size: %zi\n", sockDataSize);
            hexDump(sockData, sockDataSize);
            printf(SGR_DEFAULT "\n");
            fflush(stdout);
#endif

            printEthPacket(sockData, sockDataSize);
        }
    }

    close(sockfd);

    return 0;
}
