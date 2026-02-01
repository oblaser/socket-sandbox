/*
author          Oliver Blaser
date            07.04.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../common.h"
#include "../socket-helper.h"

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <unistd.h>



typedef _Bool bool_t;



int main(int argc, char** argv)
{
    char xtosBuffer[100];

    uint16_t filterEthProtocol = ETH_P_ALL;
    uint16_t filterIpProtocol = 0;

    if (argc > 1)
    {
        const char* const arg1 = argv[1];

        if (0 == strncmp(arg1, "ARP", 4)) { filterEthProtocol = ETH_P_ARP; }
        else if (0 == strncmp(arg1, "IP", 3)) { filterEthProtocol = ETH_P_IP; }
        else if (0 == strncmp(arg1, "ICMP", 5))
        {
            filterEthProtocol = ETH_P_IP;
            filterIpProtocol = IPPROTO_ICMP;
        }
        else if (0 == strncmp(arg1, "TCP", 4))
        {
            filterEthProtocol = ETH_P_IP;
            filterIpProtocol = IPPROTO_TCP;
        }
        else if (0 == strncmp(arg1, "UDP", 4))
        {
            filterEthProtocol = ETH_P_IP;
            filterIpProtocol = IPPROTO_UDP;
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



    const int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
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
            const int err = close(sockfd);
            if (err) { printErrno("close() failed", errno); }
            return EC_ERROR;
        }
        else
        {
            const struct ethhdr* const ethHeader = (const struct ethhdr*)(sockData);
            uint16_t ethProtocol = ntohs(ethHeader->h_proto);
            const size_t ethHeaderSize = ((ethProtocol == ETH_P_8021Q) ? (ETH_HLEN + 4) : (ETH_HLEN));
            __attribute__((unused)) const uint8_t* const ethData = sockData + ethHeaderSize;
            __attribute__((unused)) const size_t ethDataSize = sockDataSize - ethHeaderSize;

            const struct iphdr* const ipHeader = (const struct iphdr*)(ethData);
            const uint8_t ipIhl = ipHeader->ihl;
            const size_t ipHeaderSize = ipIhl * 4u;
            const uint8_t ipProtocol = ipHeader->protocol;
            __attribute__((unused)) const uint8_t* const ipData = ethData + ipHeaderSize;
            __attribute__((unused)) const size_t ipDataSize = ethDataSize - ipHeaderSize;

            const uint16_t ipCheckCalc = inet_checksum(ethData, ipHeaderSize);

            struct ippseudohdr ___pseudoHdr;
            const struct ippseudohdr* const pseudoHdr = &___pseudoHdr;
            ippseudohdr_init(&___pseudoHdr, ipHeader);

            __attribute__((unused)) uint16_t srcPort = 0;
            __attribute__((unused)) uint16_t dstPort = 0;
            __attribute__((unused)) uint8_t icmpType;

            __attribute__((unused)) bool_t checksumOk = true;
            if (ipCheckCalc != 0) { checksumOk = false; }

            if (ipProtocol == IPPROTO_TCP)
            {
                const struct tcphdr* const tcpHeader = (const struct tcphdr*)(ipData);
                srcPort = ntohs(tcpHeader->th_sport);
                dstPort = ntohs(tcpHeader->th_dport);

                uint32_t sum;
                inet_checksum_init(&sum);
                inet_checksum_update_ippseudohdr(&sum, pseudoHdr);
                inet_checksum_update(&sum, ipData, pseudoHdr->length);
                const uint16_t tcpCheckCalc = inet_checksum_final(&sum);

                if (tcpCheckCalc != 0) { checksumOk = false; }
            }
            else if (ipProtocol == IPPROTO_UDP)
            {
                const struct udphdr* const udpHeader = (const struct udphdr*)(ipData);
                srcPort = ntohs(udpHeader->uh_sport);
                dstPort = ntohs(udpHeader->uh_dport);

                uint32_t sum;
                inet_checksum_init(&sum);
                inet_checksum_update_ippseudohdr(&sum, pseudoHdr);
                inet_checksum_update(&sum, ipData, pseudoHdr->length);
                const uint16_t udpCheckCalc = inet_checksum_final(&sum);

                if (udpCheckCalc != 0) { checksumOk = false; }
            }
            else if (ipProtocol == IPPROTO_ICMP)
            {
                const struct icmphdr* const icmpHeader = (const struct icmphdr*)(ipData);
                const size_t icmpHeaderSize = 8;
                icmpType = icmpHeader->type;
                const size_t icmpDataSize = ipDataSize - icmpHeaderSize;

                const uint16_t icmpCheckCalc = inet_checksum(ipData, icmpHeaderSize + icmpDataSize);

                if (icmpCheckCalc != 0) { checksumOk = false; }
            }



            // filter
            if ((1 && 0) || 0 ||                                                            // global enable/disable filter
                ((filterEthProtocol != ETH_P_ALL) && (ethProtocol == filterEthProtocol)) || // ETH protocol filter
                ((filterIpProtocol != 0) && (ipProtocol == filterIpProtocol)) ||            // IP protocol filter
                //(!checksumOk) ||                                               // checksum filter
                false // (closing global)
            )
            {
#if 0
                if ((ethHeader->h_source[0] == 0xb8) && (ethHeader->h_source[1] == 0xd8) && (ethHeader->h_source[2] == 0x12)) { continue; }
#endif

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
    } // while (1)

    const int err = close(sockfd);
    if (err) { printErrno("close() failed", errno); }

    return 0;
}
