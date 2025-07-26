/*
author          Oliver Blaser
date            07.04.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "common.h"
#include "socket-helper.h"

#ifdef _WIN32

#include <sys/types.h>
#include <winsock2.h>
#include <WS2tcpip.h>

#include <Windows.h>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif // _MSC_VER

#else // _WIN32

#include <arpa/inet.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <ifaddrs.h>
#include <unistd.h>

#endif // _WIN32


#define SGR_ETH     SGR_DEFAULT
#define SGR_ARP     SGR_RGB(244, 221, 153)
#define SGR_IPv4    SGR_DEFAULT
#define SGR_ICMP    SGR_DEFAULT
#define SGR_TCP     SGR_RGB(255, 194, 255)
#define SGR_UDP     SGR_RGB(156, 227, 255)
#define SGR_PADDING SGR_BBLACK


#define SWITCH_CASE_STRCPY_DEFINE(_dst, _define, _off)    \
    case _define:                                         \
        strcpy((_dst), (const char*)(#_define) + (_off)); \
        break



#ifndef _WIN32

struct ippseudohdr* ippseudohdr_init(struct ippseudohdr* dst, const struct iphdr* iphdr)
{
    struct sockaddr_in* dst_saddr = (struct sockaddr_in*)(&(dst->saddr));
    dst_saddr->sin_family = AF_INET;
    dst_saddr->sin_port = 0;
    dst_saddr->sin_addr.s_addr = iphdr->saddr;

    struct sockaddr_in* dst_daddr = (struct sockaddr_in*)(&(dst->daddr));
    dst_daddr->sin_family = AF_INET;
    dst_daddr->sin_port = 0;
    dst_daddr->sin_addr.s_addr = iphdr->daddr;

    dst->protocol = iphdr->protocol;

    dst->length = ntohs(iphdr->tot_len) - ((uint16_t)(iphdr->ihl) * 4);

    return dst;
}

struct ippseudohdr* ippseudohdr_init6(struct ippseudohdr* dst, const void* saddr, const void* daddr, uint8_t protocol, uint32_t length)
{
    fprintf(stderr, SGR_BRED "error:" SGR_DEFAULT " %s is not yet implemented", __func__);
    return NULL;
}

#endif // _WIN32



uint16_t inet_checksum(const uint8_t* data, size_t count)
{
    uint32_t sum = 0;

    while (count > 1)
    {
        sum += (((uint16_t)(*data) << 8) | (uint16_t)(*(data + 1)));

        data += 2;
        count -= 2;
    }

    if (count > 0) { sum += (uint32_t)(*data) << 8; }

    sum = (sum & 0x0000FFFF) + (sum >> 16);

    return (uint16_t)(~sum);
}

void inet_checksum_update(uint32_t* sum, const uint8_t* data, size_t count)
{
    while (count > 1)
    {
        *sum += (((uint16_t)(*data) << 8) | (uint16_t)(*(data + 1)));

        data += 2;
        count -= 2;
    }

    if (count > 0) { *sum += (uint32_t)(*data) << 8; }
}

void inet_checksum_update_ippseudohdr(uint32_t* sum, const struct ippseudohdr* pseudoHdr)
{
    const int af = pseudoHdr->saddr.ss_family;

    switch (af)
    {
    case AF_INET:
    {
        const struct sockaddr_in* saddr = (struct sockaddr_in*)(&(pseudoHdr->saddr));
        const struct sockaddr_in* daddr = (struct sockaddr_in*)(&(pseudoHdr->daddr));

        inet_checksum_update32n(sum, saddr->sin_addr.s_addr);
        inet_checksum_update32n(sum, daddr->sin_addr.s_addr);
        inet_checksum_update16h(sum, (uint16_t)(pseudoHdr->protocol));
        inet_checksum_update16h(sum, (uint16_t)(pseudoHdr->length));
    }
    break;

    case AF_INET6:
    {
        const struct sockaddr_in6* saddr = (struct sockaddr_in6*)(&(pseudoHdr->saddr));
        const struct sockaddr_in6* daddr = (struct sockaddr_in6*)(&(pseudoHdr->daddr));

        fprintf(stderr, SGR_BRED "error:" SGR_DEFAULT " %s does not yet support IPv6", __func__);
        (void)saddr;
        (void)daddr;
        inet_checksum_update32h(sum, pseudoHdr->length);
        inet_checksum_update16h(sum, (uint16_t)(pseudoHdr->protocol));
    }
    break;

    default:
    {
        char buffer[AF_STRLEN];
        fprintf(stderr, SGR_BRED "error:" SGR_DEFAULT " %s does not support %s", __func__, aftos(af, buffer, sizeof(buffer)));
    }
    break;
    }
}

uint16_t inet_checksum_final(uint32_t* sum)
{
    *sum = ~((*sum & 0x0000FFFF) + (*sum >> 16));
    return (uint16_t)(*sum);
}



char* mactos(const uint8_t* mac, char* dst, size_t size)
{
    char* r = NULL;

    if (mac && dst && (size >= MAC_ADDRSTRLEN))
    {
        const size_t res = (size_t)snprintf(dst, size, "%02x-%02x-%02x-%02x-%02x-%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        if (res < size) { r = dst; }
    }

    return r;
}

char* aftos(int af, char* dst, size_t size)
{
    char* r = NULL;

    if (dst && (size >= AF_STRLEN))
    {
        r = dst;

        switch (af)
        {
            SWITCH_CASE_STRCPY_DEFINE(dst, AF_UNSPEC, 3);
            SWITCH_CASE_STRCPY_DEFINE(dst, AF_INET, 3);
            SWITCH_CASE_STRCPY_DEFINE(dst, AF_IPX, 3);
            SWITCH_CASE_STRCPY_DEFINE(dst, AF_INET6, 3);
#ifndef _WIN32
#if (AF_UNIX != AF_LOCAL)
            SWITCH_CASE_STRCPY_DEFINE(dst, AF_UNIX, 3);
#endif
            SWITCH_CASE_STRCPY_DEFINE(dst, AF_PACKET, 3);
            SWITCH_CASE_STRCPY_DEFINE(dst, AF_X25, 3);
            SWITCH_CASE_STRCPY_DEFINE(dst, AF_AX25, 3);
#else  // _WIN32
            SWITCH_CASE_STRCPY_DEFINE(dst, AF_LOCAL, 3);
#endif // _WIN32

        default:
        {
            _Static_assert(AF_STRLEN >= 7, "increase AF_STRLEN");
            _Static_assert(AF_MAX < 100, "increase the compare value in the AF_STRLEN assertion");

            const size_t res = (size_t)snprintf(dst, size, "AF_#%i", af);
            if (res >= size) { r = NULL; }
        }
        break;
        }
    }

    return r;
}

char* ethptos(uint16_t proto, char* dst, size_t size)
{
    char* r = NULL;

    if (dst && (size >= ETH_P_STRLEN))
    {
        r = dst;

        switch (proto)
        {
#ifndef _WIN32
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_IP, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_X25, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_ARP, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_IPV6, 6);

            // seems like a socket won't ever receive a "non Ethernet II" packet, so convert these to string?
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_LOOP, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_PUP, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_PUPAT, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_802_3, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_AX25, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_ALL, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_802_2, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_SNAP, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_DDCMP, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_WAN_PPP, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_PPP_MP, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_LOCALTALK, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_CAN, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_CANFD, 6);
#ifdef ETH_P_CANXL
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_CANXL, 6);
#endif
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_PPPTALK, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_TR_802_2, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_MOBITEX, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_CONTROL, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_IRDA, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_ECONET, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_HDLC, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_ARCNET, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_DSA, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_TRAILER, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_PHONET, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_IEEE802154, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_CAIF, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_XDSA, 6);
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_MAP, 6);
#ifdef ETH_P_MCTP
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_MCTP, 6);
#endif
#endif // _WIN32

        default:
        {
            const char* format;
            if (proto <= 1500) { format = "[len: %i]"; } // IEEE 802.3 data length
            else { format = "ETH_P_#%04xh"; }            // Ethernet II EtherType

            _Static_assert(ETH_P_STRLEN >= 13, "increase ETH_P_STRLEN");

            const size_t res = (size_t)snprintf(dst, size, format, (int)proto);
            if (res >= size) { r = NULL; }
        }
        break;
        }
    }

    return r;
}

char* ipptos(uint16_t proto, char* dst, size_t size)
{
    char* r = NULL;

    if (dst && (size >= IPPROTO_STRLEN))
    {
        r = dst;

        switch (proto)
        {
            // SWITCH_CASE_STRCPY_DEFINE(dst, IPPROTO_IP, 8); dummy
            SWITCH_CASE_STRCPY_DEFINE(dst, IPPROTO_ICMP, 8);
            SWITCH_CASE_STRCPY_DEFINE(dst, IPPROTO_IGMP, 8);
            SWITCH_CASE_STRCPY_DEFINE(dst, IPPROTO_TCP, 8);
            SWITCH_CASE_STRCPY_DEFINE(dst, IPPROTO_UDP, 8);
            SWITCH_CASE_STRCPY_DEFINE(dst, IPPROTO_IPV6, 8);
#ifdef IPPROTO_L2TP
            SWITCH_CASE_STRCPY_DEFINE(dst, IPPROTO_L2TP, 8);
#endif
#ifdef IPPROTO_ETHERNET
            SWITCH_CASE_STRCPY_DEFINE(dst, IPPROTO_ETHERNET, 8);
#endif
            SWITCH_CASE_STRCPY_DEFINE(dst, IPPROTO_RAW, 8);

        default:
        {
            _Static_assert(IPPROTO_STRLEN >= 15, "increase IPPROTO_STRLEN");
            const char* format;
            if (proto <= 0x00FF) { format = "IPPROTO_#%02xh"; }
            else { format = "IPPROTO_#%04xh"; }

            const size_t res = (size_t)snprintf(dst, size, format, (int)proto);
            if (res >= size) { r = NULL; }
        }
        break;
        }
    }

    return r;
}

char* icmpttos(uint8_t type, char* dst, size_t size)
{
    char* r = NULL;

    if (dst && (size >= ICMP_TYPE_STRLEN))
    {
        r = dst;

        switch (type)
        {
#ifndef _WIN32
            SWITCH_CASE_STRCPY_DEFINE(dst, ICMP_ECHOREPLY, 5);
            SWITCH_CASE_STRCPY_DEFINE(dst, ICMP_DEST_UNREACH, 5);
            SWITCH_CASE_STRCPY_DEFINE(dst, ICMP_SOURCE_QUENCH, 5);
            SWITCH_CASE_STRCPY_DEFINE(dst, ICMP_REDIRECT, 5);
            SWITCH_CASE_STRCPY_DEFINE(dst, ICMP_ECHO, 5);
            SWITCH_CASE_STRCPY_DEFINE(dst, ICMP_TIME_EXCEEDED, 5);
            SWITCH_CASE_STRCPY_DEFINE(dst, ICMP_PARAMETERPROB, 5);
            SWITCH_CASE_STRCPY_DEFINE(dst, ICMP_TIMESTAMP, 5);
            SWITCH_CASE_STRCPY_DEFINE(dst, ICMP_TIMESTAMPREPLY, 5);
            SWITCH_CASE_STRCPY_DEFINE(dst, ICMP_INFO_REQUEST, 5);
            SWITCH_CASE_STRCPY_DEFINE(dst, ICMP_INFO_REPLY, 5);
            SWITCH_CASE_STRCPY_DEFINE(dst, ICMP_ADDRESS, 5);
            SWITCH_CASE_STRCPY_DEFINE(dst, ICMP_ADDRESSREPLY, 5);
#endif // _WIN32

        default:
        {
            _Static_assert(ICMP_TYPE_STRLEN >= 11, "increase ICMP_TYPE_STRLEN");

            const size_t res = (size_t)snprintf(dst, size, "ICMP_#%02xh", (int)type);
            if (res >= size) { r = NULL; }
        }
        break;
        }
    }

    return r;
}

// char* icmpctos(uint8_t code, uint8_t type, char* dst, size_t size) {}

static char* sockaddrtos_inet(const struct sockaddr_in* sa, char* dst, size_t size)
{
    const in_port_t port = sa->sin_port;

    char* r = (char*)inet_ntop(AF_INET, &(sa->sin_addr), dst, size);

    if (r && port)
    {
        _Static_assert(SOCKADDRSTRLEN >= (INET_ADDRSTRLEN + 1 + 5), "increase SOCKADDRSTRLEN");

        char portStr[7];
        const size_t res = (size_t)snprintf(portStr, sizeof(portStr), ":%i", (int)port);
        if (res >= size) { r = NULL; }
        else { strcat(r, portStr); }
    }

    return r;
}

static char* sockaddrtos_inet6(const struct sockaddr_in6* sa, char* dst, size_t size)
{
    char* r = NULL;
    const in_port_t port = sa->sin6_port;

    char addrStrBuffer[INET6_ADDRSTRLEN];
    const char* addrStr = inet_ntop(AF_INET6, &(sa->sin6_addr), addrStrBuffer, sizeof(addrStrBuffer));

    if (addrStr)
    {
        r = dst;

        _Static_assert(SOCKADDRSTRLEN >= (INET6_ADDRSTRLEN + 3 + 5), "increase SOCKADDRSTRLEN");

        if (port == 0) { strcpy(dst, addrStr); }
        else
        {
            const size_t res = (size_t)snprintf(dst, size, "[%s]:%i", addrStr, (int)port);
            if (res >= size) { r = NULL; }
        }
    }

    return r;
}

char* sockaddrtos(const void* sa, char* dst, size_t size)
{
    char* r = NULL;

    if (sa && dst && (size >= SOCKADDRSTRLEN))
    {
        const int af = ((const struct sockaddr*)sa)->sa_family;

        switch (af)
        {
        case AF_INET:
            r = sockaddrtos_inet((const struct sockaddr_in*)sa, dst, size);
            break;

        case AF_INET6:
            r = sockaddrtos_inet6((const struct sockaddr_in6*)sa, dst, size);
            break;

        default:
        {
            _Static_assert(SOCKADDRSTRLEN >= (AF_STRLEN + 11), "increase SOCKADDRSTRLEN");

            char afStrBuffer[AF_STRLEN];
            const char* const afStr = aftos(af, afStrBuffer, sizeof(afStrBuffer));

            strcpy(dst, "(sockaddr ");
            strcat(dst, afStr);
            strcat(dst, ")");
            r = dst;
        }
        break;
        }
    }

    return r;
}



#ifndef _WIN32

static void printPacket_padding(const uint8_t* data, size_t size)
{
    // hex dump padding if it's not all 0
    for (size_t i = 0; i < size; ++i)
    {
        if (data[i])
        {
            printf("\n" SGR_PADDING "Padding:\n");
            hexDump(data, size);
            printf(SGR_DEFAULT);
            fflush(stdout);
            break;
        }
    }
}

void printEthHeader(const uint8_t* data, size_t size)
{
    const struct ethhdr* const ethHeader = (const struct ethhdr*)(data);
    const uint8_t* ethSrc = ethHeader->h_source;
    const uint8_t* ethDst = ethHeader->h_dest;
    uint16_t ethProtocol = ntohs(ethHeader->h_proto);
    const size_t ethHeaderSize = ((ethProtocol == ETH_P_8021Q) ? (ETH_HLEN + 4) : (ETH_HLEN));
    __attribute__((unused)) const uint8_t* const ethData = data + ethHeaderSize;
    __attribute__((unused)) const size_t ethDataSize = size - ethHeaderSize;

    char buffer[100];

    printf(SGR_ETH);

    printf("Ethernet\n");
    printf("  src   %s\n", mactos(ethSrc, buffer, sizeof(buffer)));
    printf("  dst   %s\n", mactos(ethDst, buffer, sizeof(buffer)));

    if (ethProtocol == ETH_P_8021Q) // not tested
    {
        const struct ethhdr8021Q* const ethHeader = (const struct ethhdr8021Q*)(data);
        const uint16_t ethVlanTpid = ntohs(ethHeader->ehq_tpid); // Tag Protocol Identifier
        const uint16_t ethVlanTci = ntohs(ethHeader->ehq_tci);   // Tag Control Information
        const int ethVlanPcp = ethVlanTci >> 13;                 // Priority Code Point
        const int ethVlanDei = (ethVlanTci >> 12) & 0x01;        // Drop Eligible Indicator
        const int ethVlanVid = ethVlanTci & 0x0FFF;              // VLAN-Identifier
        ethProtocol = ntohs(ethHeader->ehq_proto);

        printf("  802.1Q VLAN Extended Header (0x%04x)\n", (int)ethVlanTpid);
        printf("    PCP %i", ethVlanPcp);
        printf("    DEI %i", ethVlanDei);
        printf("    VID %i", ethVlanVid);
    }

    printf("  proto 0x%04x %s\n", (int)ethProtocol, ethptos(ethProtocol, buffer, sizeof(buffer)));
    printf("  hdr size  %zu\n", ethHeaderSize);
    printf("  data size %zu\n", ethDataSize);

    hexDump((const uint8_t*)ethHeader, ethHeaderSize);

    printf(SGR_DEFAULT);
    fflush(stdout);
}

void printEthPacket(const uint8_t* data, size_t size)
{
    printEthHeader(data, size);
    printf("\n");

    const struct ethhdr* const ethHeader = (const struct ethhdr*)(data);
    uint16_t ethProtocol = ntohs(ethHeader->h_proto);
    const size_t ethHeaderSize = ((ethProtocol == ETH_P_8021Q) ? (ETH_HLEN + 4) : (ETH_HLEN));
    const uint8_t* const ethData = data + ethHeaderSize;
    const size_t ethDataSize = size - ethHeaderSize;

    if (ethProtocol == ETH_P_IP) { printIpPacket(ethData, ethDataSize); }
    else if (ethProtocol == ETH_P_ARP)
    {
        const struct arphdr* const arpHeader = (const struct arphdr*)(ethData);
        const size_t arpHeaderSize = 8;
        const uint16_t arpHwType = ntohs(arpHeader->ar_hrd);
        const uint16_t arpProtocol = ntohs(arpHeader->ar_pro);
        const uint8_t arpHwLength = arpHeader->ar_hln;
        const uint8_t arpProtoLen = arpHeader->ar_pln;
        const uint16_t arpOperation = ntohs(arpHeader->ar_op);
        const uint8_t* const arpData = ethData + arpHeaderSize;
        const size_t arpDataSize = 2 * arpHwLength + 2 * arpProtoLen;
        const uint8_t* const padData = ethData + arpHeaderSize + arpDataSize; // padding
        const size_t padDataSize = ethDataSize - arpHeaderSize - arpDataSize; // padding

        char buffer[100];

        printf(SGR_ARP);

        printf("ARP\n");
        printf("  hw type   %i %s\n", (int)arpHwType, (arpHwType == ARPHRD_ETHER ? "ETH" : ""));
        printf("  proto     0x%04x %s\n", (int)arpProtocol, ethptos(arpProtocol, buffer, sizeof(buffer)));
        printf("  hw length %i\n", (int)arpHwLength);
        printf("  proto len %i\n", (int)arpProtoLen);
        printf("  operation %i %s\n", (int)arpOperation, (arpOperation == 1 ? "request" : (arpOperation == 2 ? "reply" : "")));
        printf("  hdr size  %zu\n", arpHeaderSize);
        printf("  data size %zu + %zu pad\n", arpDataSize, padDataSize);

        hexDump((const uint8_t*)arpHeader, arpHeaderSize);
        printf("\n");

        if ((arpHwType == ARPHRD_ETHER) && (arpProtocol == ETH_P_IP) && (arpHwLength == ARPDATA_HLEN) && (arpProtoLen == ARPDATA_PLEN))
        {
            const struct arpdata* const arpdata = (const struct arpdata*)(arpData);
            const uint8_t* sMac = arpdata->ar_sha;
            const uint8_t* tMac = arpdata->ar_tha;

            char buffer[100];

            printf("  sender MAC   %s\n", mactos(sMac, buffer, sizeof(buffer)));
            printf("  sender addr  %s\n", inet_ntop(AF_INET, &(arpdata->ar_spa), buffer, sizeof(buffer)));
            printf("  target MAC   %s\n", mactos(tMac, buffer, sizeof(buffer)));
            printf("  target addr  %s\n", inet_ntop(AF_INET, &(arpdata->ar_tpa), buffer, sizeof(buffer)));

            hexDump(arpData, arpDataSize);
        }
        else { hexDump(arpData, arpDataSize); }

        printf(SGR_DEFAULT);
        fflush(stdout);

        printPacket_padding(padData, padDataSize);
    }
    else
    {
        char buffer[100];

        printf(SGR_ETH);

        printf("\nEtherType 0x%04x %s\n", (int)ethProtocol, ethptos(ethProtocol, buffer, sizeof(buffer)));
        hexDump(ethData, ethDataSize);

        printf(SGR_DEFAULT);
        fflush(stdout);
    }
}

void printIpHeader(const uint8_t* data, size_t size)
{
    const struct iphdr* const ipHeader = (const struct iphdr*)(data + 0);
    const uint8_t ipVersion = ipHeader->version;
    const uint8_t ipIhl = ipHeader->ihl;
    const size_t ipHeaderSize = ipIhl * 4u;
    const uint8_t ipTos = ipHeader->tos;
    const uint16_t ipTotalLen = ntohs(ipHeader->tot_len);
    const uint16_t ipId = ntohs(ipHeader->id);
    const uint8_t ipFlags = (uint8_t)(ntohs(ipHeader->frag_off) >> 13);
    const uint16_t ipFragOff = (ntohs(ipHeader->frag_off) & 0x1FFF);
    const uint8_t ipTtl = ipHeader->ttl;
    const uint8_t ipProtocol = ipHeader->protocol;
    const uint16_t ipCheck = ntohs(ipHeader->check);
    const uint32_t srcIp = ntohl(ipHeader->saddr);
    const uint32_t dstIp = ntohl(ipHeader->daddr);
    __attribute__((unused)) const uint8_t* const ipData = data + ipHeaderSize;
    __attribute__((unused)) const size_t ipDataSize = size - ipHeaderSize;

    const uint16_t ipCheckCalc = inet_checksum(data, ipHeaderSize);

    char buffer[100];

    printf(SGR_IPv4);

    printf("IPv4\n");
    printf("  version   %i\n", (int)ipVersion);
    printf("  IHL       %i\n", (int)ipIhl);
    printf("  ToS       0x%02x\n", (int)ipTos);
    printf("  total len %i\n", (int)ipTotalLen);
    printf("  ID        %i\n", (int)ipId);
    printf("  flags     0x%02x\n", (int)ipFlags);
    printf("  frag off  %i\n", (int)ipFragOff);
    printf("  TTL       %i\n", (int)ipTtl);
    printf("  protocol  %02x %s\n", ipProtocol, ipptos(ipProtocol, buffer, sizeof(buffer)));
    printf("  check     %s0x%04x" SGR_IPv4 "\n", ((ipCheckCalc == 0) ? "" : SGR_RED), (int)ipCheck);
    printf("  src addr  %15s = 0x%08x\n", inet_ntop(AF_INET, &(ipHeader->saddr), buffer, sizeof(buffer)), srcIp);
    printf("  dst addr  %15s = 0x%08x\n", inet_ntop(AF_INET, &(ipHeader->daddr), buffer, sizeof(buffer)), dstIp);
    printf("  hdr size  %zu\n", ipHeaderSize);
    printf("  data size %zu\n", ipDataSize);

    hexDump((const uint8_t*)ipHeader, ipHeaderSize);

    printf(SGR_DEFAULT);
    fflush(stdout);
}

void printIpPacket(const uint8_t* data, size_t size)
{
    printIpHeader(data, size);
    printf("\n");

    const struct iphdr* const ipHeader = (const struct iphdr*)(data);
    const uint8_t ipIhl = ipHeader->ihl;
    const size_t ipHeaderSize = ipIhl * 4u;
    const uint8_t ipProtocol = ipHeader->protocol;
    const uint8_t* const ipData = data + ipHeaderSize;
    const size_t ipDataSize = size - ipHeaderSize;

    struct ippseudohdr pseudoHdr;
    ippseudohdr_init(&pseudoHdr, ipHeader);



    if (ipProtocol == IPPROTO_TCP) { printTcpPacket(ipData, ipDataSize, &pseudoHdr); }
    else if (ipProtocol == IPPROTO_UDP) { printUdpPacket(ipData, ipDataSize, &pseudoHdr); }
    else if (ipProtocol == IPPROTO_ICMP) { printIcmpPacket(ipData, ipDataSize); }
    else
    {
        char buffer[100];

        printf(SGR_IPv4);

        printf("IP %s\n", ipptos(ipProtocol, buffer, sizeof(buffer)));
        hexDump(ipData, ipDataSize);

        printf(SGR_DEFAULT);
        fflush(stdout);
    }
}

void printIcmpHeader(const uint8_t* data, size_t size)
{
    const struct icmphdr* const icmpHeader = (const struct icmphdr*)(data);
    const size_t icmpHeaderSize = 8;
    const uint8_t icmpType = icmpHeader->type;
    const uint8_t icmpCode = icmpHeader->code;
    const uint16_t icmpCheck = ntohs(icmpHeader->checksum);
    // ...
    __attribute__((unused)) const uint8_t* const icmpData = data + icmpHeaderSize;
    __attribute__((unused)) const size_t icmpDataSize = size - icmpHeaderSize;
    __attribute__((unused)) const uint8_t* const padData = data + icmpHeaderSize + icmpDataSize; // potential padding
    __attribute__((unused)) const size_t padDataSize = size - icmpHeaderSize - icmpDataSize;     // potential padding

    const uint16_t icmpCheckCalc = inet_checksum(data, icmpHeaderSize + icmpDataSize);

    char buffer[100];

    printf(SGR_ICMP);

    printf("ICMP\n");
    printf("  type      %i %s\n", (int)icmpType, icmpttos(icmpType, buffer, sizeof(buffer)));
    printf("  code      %i\n", (int)icmpCode);
    printf("  check     %s0x%04x" SGR_ICMP "\n", ((icmpCheckCalc == 0) ? "" : SGR_RED), (int)icmpCheck);
    printf("  hdr size  %zu\n", icmpHeaderSize);
    printf("  data size %zu + %zu pad\n", icmpDataSize, padDataSize);

    hexDump((const uint8_t*)icmpHeader, icmpHeaderSize);

    printf(SGR_DEFAULT);
    fflush(stdout);
}

void printIcmpPacket(const uint8_t* data, size_t size)
{
    printIcmpHeader(data, size);
    printf("\n");

    const size_t icmpHeaderSize = 8;
    const uint8_t* const icmpData = data + icmpHeaderSize;
    const size_t icmpDataSize = size - icmpHeaderSize;
    const uint8_t* const padData = data + icmpHeaderSize + icmpDataSize; // potential padding
    const size_t padDataSize = size - icmpHeaderSize - icmpDataSize;     // potential padding

    printf(SGR_ICMP);

    hexDump(icmpData, icmpDataSize);

    printf(SGR_DEFAULT);
    fflush(stdout);

    printPacket_padding(padData, padDataSize);
}

void printTcpHeader(const uint8_t* data, size_t size, const struct ippseudohdr* pseudoHdr)
{
    const struct tcphdr* const tcpHeader = (const struct tcphdr*)(data);
    const uint16_t srcPort = ntohs(tcpHeader->th_sport);
    const uint16_t dstPort = ntohs(tcpHeader->th_dport);
    const uint32_t tcpSeq = ntohl(tcpHeader->th_seq);
    // ...
    const uint8_t tcpDataOff = tcpHeader->th_off;
    const size_t tcpHeaderSize = tcpDataOff * 4u;
    const uint8_t tcpFlags = tcpHeader->th_flags;
    // ...
    const uint16_t tcpCheck = ntohs(tcpHeader->check);
    // ...
    __attribute__((unused)) const uint8_t* const tcpData = data + tcpHeaderSize;
    __attribute__((unused)) const size_t tcpDataSize = size - tcpHeaderSize;
    __attribute__((unused)) const uint8_t* const padData = data + tcpHeaderSize + tcpDataSize; // potential padding
    __attribute__((unused)) const size_t padDataSize = size - tcpHeaderSize - tcpDataSize;     // potential padding

    uint16_t tcpCheckCalc;
    if (pseudoHdr)
    {
        uint32_t sum;
        inet_checksum_init(&sum);
        inet_checksum_update_ippseudohdr(&sum, pseudoHdr);
        inet_checksum_update(&sum, data, pseudoHdr->length);
        tcpCheckCalc = inet_checksum_final(&sum);
    }

    printf(SGR_TCP);

    printf("TCP\n");
    printf("  src port  %i\n", (int)srcPort);
    printf("  dst port  %i\n", (int)dstPort);
    printf("  sequence  %u\n", tcpSeq);
    printf("  data off  %i\n", (int)tcpDataOff);
    printf("  flags     0x%02x\n", (int)tcpFlags);
    printf("  check     %s0x%04x" SGR_TCP "\n", ((tcpCheckCalc == 0) || (!pseudoHdr) ? "" : SGR_RED), (int)tcpCheck);
    printf("  hdr size  %zu\n", tcpHeaderSize);
    printf("  data size %zu + %zu pad\n", tcpDataSize, padDataSize);

    hexDump((const uint8_t*)tcpHeader, tcpHeaderSize);

    printf(SGR_DEFAULT);
    fflush(stdout);
}

void printTcpPacket(const uint8_t* data, size_t size, const struct ippseudohdr* pseudoHdr)
{
    printTcpHeader(data, size, pseudoHdr);
    printf("\n");

    const struct tcphdr* const tcpHeader = (const struct tcphdr*)(data);
    const uint8_t tcpDataOff = tcpHeader->th_off;
    const size_t tcpHeaderSize = tcpDataOff * 4u;
    const uint8_t* const tcpData = data + tcpHeaderSize;
    const size_t tcpDataSize = size - tcpHeaderSize;
    const uint8_t* const padData = data + tcpHeaderSize + tcpDataSize; // potential padding
    const size_t padDataSize = size - tcpHeaderSize - tcpDataSize;     // potential padding

    printf(SGR_TCP);

    hexDump(tcpData, tcpDataSize);

    printf(SGR_DEFAULT);
    fflush(stdout);

    printPacket_padding(padData, padDataSize);
}

void printUdpHeader(const uint8_t* data, size_t size, const struct ippseudohdr* pseudoHdr)
{
    const struct udphdr* const udpHeader = (const struct udphdr*)(data);
    const size_t udpHeaderSize = 8;
    const uint16_t srcPort = ntohs(udpHeader->uh_sport);
    const uint16_t dstPort = ntohs(udpHeader->uh_dport);
    const uint16_t udpLength = ntohs(udpHeader->uh_ulen);
    const uint16_t udpCheck = ntohs(udpHeader->uh_sum);
    __attribute__((unused)) const uint8_t* const udpData = data + udpHeaderSize;
    __attribute__((unused)) const size_t udpDataSize = udpLength - udpHeaderSize;
    __attribute__((unused)) const uint8_t* const padData = data + udpHeaderSize + udpDataSize; // potential padding
    __attribute__((unused)) const size_t padDataSize = size - udpHeaderSize - udpDataSize;     // potential padding

    uint16_t udpCheckCalc;
    if (pseudoHdr)
    {
        uint32_t sum;
        inet_checksum_init(&sum);
        inet_checksum_update_ippseudohdr(&sum, pseudoHdr);
        inet_checksum_update(&sum, data, pseudoHdr->length);
        udpCheckCalc = inet_checksum_final(&sum);
    }

    printf(SGR_UDP);

    printf("UDP\n");
    printf("  src port  %i\n", (int)srcPort);
    printf("  dst port  %i\n", (int)dstPort);
    printf("  length    %i\n", (int)udpLength);
    printf("  check     %s0x%04x" SGR_UDP "\n", ((udpCheckCalc == 0) || (udpCheck == 0) || (!pseudoHdr) ? "" : SGR_RED), (int)udpCheck);
    printf("  hdr size  %zu\n", udpHeaderSize);
    printf("  data size %zu + %zu pad\n", udpDataSize, padDataSize);

    hexDump((const uint8_t*)udpHeader, udpHeaderSize);

    printf(SGR_DEFAULT);
    fflush(stdout);
}

void printUdpPacket(const uint8_t* data, size_t size, const struct ippseudohdr* pseudoHdr)
{
    printUdpHeader(data, size, pseudoHdr);
    printf("\n");

    const struct udphdr* const udpHeader = (const struct udphdr*)(data);
    const size_t udpHeaderSize = 8;
    const uint16_t udpLength = ntohs(udpHeader->uh_ulen);
    const uint8_t* const udpData = data + udpHeaderSize;
    const size_t udpDataSize = udpLength - udpHeaderSize;
    const uint8_t* const padData = data + udpHeaderSize + udpDataSize; // potential padding
    const size_t padDataSize = size - udpHeaderSize - udpDataSize;     // potential padding

    printf(SGR_UDP);

    hexDump(udpData, udpDataSize);

    printf(SGR_DEFAULT);
    fflush(stdout);

    printPacket_padding(padData, padDataSize);
}

#endif // _WIN32



/**
 * @brief Converts the data buffer bytes to printable characters.
 *
 * Writes 16 characters and a terminating null to `buffer`.
 *
 * @param buffer Destination string buffer
 * @param p First element to parse, points into the source data buffer
 * @param end First element after the source data buffer
 */
static void hexDump_dataToString(char* buffer, const uint8_t* p, const uint8_t* end)
{
    size_t i = 0;

    while ((i < 16) && (p < end))
    {
        const char c = (char)(*p);

        if (isprint(c)) { buffer[i] = c; }
        else { buffer[i] = '.'; }

        ++p;
        ++i;
    }

    while (i < 16)
    {
        buffer[i] = ' ';
        ++i;
    }

    buffer[i] = 0;
}

void hexDump(const uint8_t* data, size_t count)
{
    if (!data) { count = 0; }

    const uint8_t* const end = (data + count);

    for (size_t i = 0; i < count; ++i)
    {
        const int byte = *(data + i);
        const size_t row = (i / 16);
        const size_t col = (i % 16);

        if (col == 0)
        {
            if (i == 0) { printf("%05zx ", i); }
            else
            {
                char str[17];
                hexDump_dataToString(str, data + 16 * (row - 1), end);
                printf("  | %s\n%05zx ", str, i);
            }
        }
        else if (col == 8) { printf(" "); }

        printf(" %02x", byte);
    }

    if (count == 0) { printf("%05x ", 0); }



    size_t lastRowSize = (count % 16);
    if ((lastRowSize == 0) && (count != 0)) { lastRowSize = 16; }
    const size_t remaining = (16 - lastRowSize);

    if (remaining >= 8) { printf(" "); }
    for (size_t i = 0; i < remaining; ++i) { printf("   "); }

    char str[17];
    hexDump_dataToString(str, end - lastRowSize, end);
    printf("  | %s", str);

    printf("\n");
}



#ifndef _WIN32

void SOCKETHELPER_test_unit_system()
{
    char __attribute__((unused)) buffer[100];

    const uint8_t __attribute__((unused)) ETH_ARP_request[] = {
        0xdc, 0x2c, 0x6e, 0x11, 0x22, 0x33, 0x34, 0x97, 0xf6, 0xdd, 0xee, 0xff, 0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00,
        0x01, 0x34, 0x97, 0xf6, 0xdd, 0xee, 0xff, 0xc0, 0xa8, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
    };

    const uint8_t __attribute__((unused)) ETH_ICMP_echo_request[] = {
        0xdc, 0x2c, 0x6e, 0x11, 0x22, 0x33, 0x34, 0x97, 0xf6, 0xdd, 0xee, 0xff, 0x08, 0x00, 0x45, 0x00, 0x00, 0x54, 0xf9, 0x8f, 0x40, 0x00, 0x40, 0x01, 0xa7,
        0x3e, 0xc0, 0xa8, 0x01, 0x08, 0xbc, 0x28, 0x1c, 0x02, 0x08, 0x00, 0xa8, 0x3d, 0x35, 0x2a, 0x00, 0x03, 0xcb, 0xad, 0xfb, 0x67, 0x00, 0x00, 0x00, 0x00,
        0x8f, 0xac, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    };

    const uint8_t __attribute__((unused)) ETH_ICMP_echo_reply[] = {
        0x34, 0x97, 0xf6, 0xdd, 0xee, 0xff, 0xdc, 0x2c, 0x6e, 0x11, 0x22, 0x33, 0x08, 0x00, 0x45, 0x00, 0x00, 0x54, 0xe8, 0x8f, 0x00, 0x00, 0x31, 0x01, 0x07,
        0x3f, 0xbc, 0x28, 0x1c, 0x02, 0xc0, 0xa8, 0x01, 0x08, 0x00, 0x00, 0xb0, 0x3d, 0x35, 0x2a, 0x00, 0x03, 0xcb, 0xad, 0xfb, 0x67, 0x00, 0x00, 0x00, 0x00,
        0x8f, 0xac, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    };

    const uint8_t __attribute__((unused)) TCP_csTest[] = {
        0x11, 0x5c, 0xdc, 0xba, 0x28, 0xd5, 0x41, 0xda, 0x64, 0xe8, 0x6a, 0x10, 0x80, 0x18, 0x01, 0xfe, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x01, 0x08, 0x0a, 0x5c, 0x86, 0xc6, 0xf8, 0xbd, 0x62, 0xe3, 0x6f, 0x6c, 0x69, 0x64, 0x6f, 0x72, 0x0a,
    };

#if 1
    printf("\n" SGR_BWHITE "%s" SGR_DEFAULT "\n", "inet_checksum");

    {
        const uint8_t ipPseudoHeader[] = { 0xc0, 0xa8, 0xae, 0x80, 0xc0, 0xa8, 0xae, 0x01, 0x00, 0x06, 0x00, 0x26 };
        const uint16_t crcExpected = 0x67ea;
        uint32_t sum;

        inet_checksum_init(&sum);
        inet_checksum_update(&sum, ipPseudoHeader, sizeof(ipPseudoHeader));
        inet_checksum_update(&sum, TCP_csTest, sizeof(TCP_csTest));
        const uint16_t crcCalc_buffer = inet_checksum_final(&sum);

        inet_checksum_init(&sum);
        inet_checksum_update32h(&sum, 0xc0a8ae80);
        inet_checksum_update32h(&sum, 0xc0a8ae01);
        inet_checksum_update16h(&sum, IPPROTO_TCP);
        inet_checksum_update16h(&sum, sizeof(TCP_csTest));
        inet_checksum_update(&sum, TCP_csTest, sizeof(TCP_csTest));
        const uint16_t crcCalc_val = inet_checksum_final(&sum);

        struct ippseudohdr ippseudohdr;
        struct iphdr iphdr;
        inet_pton(AF_INET, "192.168.174.128", &(iphdr.saddr));
        inet_pton(AF_INET, "192.168.174.1", &(iphdr.daddr));
        iphdr.ihl = 5;
        iphdr.tot_len = (uint16_t)(iphdr.ihl) * 4 + sizeof(TCP_csTest);
        iphdr.protocol = IPPROTO_TCP;

        inet_checksum_init(&sum);
        inet_checksum_update_ippseudohdr(&sum, ippseudohdr_init(&ippseudohdr, &iphdr));
        inet_checksum_update(&sum, TCP_csTest, sizeof(TCP_csTest));
        const uint16_t crcCalc_psh = inet_checksum_final(&sum);

        if ((crcCalc_buffer != crcExpected) || (crcCalc_val != crcExpected) || (crcCalc_psh != crcExpected))
        {
            printf("b 0x%04x, v 0x%04x, p 0x%04x, e 0x%04x", crcCalc_buffer, crcCalc_val, crcCalc_psh, crcExpected);
        }
        else { printf("OK\n"); }
    }
#endif

#if 1
    printf("\n" SGR_BWHITE "%s" SGR_DEFAULT "\n", "mactos");

    const uint8_t mac[6] = { 0xb8, 0x27, 0xeb, 0x00, 0x0a, 0x12 };
    printf("MAC address: %s\n", mactos(mac, buffer, sizeof(buffer)));
#endif

#if 1
    printf("\n" SGR_BWHITE "%s" SGR_DEFAULT "\n", "ethptos");
    printf("ETH proto: %s\n", ethptos(ETH_P_LOOP, buffer, sizeof(buffer)));
    printf("ETH proto: %s\n", ethptos(ETH_P_IP, buffer, sizeof(buffer)));
    printf("ETH proto: %s\n", ethptos(ETH_P_X25, buffer, sizeof(buffer)));
    printf("ETH proto: %s\n", ethptos(ETH_P_IPV6, buffer, sizeof(buffer)));
    printf("ETH proto: %s\n", ethptos(1234, buffer, sizeof(buffer)));
#endif

#if 1
    printf("\n" SGR_BWHITE "%s" SGR_DEFAULT "\n", "sockaddrtos");

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(struct sockaddr_in));

    sa.sin_family = AF_PACKET;
    printf("sockaddr: %s\n", sockaddrtos(&sa, buffer, sizeof(buffer)));

    sa.sin_family = AF_AX25;
    printf("sockaddr: %s\n", sockaddrtos(&sa, buffer, sizeof(buffer)));

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(0x0a000125); // 10.0.1.37
    printf("sockaddr: %s\n", sockaddrtos(&sa, buffer, sizeof(buffer)));

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(0xc0a8012d); // 192.168.1.45
    sa.sin_port = 3030;
    printf("sockaddr: %s\n", sockaddrtos(&sa, buffer, sizeof(buffer)));

    sa.sin_family = AF_INET6;
    printf("sockaddr: %s (sockaddr_in with AF_INET6)\n", sockaddrtos(&sa, buffer, sizeof(buffer)));

    memset(&sa, 0xFF, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET6;
    printf("sockaddr: %s (sockaddr_in with AF_INET6)\n", sockaddrtos(&sa, buffer, sizeof(buffer)));

    printf("sockaddr: no AF_INET6 test cases yet\n");
#endif

#if 0
    printf("\n" SGR_BWHITE "%s" SGR_DEFAULT "\n", "print frames and headers");

    printf("\n" SGR_BLUE "  --=====| " SGR_BBLUE " %s " SGR_BLUE " |=====--" SGR_DEFAULT "\n", "ARP request");
    printEthPacket(ETH_ARP_request, sizeof(ETH_ARP_request));

    printf("\n" SGR_BLUE "  --=====| " SGR_BBLUE " %s " SGR_BLUE " |=====--" SGR_DEFAULT "\n", "ICMP echo request");
    printEthPacket(ETH_ICMP_echo_request, sizeof(ETH_ICMP_echo_request));

    printf("\n" SGR_BLUE "  --=====| " SGR_BBLUE " %s " SGR_BLUE " |=====--" SGR_DEFAULT "\n", "ICMP echo reply");
    printEthPacket(ETH_ICMP_echo_reply, sizeof(ETH_ICMP_echo_reply));

#endif

#if 0
    printf("\n" SGR_BWHITE "%s" SGR_DEFAULT "\n", "hexDump");

    const uint8_t* const loremIpsum = (uint8_t*)("Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam "
                                                 "nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat"
                                                 ", sed diam voluptua. At vero eos et accusam et justo duo dolores et "
                                                 "ea rebum.");

    hexDump(loremIpsum, strlen((char*)loremIpsum));
    printf("\n");
    hexDump(NULL, 20);
    printf("\n");
    hexDump(loremIpsum, 0);
    printf("\n");
    hexDump(loremIpsum, 3);
    printf("\n");
    hexDump(loremIpsum, 13);
    printf("\n");
    hexDump(loremIpsum, 16);
    printf("\n");
    hexDump(loremIpsum, 19);
    printf("\n");
    hexDump(loremIpsum, 29);
    printf("\n");
    hexDump(loremIpsum, 32);
#endif
}

#endif // _WIN32



#ifndef _WIN32

_Static_assert(ARPDATA_HLEN == ETH_ALEN, "invalid ARPDATA_HLEN value");
_Static_assert(ARPDATA_PLEN == sizeof(struct in_addr), "invalid ARPDATA_PLEN value");

#endif // _WIN32
