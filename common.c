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



#define SWITCH_CASE_STRCPY_DEFINE(_dst, _define, _off)    \
    case _define:                                         \
        strcpy((_dst), (const char*)(#_define) + (_off)); \
        break



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
            SWITCH_CASE_STRCPY_DEFINE(dst, AF_LOCAL, 3);
#if (AF_UNIX != AF_LOCAL)
            SWITCH_CASE_STRCPY_DEFINE(dst, AF_UNIX, 3);
#endif
            SWITCH_CASE_STRCPY_DEFINE(dst, AF_INET, 3);
            SWITCH_CASE_STRCPY_DEFINE(dst, AF_AX25, 3);
            SWITCH_CASE_STRCPY_DEFINE(dst, AF_IPX, 3);
            SWITCH_CASE_STRCPY_DEFINE(dst, AF_X25, 3);
            SWITCH_CASE_STRCPY_DEFINE(dst, AF_INET6, 3);
            SWITCH_CASE_STRCPY_DEFINE(dst, AF_PACKET, 3);

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
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_CANXL, 6);
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
            SWITCH_CASE_STRCPY_DEFINE(dst, ETH_P_MCTP, 6);

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
            SWITCH_CASE_STRCPY_DEFINE(dst, IPPROTO_TCP, 8);
            SWITCH_CASE_STRCPY_DEFINE(dst, IPPROTO_UDP, 8);
            SWITCH_CASE_STRCPY_DEFINE(dst, IPPROTO_IPV6, 8);
            SWITCH_CASE_STRCPY_DEFINE(dst, IPPROTO_L2TP, 8);
            SWITCH_CASE_STRCPY_DEFINE(dst, IPPROTO_ETHERNET, 8);
            SWITCH_CASE_STRCPY_DEFINE(dst, IPPROTO_RAW, 8);

        default:
        {
            _Static_assert(IPPROTO_STRLEN >= 15, "increase IPPROTO_STRLEN");

            const size_t res = (size_t)snprintf(dst, size, "IPPROTO_#%04xh", (int)proto);
            if (res >= size) { r = NULL; }
        }
        break;
        }
    }

    return r;
}

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

void COMMON_test_unit_system()
{
    char buffer[100];

#if 1
    printf("\n\033[97m%s\033[39m\n", "mactos");

    const uint8_t mac[6] = { 0xb8, 0x27, 0xeb, 0x00, 0x0a, 0x12 };
    printf("MAC address: %s\n", mactos(mac, buffer, sizeof(buffer)));
#endif

#if 0
    printf("\n\033[97m%s\033[39m\n", "ethptos");
    printf("ETH proto: %s\n", ethptos(ETH_P_LOOP, buffer, sizeof(buffer)));
    printf("ETH proto: %s\n", ethptos(ETH_P_IP, buffer, sizeof(buffer)));
    printf("ETH proto: %s\n", ethptos(ETH_P_X25, buffer, sizeof(buffer)));
    printf("ETH proto: %s\n", ethptos(1234, buffer, sizeof(buffer)));
#endif

#if 1
    printf("\n\033[97m%s\033[39m\n", "sockaddrtos");

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
    printf("sockaddr: %s (kind of random)\n", sockaddrtos(&sa, buffer, sizeof(buffer)));

    memset(&sa, 0xFF, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET6;
    printf("sockaddr: %s (kind of random)\n", sockaddrtos(&sa, buffer, sizeof(buffer)));
#endif

#if 0
    printf("\n\033[97m%s\033[39m\n", "hexDump");

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



_Static_assert(ARPDATA_HLEN == ETH_ALEN, "invalid ARPDATA_HLEN value");
_Static_assert(ARPDATA_PLEN == sizeof(struct in_addr), "invalid ARPDATA_PLEN value");
