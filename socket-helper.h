/*
author          Oliver Blaser
date            07.04.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#ifndef IG_MIDDLEWARE_SOCKETHELPER_H
#define IG_MIDDLEWARE_SOCKETHELPER_H

#include <stddef.h>
#include <stdint.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <sys/socket.h>


#ifdef __cplusplus
#define C_DECL_BEGIN extern "C" {
#define C_DECL_END   }
#else
#define C_DECL_BEGIN
#define C_DECL_END
#endif

C_DECL_BEGIN



/**
 * @brief Extended 802.1Q VLAN ethernet header
 */
struct ethhdr8021Q
{
    uint8_t ehq_dest[ETH_ALEN];
    uint8_t ehq_source[ETH_ALEN];
    uint16_t ehq_tpid;
    uint16_t ehq_tci;
    uint16_t ehq_proto;
} __attribute__((packed));



#define ARPDATA_HLEN (6) // hardware address length
#define ARPDATA_PLEN (4) // protocol address length

/**
 * @brief IPv4 ARP data container.
 *
 * - hardware address: MAC/EUI48
 * - protocol address: IPv4 address
 */
struct arpdata
{
    uint8_t ar_sha[ARPDATA_HLEN]; // sender hardware address
    uint8_t ar_spa[ARPDATA_PLEN]; // sender protocol address
    uint8_t ar_tha[ARPDATA_HLEN]; // target hardware address
    uint8_t ar_tpa[ARPDATA_PLEN]; // target protocol address
} __attribute__((packed));



struct ippseudohdr
{
    struct sockaddr_storage saddr;
    struct sockaddr_storage daddr;
    uint32_t length; // number of TCP/UDP packet octets = TCP/UDP header size + TCP/UDP payload size
                     //                                 = IP packet size - IP header size (=IHL*4)
    uint8_t protocol;
};

/**
 * @param [out] dst
 * @param iphdr
 * @return `dst`
 */
struct ippseudohdr* ippseudohdr_init(struct ippseudohdr* dst, const struct iphdr* iphdr);

/**
 * @param [out] dst
 * @param saddr `struct in6_addr*` or _tbd ..._
 * @param daddr `struct in6_addr*` or _tbd ..._
 * @param protocol Protocol type `IPPROTO_...`
 * @param length
 * @return On success `dst` is returned, `NULL` on error
 */
struct ippseudohdr* ippseudohdr_init6(struct ippseudohdr* dst, const void* saddr, const void* daddr, uint8_t protocol, uint32_t length);



uint16_t inet_checksum(const uint8_t* data, size_t count);

void inet_checksum_init(uint32_t* sum);
void inet_checksum_update(uint32_t* sum, const uint8_t* data, size_t count);
void inet_checksum_update16h(uint32_t* sum, uint16_t value);
void inet_checksum_update16n(uint32_t* sum, uint16_t value);
void inet_checksum_update32h(uint32_t* sum, uint32_t value);
void inet_checksum_update32n(uint32_t* sum, uint32_t value);
void inet_checksum_update_ippseudohdr(uint32_t* sum, const struct ippseudohdr* pseudoHdr);
uint16_t inet_checksum_final(uint32_t* sum);



#define MAC_ADDRSTRLEN 18
#define AF_STRLEN      14
#define ETH_P_STRLEN   17
#define IPPROTO_STRLEN 17
#define SOCKADDRSTRLEN 54

/**
 * @brief Converts a hardware (MAC) address to it's string representation.
 *
 * @param mac Pointer to a buffer holding the hardware address, must be at least `ETH_ALEN` bytes long
 * @param dst Pointer to a string buffer, wich must be at least `MAC_ADDRSTRLEN` bytes long
 * @param size Size of the buffer pointed to by `dst`
 * @return On success `dst` is returned, `NULL` on error
 */
char* mactos(const uint8_t* mac, char* dst, size_t size);

char* aftos(int af, char* dst, size_t size);
char* ethptos(uint16_t proto, char* dst, size_t size);
char* ipptos(uint16_t proto, char* dst, size_t size);
char* sockaddrtos(const void* sa, char* dst, size_t size);



void printEthHeader(const uint8_t* data, size_t size);
void printEthPacket(const uint8_t* data, size_t size);
void printIpHeader(const uint8_t* data, size_t size);
void printIpPacket(const uint8_t* data, size_t size);

/**
 * @param data
 * @param size
 * @param pseudoHdr _optional_
 */
void printTcpHeader(const uint8_t* data, size_t size, const struct ippseudohdr* pseudoHdr);

/**
 * @param data
 * @param size
 * @param pseudoHdr _optional_
 */
void printTcpPacket(const uint8_t* data, size_t size, const struct ippseudohdr* pseudoHdr);

/**
 * @param data
 * @param size
 * @param pseudoHdr _optional_
 */
void printUdpHeader(const uint8_t* data, size_t size, const struct ippseudohdr* pseudoHdr);

/**
 * @param data
 * @param size
 * @param pseudoHdr _optional_
 */
void printUdpPacket(const uint8_t* data, size_t size, const struct ippseudohdr* pseudoHdr);



void hexDump(const uint8_t* data, size_t count);



void SOCKETHELPER_test_unit_system();



C_DECL_END

#endif // IG_MIDDLEWARE_SOCKETHELPER_H
