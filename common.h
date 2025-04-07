/*
author          Oliver Blaser
date            07.04.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#ifndef IG_COMMON_H
#define IG_COMMON_H

#include <stddef.h>
#include <stdint.h>

#include <net/ethernet.h>


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



void printRawEthFrame(const uint8_t* data, size_t count);



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
 * @return On success `dst` is returned, `NULL` on error.
 */
char* mactos(const uint8_t* mac, char* dst, size_t size);

char* aftos(int af, char* dst, size_t size);
char* ethptos(uint16_t proto, char* dst, size_t size);
char* ipptos(uint16_t proto, char* dst, size_t size);
char* sockaddrtos(const void* sa, char* dst, size_t size);



void hexDump(const uint8_t* data, size_t count);



void COMMON_test_unit_system();



C_DECL_END

#endif // IG_COMMON_H
