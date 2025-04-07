/*
author          Oliver Blaser
date            07.04.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "../common.h"

#include <arpa/inet.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <unistd.h>



int main(int argc, char** argv)
{
    // const sockfd = socket();


    COMMON_test_unit_system();



    return 0;
}
