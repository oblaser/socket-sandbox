/*
author          Oliver Blaser
date            05.06.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common.h"
#include "../socket-helper.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>



int main(int argc, char** argv)
{
    int err;

    if (argc < 2)
    {
        printError("missing address");
        return EC_ERROR;
    }

    const char* const hostaddrStr = argv[1];
    struct sockaddr_in hostaddr;
    memset(&hostaddr, 0, sizeof(hostaddr));
    hostaddr.sin_family = AF_INET;
    err = inet_pton(hostaddr.sin_family, hostaddrStr, &hostaddr.sin_addr);
    if (err != 1)
    {
        printError("invalid address");
        return EC_ERROR;
    }

    uint16_t port = 80;
    if (argc >= 3)
    {
        const int tmp = atoi(argv[2]);
        if ((tmp > 0) && (tmp <= INT16_MAX)) { port = (uint16_t)tmp; }
        else
        {
            printError("invalid port");
            return EC_ERROR;
        }
    }
    hostaddr.sin_port = htons(port);

    const char* http_host = NULL;
    if (argc >= 4) { http_host = argv[3]; }

    char http_path[1024] = "/";
    if (argc >= 5) { strcpy(http_path, argv[4]); }



    const int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0)
    {
        printErrno("socket() failed", errno);
        return EC_SOCK;
    }

    err = connect(sockfd, (struct sockaddr*)(&hostaddr), sizeof(hostaddr));
    if (err)
    {
        printErrno("connect() failed", errno);
        close(sockfd);
        return EC_CONNECT;
    }



    // the actual transfer
    {
        char reqBuffer[2 * 1024];
        char ansBuffer[1024 * 1024];
        ssize_t n, transferred;

        if (http_host) { sprintf(reqBuffer, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", http_path, http_host); }
        else { sprintf(reqBuffer, "GET %s HTTP/1.1\r\n\r\n", http_path); }
        const size_t reqSize = strlen(reqBuffer);



        transferred = 0;
        while ((size_t)transferred < reqSize)
        {
            n = write(sockfd, reqBuffer, reqSize);
            if (n < 0)
            {
                printErrno("write() failed", errno);
                close(sockfd);
                return EC_WRITE;
            }

            transferred += n;
        }



        transferred = 0;

        do {
            n = read(sockfd, ansBuffer + transferred, sizeof(ansBuffer) - transferred);
            if (n < 0)
            {
                printErrno("read() failed", errno);
                close(sockfd);
                return EC_READ;
            }

            if (n > 0)
            {
                printf(SGR_BBLACK "received chunk:\n");
                hexDump((uint8_t*)ansBuffer + transferred, (ssize_t)n);
                printf(SGR_DEFAULT);
            }
            else { printf(SGR_BBLACK "end of transfer" SGR_DEFAULT "\n"); }

            transferred += n;
        }
        while (n > 0);

        ansBuffer[transferred] = 0; // CAUTION this may write to memory outside of the buffer

        printf(SGR_BBLACK "received data:" SGR_DEFAULT "\n%s\n", ansBuffer);
    }



    err = close(sockfd);
    if (err) { printErrno("close(sockfd) failed", errno); }

    return 0;
}
