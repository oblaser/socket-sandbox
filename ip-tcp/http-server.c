/*
author          Oliver Blaser
date            05.06.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <errno.h>
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

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#endif // _WIN32



int main(int argc, char** argv)
{
    int err;
    char xtosBuffer[100];

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

    const int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0)
    {
        printErrno("socket() failed", errno);
        cleanupWinsock();
        return EC_SOCK;
    }

    err = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(sockopt_optval_t){ 1 }, sizeof(int));
    if (err) { printErrno("setsockopt(SO_REUSEADDR) failed", errno); }

    struct sockaddr_in srvaddr;
    memset(&srvaddr, 0, sizeof(srvaddr));

    srvaddr.sin_family = AF_INET;
    srvaddr.sin_port = htons(8080);
    srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    err = bind(sockfd, (struct sockaddr*)(&srvaddr), sizeof(srvaddr));
    if (err)
    {
        printErrno("bind() failed", errno);
        close(sockfd);
        cleanupWinsock();
        return EC_BIND;
    }

    err = listen(sockfd, 3);
    if (err)
    {
        printErrno("listen() failed", errno);
        close(sockfd);
        cleanupWinsock();
        return EC_LISTEN;
    }



    while (1)
    {
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);
        char rcvBuffer[4 * 1024];
        char ansBuffer[1024];
        ssize_t n;

        printf(SGR_BBLACK "waiting for a connection on port %i" SGR_DEFAULT "\n", (int)ntohs(srvaddr.sin_port));

        const int connfd = accept(sockfd, (struct sockaddr*)(&addr), &addrlen);
        if (connfd < 0)
        {
#ifdef _WIN32
            printWSError("accept() failed", WSAGetLastError());
#else
            printErrno("accept() failed", errno);
#endif

            continue;
        }

        printf(SGR_BBLACK "connected to %s" SGR_DEFAULT "\n", sockaddrtos(&addr, xtosBuffer, sizeof(xtosBuffer)));



        n = recv(connfd, rcvBuffer, sizeof(rcvBuffer), 0);
        if (n < 0)
        {
            printErrno("read() failed", errno);
            err = close(connfd);
            if (err) { printErrno("close(connfd) failed", errno); }
            continue;
        }

        if (strncmp((rcvBuffer + n - 4), "\r\n\r\n", 4))
        {
            printWarning("invalid HTTP request");
            rcvBuffer[(n < sizeof(rcvBuffer) ? n : sizeof(rcvBuffer))] = 0;
        }
        else { rcvBuffer[n - 4] = 0; }

        printf(SGR_BBLACK "received data:" SGR_DEFAULT "\n%s\n", rcvBuffer);



        strcpy(ansBuffer, "HTTP/1.0 200 OK\r\n\r\n");
        strcat(ansBuffer, "<h3>Hello World!</h3>");
        strcat(ansBuffer, "Your IP address is ");
        strcat(ansBuffer, sockaddrtos(&addr, xtosBuffer, sizeof(xtosBuffer)));

        n = send(connfd, ansBuffer, strlen(ansBuffer), 0);
        if (n < 0) { printErrno("write() failed", errno); }
        else if (n != strlen(ansBuffer)) { printWarning("failed to write the whole answer"); }

#ifdef _WIN32
        err = closesocket(connfd);
        if (err) { printWSError("closesocket(connfd) failed", WSAGetLastError()); }
#else
        err = close(connfd);
        if (err) { printErrno("close(connfd) failed", errno); }
#endif
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
