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

#include "common.h"



static const int ewiWidth = 10;



void printError(const char* str) { printf(SGR_BRED "%-*s" SGR_DEFAULT "%s\n", ewiWidth, "error:", str); }

void printErrno(const char* str, int eno) { printf(SGR_BRED "%-*s" SGR_DEFAULT "%s, %i %s\n", ewiWidth, "error:", str, eno, strerror(eno)); }

void printWarning(const char* str) { printf(SGR_BYELLOW "%-*s" SGR_DEFAULT "%s\n", ewiWidth, "warning:", str); }



#ifdef _WIN32

#include <winsock2.h>

#include <Windows.h>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif // _MSC_VER

void printWSError(const char* str, int error)
{
    const static char msg[] = "";

    //const DWORD count = FormatMessageA();
    //if (count <= 0) { strcpy(msg, "[FormatMessage() failed]"); }

    printf(SGR_BRED "%-*s" SGR_DEFAULT "%s, %i %s\n", ewiWidth, "error:", str, error, msg);
}

#endif // _WIN32
