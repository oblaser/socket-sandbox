/*
author          Oliver Blaser
date            07.04.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#ifndef IG_COMMON_H
#define IG_COMMON_H

#include <stddef.h>
#include <stdint.h>



#define SGR_BLACK           "\033[30m"
#define SGR_RED             "\033[31m"
#define SGR_GREEN           "\033[32m"
#define SGR_YELLOW          "\033[33m"
#define SGR_BLUE            "\033[34m"
#define SGR_MAGENTA         "\033[35m"
#define SGR_CYAN            "\033[36m"
#define SGR_WHITE           "\033[37m"
#define SGR_RGB(_r, _g, _b) "\033[38;2;" #_r ";" #_g ";" #_b "m"
#define SGR_DEFAULT         "\033[39m"
#define SGR_BBLACK          "\033[90m"
#define SGR_BRED            "\033[91m"
#define SGR_BGREEN          "\033[92m"
#define SGR_BYELLOW         "\033[93m"
#define SGR_BBLUE           "\033[94m"
#define SGR_BMAGENTA        "\033[95m"
#define SGR_BCYAN           "\033[96m"
#define SGR_BWHITE          "\033[97m"



enum EXITCODE // https://tldp.org/LDP/abs/html/exitcodes.html / on MSW are no preserved codes
{
    EC_OK = 0,
    EC_ERROR = 1,

    EC__begin_ = 79,

    EC_SOCK = EC__begin_,
    EC_CONNECT,
    EC_BIND,
    EC_LISTEN,
    EC_ACCEPT,
    EC_READ,
    EC_WRITE,

    EC__end_,

    EC__max_ = 113
};
_Static_assert(EC__end_ <= EC__max_, "too many error codes defined");



void printError(const char* str);
void printErrno(const char* str, int eno);
void printWarning(const char* str);

#ifdef _WIN32
void printWSError(const char* str, int error);
#endif












#endif // IG_COMMON_H
