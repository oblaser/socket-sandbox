/*
author          Oliver Blaser
date            28.07.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#ifndef IG_UTIL_ENDIAN_H
#define IG_UTIL_ENDIAN_H

#ifndef _MSC_VER
#include <endian.h>
#endif


#ifdef __cplusplus
extern "C" {
#endif



//======================================================================================================================
// pre checks, warning

#ifndef _MSC_VER

#ifdef UTIL_BIG_ENDIAN
#warning "UTIL_BIG_ENDIAN is already defined"
#define ___UTIL_BIG_ENDIAN_was_defined (1)
#endif

#ifdef UTIL_LITTLE_ENDIAN
#warning "UTIL_LITTLE_ENDIAN is already defined"
#define ___UTIL_LITTLE_ENDIAN_was_defined (1)
#endif

#endif // _MSC_VER



//======================================================================================================================
// detect and define

#ifdef _MSC_VER

#if (defined(_M_PPC))
#define UTIL_BIG_ENDIAN (1)
#endif

#if (defined(_M_IX86) || defined(_M_X64) || defined(_M_AMD64) || defined(_M_ARM) || defined(_M_ARM64))
#define UTIL_LITTLE_ENDIAN (1)
#endif

#else //_MSC_VER

#if ((defined(__BYTE_ORDER) && (__BYTE_ORDER == __BIG_ENDIAN)) || (defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __BIG_ENDIAN__)) || defined(__ARMEB__) || \
     defined(__AARCH64EB__) || defined(__THUMBEB__) || defined(_MIPSEB) || defined(__MIPSEB) || defined(__MIPSEB__))
#define UTIL_BIG_ENDIAN (1)
#endif

#if ((defined(__BYTE_ORDER) && (__BYTE_ORDER == __LITTLE_ENDIAN)) || (defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __LITTLE_ENDIAN__)) || \
     defined(__ARMEL__) || defined(__AARCH64EL__) || defined(__THUMBEL__) || defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__))
#define UTIL_LITTLE_ENDIAN (1)
#endif

#endif //_MSC_VER



//======================================================================================================================
// post checks

#if ((UTIL_BIG_ENDIAN && ___UTIL_LITTLE_ENDIAN_was_defined) || (UTIL_LITTLE_ENDIAN && ___UTIL_BIG_ENDIAN_was_defined) || \
     (UTIL_BIG_ENDIAN && UTIL_LITTLE_ENDIAN))
#error "fatal error, please (if possible) investigate and open an issue"
#endif

#undef ___UTIL_BIG_ENDIAN_was_defined
#undef ___UTIL_LITTLE_ENDIAN_was_defined

#if (!UTIL_BIG_ENDIAN && !UTIL_LITTLE_ENDIAN)
#error "unknown endianness"
#endif



#ifdef __cplusplus
}
#endif

#endif // IG_UTIL_ENDIAN_H
