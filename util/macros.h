/*
author          Oliver Blaser
date            28.07.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#ifndef IG_UTIL_MACROS_H
#define IG_UTIL_MACROS_H



#if defined(_MSC_VER)
#if (_MSVC_LANG >= 201703L)
#define ATTR_UNUSED [[maybe_unused]]
#else // Cpp std version
#define ATTR_UNUSED
#endif // Cpp std version
#else  // compiler
#define ATTR_UNUSED __attribute__((unused))
#endif // compiler



#endif // IG_UTIL_MACROS_H
