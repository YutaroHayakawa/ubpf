#ifndef _DBPF_COMMON_H_
#define _DBPF_COMMON_H_

#if defined(linux)

#elif defined(__FreeBSD__)

#include <sys/endian.h>

#else

#error Unsupported platform

#endif

#endif
