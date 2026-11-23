#ifndef SHIM_STRING_H
#define SHIM_STRING_H
#include <grub/misc.h>
#define memcpy grub_memcpy
#define memset grub_memset
#define memcmp grub_memcmp
#define strlen grub_strlen
#endif
