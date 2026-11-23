#ifndef SHIM_STDARG_H
#define SHIM_STDARG_H
/* grub 内核头在 freestanding 环境需要 va_list；用编译器内建 */
typedef __builtin_va_list va_list;
#define va_start(v, l) __builtin_va_start(v, l)
#define va_end(v) __builtin_va_end(v)
#define va_arg(v, t) __builtin_va_arg(v, t)
#define va_copy(d, s) __builtin_va_copy(d, s)
#endif
