/* SPDX-License-Identifier: GPL-2.0-or-later */
/* kpm_lib.c - 本地 lib_* 函数实现
 *
 * KPM 框架的 baselib.c 定义了 lib_* 函数，但这些函数未通过
 * KP_EXPORT_SYMBOL 导出，KPM 模块无法链接。
 * 此处提供本地实现以解决 "unknown symbol" 加载错误。
 */

#include <ktypes.h>

void *lib_memset(void *dst, int c, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    while (n--)
        *d++ = (unsigned char)c;
    return dst;
}

void *lib_memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--)
        *d++ = *s++;
    return dst;
}

char *lib_strncpy(char *dst, const char *src, size_t n)
{
    size_t i;
    for (i = 0; i < n && src[i] != '\0'; i++)
        dst[i] = src[i];
    for (; i < n; i++)
        dst[i] = '\0';
    return dst;
}

size_t lib_strlen(const char *s)
{
    size_t n = 0;
    while (s && s[n] != '\0')
        n++;
    return n;
}

/* lib_strcmp / lib_strncmp：实现与 KernelPatch baselib.c 保持一致，
 * 避免行为差异。 */
int lib_strcmp(const char *s1, const char *s2)
{
    const unsigned char *c1 = (const unsigned char *)s1;
    const unsigned char *c2 = (const unsigned char *)s2;
    unsigned char ch;
    int d = 0;
    while (1) {
        d = (int)(ch = *c1++) - (int)*c2++;
        if (d || !ch)
            break;
    }
    return d;
}

int lib_strncmp(const char *s1, const char *s2, size_t n)
{
    const unsigned char *c1 = (const unsigned char *)s1;
    const unsigned char *c2 = (const unsigned char *)s2;
    unsigned char ch;
    int d = 0;
    while (n--) {
        d = (int)(ch = *c1++) - (int)*c2++;
        if (d || !ch)
            break;
    }
    return d;
}