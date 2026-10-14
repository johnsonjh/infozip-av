/* Native Win32 temporary output and no-replace publication helpers.
 * SPDX-License-Identifier: MIT-0
 * Both utilities put the temporary file alongside its destination.
 */
#ifndef IZ_WIN32_PORT_H
#define IZ_WIN32_PORT_H
#if !defined(_WIN32)
#error Windows helpers must only be included for native Windows
#endif
#include <windows.h>
#include <fcntl.h>
#include <stdint.h>
#include <io.h>
#include <stdio.h>
#include <string.h>

/* Replace the six trailing X characters. CREATE_NEW prevents collisions,
 * including names held by another process. The CRT owns the HANDLE on
 * successful _open_osfhandle(). Call _close() on the returned descriptor. */
static int iz_win_mkstemp(char *name)
{
    size_t len = strlen(name);
    unsigned attempt, i;
    unsigned long seed;
    LARGE_INTEGER ticks;
    static const char digits[] = "0123456789abcdef";
    HANDLE h;
    int fd;
    if (len < 6 || strcmp(name + len - 6, "XXXXXX") != 0)
        return -1;
    QueryPerformanceCounter(&ticks);
    seed = (unsigned long)ticks.LowPart ^ GetCurrentProcessId() ^ GetTickCount();
    for (attempt = 0; attempt < 256; ++attempt) {
        unsigned long x = seed + (unsigned long)attempt * 2654435761UL;
        for (i = 0; i < 6; ++i) {
            name[len - 6 + i] = digits[x & 15U];
            x >>= 4;
        }
        h = CreateFileA(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                        NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            if (err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS)
                continue;
            return -1;
        }
        fd = _open_osfhandle((intptr_t)h, _O_BINARY | _O_RDWR);
        if (fd >= 0)
            return fd;
        CloseHandle(h);
        DeleteFileA(name);
        return -1;
    }
    return -1;
}

/* Atomic no-replace publication on NTFS: fails if destination exists.
 * Failure on filesystems without hard links is intentional, not a reason
 * to fall back to potentially destructive rename/copy operations. */
static int iz_win_publish_noreplace(const char *temp, const char *dest)
{
    return CreateHardLinkA(dest, temp, NULL) ? 0 : -1;
}
#endif
