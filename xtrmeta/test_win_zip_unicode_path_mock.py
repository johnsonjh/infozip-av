#!/usr/bin/env python3
"""Compile/run isolated Win32-ABI contract checks for opt-in Zip UTF-8 paths.
No claims about real Windows CRT from this simulated ABI. MIT-0.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import sys

ROOT = Path(__file__).resolve().parent.parent
HEADER = r"""
#ifndef FAKE_WINDOWS_H
#define FAKE_WINDOWS_H
#include <wchar.h>
typedef wchar_t *LPWSTR;
#define CP_UTF8 65001U
#define CP_ACP 0U
typedef int BOOL;
#define FALSE 0
#define WC_NO_BEST_FIT_CHARS 0x400U
#define MB_ERR_INVALID_CHARS 8U
#define WC_ERR_INVALID_CHARS 0x80U
#define MAX_PATH 260
LPWSTR GetCommandLineW(void);
LPWSTR *CommandLineToArgvW(LPWSTR, int *);
void *LocalFree(void *);
int MultiByteToWideChar(unsigned, unsigned, const char *, int, wchar_t *, int);
int WideCharToMultiByte(unsigned, unsigned, const wchar_t *, int, char *, int,
                        const char *, int *);
unsigned GetTempFileNameW(const wchar_t *, const wchar_t *, unsigned, wchar_t *);
int DeleteFileW(const wchar_t *);
#endif
"""
FAKE = r"""
#ifndef FAKE_ZIP_H
#define FAKE_ZIP_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <errno.h>
#include <wchar.h>
#include <locale.h>
typedef struct stat z_stat;
int zstat_zipwin32(const char *, z_stat *);
int unlink(const char *);
FILE *_wfopen(const wchar_t *, const wchar_t *);
int _wstati64(const wchar_t *, z_stat *);
int _wunlink(const wchar_t *);
int _wrename(const wchar_t *, const wchar_t *);
#endif
"""
TEST = r"""
#include "fake_zip.h"
#include "windows.h"
#include "shellapi.h"
#include <unistd.h>
#include <assert.h>
static wchar_t arg_archive[] = { 0x61, 0x72, 0x63, 0x68, 0x69, 0x76, 0x65, 0x2d, 0x96ea, 0x2d, 0x1f9ea, 0x2e, 0x7a, 0x69, 0x70, 0 };
static wchar_t *legacy[] = { L"zip.exe", L"-q", L"legacy-\xe9.zip", L"owner.bin", NULL };
static int native_u8 = 0;
static wchar_t *args[] = { L"zip.exe", L"-q", arg_archive, L"owner.bin", NULL };
LPWSTR GetCommandLineW(void) { return L"zip.exe -q archive owner.bin"; }
LPWSTR *CommandLineToArgvW(LPWSTR s, int *n) { (void)s; *n=4; return native_u8 ? args : legacy; }
void *LocalFree(void *p) { (void)p; return NULL; }
int MultiByteToWideChar(unsigned cp,unsigned flags,const char *s,int len,wchar_t *o,int cap)
{
    size_t n;
    (void)flags;
    if (cp!=CP_UTF8 || len!=-1) return 0;
    n = mbstowcs(NULL,s,0);
    if (n==(size_t)-1 || n>INT_MAX-1) return 0;
    if (!o) return (int)n+1;
    if (cap<(int)n+1) return 0;
    if (mbstowcs(o,s,(size_t)cap)!=n) return 0;
    return (int)n+1;
}
int WideCharToMultiByte(unsigned cp,unsigned flags,const wchar_t *s,int len,char *o,int cap,const char *df,int *used)
{
    size_t n;
    (void)flags;(void)df;(void)used;
    if (len!=-1) return 0;
    if (cp==CP_ACP) {
        const wchar_t *p;
        for (p=s; *p; ++p) if (*p > 255) { if(used)*used=1; return 0; }
        if(used)*used=0;
        return (int)wcslen(s)+1;
    }
    if (cp!=CP_UTF8) return 0;
    n=wcstombs(NULL,s,0);
    if (n==(size_t)-1 || n>INT_MAX-1) return 0;
    if(!o) return (int)n+1;
    if (cap<(int)n+1) return 0;
    if(wcstombs(o,s,(size_t)cap)!=n) return 0;
    return (int)n+1;
}
static int narrow(const wchar_t *w,char *b,int cap)
{
    return WideCharToMultiByte(CP_UTF8,0,w,-1,b,cap,NULL,NULL)!=0;
}
FILE *_wfopen(const wchar_t *w,const wchar_t *m)
{
    char name[1024], mode[32];
    if(!narrow(w,name,sizeof(name)) || !narrow(m,mode,sizeof(mode))) return NULL;
    return fopen(name,mode);
}
int zstat_zipwin32(const char *p,z_stat *s) { return stat(p,s); }
int _wstati64(const wchar_t *w,z_stat *s)
{
    char name[1024]; if(!narrow(w,name,sizeof(name)))return -1;return stat(name,s);
}
int _wunlink(const wchar_t *w)
{
    char name[1024]; if(!narrow(w,name,sizeof(name)))return -1;return unlink(name);
}
int _wrename(const wchar_t *a,const wchar_t *b)
{
    char x[1024],y[1024];
    if(!narrow(a,x,sizeof(x))||!narrow(b,y,sizeof(y)))return -1;
    return rename(x,y);
}
unsigned GetTempFileNameW(const wchar_t *dir,const wchar_t *prefix,unsigned id,wchar_t *out)
{
    char path[1024];FILE *f; wchar_t *w;
    (void)prefix;(void)id;
    if(wcslen(dir)>160)return 0;
    wcscpy(out,dir); wcsncat(out,L"/zi123.tmp",260-wcslen(out)-1);
    if(!narrow(out,path,sizeof(path)))return 0;
    f=fopen(path,"wb");if(!f)return 0;fclose(f);
    w=out;return (unsigned)wcslen(w);
}
int DeleteFileW(const wchar_t *w) { return _wunlink(w)==0; }
#include "xtrzip_utf8.h"
int main(void)
{
    int argc=0;char **argv=NULL;
    const char *basename="archive-\xe9\x9b\xaa-\xf0\x9f\xa7\xaa.zip";
    FILE *f; char *temp; z_stat st; char *bad="bad-\xff.zip";
    assert(setlocale(LC_ALL,"C.UTF-8")!=NULL);
    { char *crt_argv[]={"zip.exe","-q","legacy-?zip","owner.bin",NULL};
      char **crt=crt_argv;
      argc=4;
      assert(xtr_zip_u8_argv(&argc,&crt)==0 && crt==crt_argv);
      assert(!xtr_zip_u8_active());
    }
    native_u8=1;
    assert(xtr_zip_u8_argv(&argc,&argv)==0 && xtr_zip_u8_active());
    assert(argc==4 && strstr(argv[2],"\xe9\x9b\xaa")!=NULL);
    assert(!strcmp(argv[2],basename));
    f=xtr_zip_u8_fopen(argv[2],"wb"); assert(f!=NULL);
    assert(fwrite("zip",1,3,f)==3);assert(fclose(f)==0);
    assert(xtr_zip_u8_stat(argv[2],&st)==0 && st.st_size==3);
    temp=xtr_zip_u8_tempname("."); assert(temp!=NULL);
    f=xtr_zip_u8_fopen(temp,"wb");assert(f!=NULL);
    assert(fwrite("updated",1,7,f)==7);assert(fclose(f)==0);
    assert(xtr_zip_u8_unlink(argv[2])==0);
    assert(xtr_zip_u8_rename(temp,argv[2])==0);
    assert(xtr_zip_u8_stat(argv[2],&st)==0 && st.st_size==7);
    assert(xtr_zip_u8_fopen(bad,"wb")==NULL);
    assert(xtr_zip_u8_unlink(argv[2])==0);
    free(temp);
    for(int i=0;i<argc;++i)free(argv[i]); free(argv);
    puts("PASS: native Zip UTF-8 argument/open/temp/replace boundary; 11 checks");
    return 0;
}
"""
# avoid C99 loop in C89 test
TEST = TEST.replace(
    "for(int i=0;i<argc;++i)free(argv[i]); free(argv);",
    "{ int i; for(i=0;i<argc;++i)free(argv[i]); free(argv); }",
)


def main():
    with tempfile.TemporaryDirectory(prefix="win-zip-u8-") as d:
        p = Path(d)
        (p / "windows.h").write_text(HEADER)
        (p / "shellapi.h").write_text('#include "windows.h"\n')
        (p / "fake_zip.h").write_text(FAKE)
        (p / "tester.c").write_text(TEST)
        csrc = (
            (ROOT / "zip30/win32/xtrzip_utf8.c")
            .read_text()
            .replace('#include "../zip.h"', '#include "fake_zip.h"')
        )
        (p / "xtrzip_utf8.c").write_text(csrc)
        (p / "xtrzip_utf8.h").write_text(
            (ROOT / "zip30/win32/xtrzip_utf8.h").read_text()
        )
        for compiler in ("gcc", "clang"):
            cmd = [
                compiler,
                "-std=c89",
                "-pedantic",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-DXTR_WIN_NATIVE",
                "-DWIN32",
                "-D__MINGW32__",
                "-I",
                str(p),
                str(p / "xtrzip_utf8.c"),
                str(p / "tester.c"),
                "-o",
                str(p / ("test-" + compiler)),
            ]
            if compiler == "clang" and os.environ.get("XTR_SANITIZE") == "1":
                cmd.extend(["-fsanitize=address,undefined", "-fno-omit-frame-pointer"])
            a = subprocess.run(cmd, text=True, capture_output=True)
            if a.returncode:
                raise RuntimeError("%s: %s" % (compiler, a.stderr))
            a = subprocess.run(
                [str(p / ("test-" + compiler))], cwd=p, text=True, capture_output=True
            )
            if a.returncode:
                raise RuntimeError("%s run: %s %s" % (compiler, a.stdout, a.stderr))
            print("%s: %s" % (compiler, a.stdout.strip()))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print("FAIL:", e, file=sys.stderr)
        sys.exit(1)
