/* Strict test shim for the three native OS/2 information APIs only. */
#ifndef XTR_OS2_ENTROPY_SHIM_H
#define XTR_OS2_ENTROPY_SHIM_H
typedef unsigned int ULONG;
typedef unsigned int APIRET;
typedef struct _DATETIME {
    unsigned char hours, minutes, seconds, hundredths, day, month;
    unsigned short year;
    short timezone;
    unsigned char weekday;
} DATETIME;
typedef struct _TIB { unsigned long unused; } TIB, *PTIB;
typedef struct _PIB { unsigned long pib_ulpid; } PIB, *PPIB;
#define QSV_MS_COUNT 14
#define QSV_TOTAVAILMEM 19
APIRET DosGetDateTime(DATETIME *);
APIRET DosQuerySysInfo(ULONG,ULONG,void *,ULONG);
APIRET DosGetInfoBlocks(PTIB *,PPIB *);
#endif
