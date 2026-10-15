/* Native Windows UTF-8 path boundary for Zip. MIT-0.
 * Enabled only in the opt-in XTR_WIN_NATIVE MinGW console Zip.
 * Strict conversion: a nonrepresentable path must never fall back to ACP.
 */
#include "../zip.h"
#if defined(XTR_WIN_NATIVE) && defined(WIN32) && defined(__MINGW32__) && !defined(UTIL) && !defined(WINDLL)
#include <windows.h>
#include <shellapi.h>
#include <wchar.h>
#include <errno.h>
#include <limits.h>

static int xtr_zip_utf8_active = 0;
int xtr_zip_u8_active(void) { return xtr_zip_utf8_active; }

static wchar_t *xtr_zip_to_wide(const char *s)
{
    int n;
    wchar_t *w;
    if (!s || !*s) { errno = EINVAL; return NULL; }
    if (strlen(s) > INT_MAX - 1) { errno = ENAMETOOLONG; return NULL; }
    n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, NULL, 0);
    if (n <= 0 || (size_t)n > (size_t)-1 / sizeof(wchar_t)) {
        errno = EINVAL; return NULL;
    }
    w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!w) { errno = ENOMEM; return NULL; }
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, w, n) != n) {
        free(w); errno = EINVAL; return NULL;
    }
    return w;
}

static char *xtr_zip_from_wide(const wchar_t *w)
{
    int n;
    char *s;
    n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w, -1,
                            NULL, 0, NULL, NULL);
    if (n <= 0) { errno = EINVAL; return NULL; }
    s = (char *)malloc((size_t)n);
    if (!s) { errno = ENOMEM; return NULL; }
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w, -1,
                            s, n, NULL, NULL) != n) {
        free(s); errno = EINVAL; return NULL;
    }
    return s;
}

/* The MinGW CRT's char **argv is encoded in the active code page and may
 * already have substituted '?' for a Unicode archive pathname. Obtain the
 * original command line before Zip's option parser copies/permutates argv.
 */
int xtr_zip_u8_argv(int *argc, char ***argv)
{
    LPWSTR *wide;
    char **v;
    int i, n;
    if (!argc || !argv) { errno = EINVAL; return -1; }
    wide = CommandLineToArgvW(GetCommandLineW(), &n);
    if (!wide || n <= 0 || (size_t)n > ((size_t)-1 / sizeof(char *)) - 1U) {
        if (wide) LocalFree(wide);
        errno = EINVAL; return -1;
    }
    /* Do not disturb the historical ACP source/path processing when every
     * argument can be represented without substitution. In particular,
     * legacy non-ASCII filenames that already worked must keep working. */
    {
        int need_utf8 = 0;
        for (i = 0; i < n; ++i) {
            BOOL replaced = FALSE;
            int bytes = WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS,
                             wide[i], -1, NULL, 0, NULL, &replaced);
            if (bytes <= 0 || replaced) { need_utf8 = 1; break; }
        }
        if (!need_utf8) {
            LocalFree(wide);
            return 0;
        }
    }
    v = (char **)calloc((size_t)n + 1U, sizeof(char *));
    if (!v) { LocalFree(wide); errno = ENOMEM; return -1; }
    for (i = 0; i < n; ++i) {
        v[i] = xtr_zip_from_wide(wide[i]);
        if (!v[i]) {
            int j;
            for (j = 0; j < i; ++j) free(v[j]);
            free(v); LocalFree(wide); return -1;
        }
    }
    LocalFree(wide);
    *argc = n;
    *argv = v;  /* kept until process exit; option parser owns copies */
    xtr_zip_utf8_active = 1;
    return 0;
}

FILE *xtr_zip_u8_fopen(const char *path, const char *mode)
{
    wchar_t *w, wm[16];
    FILE *fp;
    size_t i, m;
    if (!mode) { errno = EINVAL; return NULL; }
    if (!xtr_zip_utf8_active) return fopen(path, mode);
    m = strlen(mode);
    if (!m || m >= sizeof(wm) / sizeof(wm[0])) {
        errno = EINVAL; return NULL;
    }
    for (i = 0; i <= m; ++i) wm[i] = (wchar_t)(unsigned char)mode[i];
    w = xtr_zip_to_wide(path);
    if (!w) return NULL;
    fp = _wfopen(w, wm);
    free(w);
    return fp;
}

int xtr_zip_u8_stat(const char *path, z_stat *st)
{
    wchar_t *w;
    int rc;
    if (!xtr_zip_utf8_active) return zstat_zipwin32(path, st);
    w = xtr_zip_to_wide(path);
    if (!w) return -1;
    rc = _wstati64(w, st);
    free(w);
    return rc;
}

int xtr_zip_u8_unlink(const char *path)
{
    wchar_t *w;
    int rc;
    if (!xtr_zip_utf8_active) return unlink(path);
    w = xtr_zip_to_wide(path);
    if (!w) return -1;
    rc = _wunlink(w);
    free(w);
    return rc;
}

int xtr_zip_u8_rename(const char *from, const char *to)
{
    wchar_t *wfrom;
    wchar_t *wto;
    int rc;
    if (!xtr_zip_utf8_active) return rename(from, to);
    wfrom = xtr_zip_to_wide(from);
    if (!wfrom) return -1;
    wto = xtr_zip_to_wide(to);
    if (!wto) { free(wfrom); return -1; }
    rc = _wrename(wfrom, wto);
    free(wfrom);
    free(wto);
    return rc;
}

/* GetTempFileNameW creates the file atomically in the selected directory.
 * The subsequent _wfopen(...,"wbS") truncates/reopens it for the writer.
 * This avoids passing a Unicode directory through narrow mktemp().
 */
char *xtr_zip_u8_tempname(const char *directory)
{
    wchar_t *dir = xtr_zip_to_wide(directory && *directory ? directory : ".");
    wchar_t name[MAX_PATH + 1];
    char *out;
    if (!dir) return NULL;
    if (!GetTempFileNameW(dir, L"zi", 0, name)) {
        free(dir); errno = EIO; return NULL;
    }
    free(dir);
    out = xtr_zip_from_wide(name);
    if (!out) DeleteFileW(name);
    return out;
}
#endif
