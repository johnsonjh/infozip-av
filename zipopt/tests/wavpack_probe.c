/* Optional libwavpack encoder/decoder link probe (not a runtime test). */

#include <wavpack/wavpack.h>

int
main (void)
{
  WavpackContext *ctx = WavpackOpenFileOutput (0, 0, 0);

  if (ctx)
    {
      WavpackCloseFile (ctx);
    }

  return 0;
}
