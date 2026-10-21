#include <wavpack/wavpack.h>

int
main (void)
{
  WavpackContext *ctx = WavpackOpenFileInputEx64 (0, 0, 0, 0, 0, 0);

  if (ctx)
    {
      WavpackCloseFile (ctx);
    }

  return WavpackGetLibraryVersion () == 0;
}
