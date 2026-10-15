/* Info-ZIP project source integration: conservative Xtro metadata safety.
 * The format-aware archive transforms will replace this temporary write gate.
 * All accesses are bounded by the central extra-field length.
 */
#ifndef XTRO_ZIP_TRANSFORM_GUARD_H
#define XTRO_ZIP_TRANSFORM_GUARD_H
static int xtro_transform_archive_has_metadata(void)
{
  struct zlist far *entry;
  for (entry = zfiles; entry != NULL; entry = entry->nxt) {
    const unsigned char *ef = (const unsigned char *)entry->cextra;
    unsigned len = entry->cext;
    unsigned at = 0;
    while (ef != NULL && at <= len && len - at >= 4U) {
      unsigned id = (unsigned)ef[at] | ((unsigned)ef[at+1U] << 8);
      unsigned size = (unsigned)ef[at+2U] | ((unsigned)ef[at+3U] << 8);
      if (size > len - at - 4U)
        break;
      if (id == 0x5854U && size >= 4U &&
          memcmp(ef + at + 4U, "XTRO", 4U) == 0)
        return 1;
      at += 4U + size;
    }
  }
  return 0;
}
#endif /* XTRO_ZIP_TRANSFORM_GUARD_H */
