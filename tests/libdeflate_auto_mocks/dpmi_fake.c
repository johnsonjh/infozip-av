#include "dpmi.h"
#include <stdlib.h>

int
__dpmi_get_free_memory_information (__dpmi_free_mem_info *info)
{
  info->total_number_of_free_pages = getenv ("XLD_TEST_FAIL") != 0
                                     ? 0xffffffffUL : 1000UL;
  info->largest_available_free_block_in_bytes = 3000000UL;
  return 0;
}

int
__dpmi_get_page_size (unsigned long *size)
{
  *size = 4096UL;
  return 0;
}
