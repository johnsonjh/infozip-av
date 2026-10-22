/* Only the free-memory fields used by DJGPP's 0x0500 API are mocked. */
#ifndef XTR_TEST_DPMI_H
#define XTR_TEST_DPMI_H
typedef struct {
  unsigned long largest_available_free_block_in_bytes;
  unsigned long total_number_of_free_pages;
} __dpmi_free_mem_info;
int __dpmi_get_free_memory_information (__dpmi_free_mem_info *);
int __dpmi_get_page_size (unsigned long *);
#endif
