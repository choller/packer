#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "nyx.h"
#include "code_coverage.h"

typedef struct afl_module_info_t afl_module_info_t;

struct afl_module_info_t {
  // A unique id starting with 0
  uint32_t id;

  // Name and base address of the module
  char* name;
  uintptr_t base_address;

  // PC Guard start/stop
  uint32_t start;
  uint32_t stop;

  // PC Table begin/end
  uintptr_t* pcs_beg;
  uintptr_t* pcs_end;

  uint8_t mapped;

  afl_module_info_t* next;
};

// Maximum path length on Linux
#define PATH_MAX 4096

// Maximum length of an uint32_t as string
#define START_STOP_MAX 10

// Defined in the AFL++ runtime when building with CODE_COVERAGE
__attribute__((weak)) extern afl_module_info_t* __afl_module_info;

// This is the per-iteration trace buffer used by AFL for coverage
extern unsigned char* trace_buffer;

// External reference to the buffer holding all PCs (from pc-table)
extern unsigned char* pcmap_buffer;
extern size_t pcmap_buffer_size;

// External reference to the trace buffer with accumulated coverage
extern unsigned char* perm_trace_buffer;
extern size_t perm_trace_buffer_size;

static char* get_afl_modinfo_string() {
  if (!__afl_module_info) {
    return NULL;
  }

  uint32_t cnt = 0;
  afl_module_info_t* start = __afl_module_info;

  hprintf("start is %p\n", start);

  while (start) {
    ++cnt;
    start = start->next;
  }

  if (!cnt) return NULL;

  // Allocate per entry enough space for:
  //
  //   1. One path
  //   2. Two pcguard start/stop offsets
  //   3. Two spaces and a trailing newline
  //
  // This is a very conservative allocation so we can just YOLO the rest.
  size_t bufsize = (PATH_MAX + START_STOP_MAX * 2 + 2 + 1) * cnt + 1;
  char* buf = malloc(bufsize);
  char* cur = buf;

  if (!buf) return NULL;

  start = __afl_module_info;

  while (start) {
    size_t namelen = strlen(start->name);

    memcpy(cur, start->name, namelen);
    cur += namelen;
    *cur = ' ';
    cur += 1;
    cur += sprintf(cur, "%u %u", start->start, start->stop);
    *cur = '\n';
    cur += 1;

    start = start->next;
  }

  *cur = '\0';

  return buf;
}

static void upload_file_to_host(void* buffer, size_t len, char* filename) {
  kafl_dump_file_t file_obj = {0};

  file_obj.file_name_str_ptr = (uintptr_t)filename;
  file_obj.append = 0;
  file_obj.bytes = 0;
  kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uintptr_t)(&file_obj));

  file_obj.bytes = len;
  file_obj.data_ptr = (uintptr_t)buffer;
  kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uintptr_t)(&file_obj));
}

// Needs to be called before each RELEASE
void update_perm_trace_buffer() {
  for (size_t i = 0; i < perm_trace_buffer_size; ++i) {
    if (trace_buffer[i] > 0 && perm_trace_buffer[i] != 255) {
      perm_trace_buffer[i]++;
    }
  }
}

// Should be called once before taking the snapshot
void start_coverage(void) {
  if (!!getenv("NYX_COVERAGE")) {
    char* modinfo = get_afl_modinfo_string();
    if (modinfo) {
      upload_file_to_host(modinfo, strlen(modinfo), "modinfo.txt");
    }

    upload_file_to_host(pcmap_buffer, pcmap_buffer_size, "pcmap.dump");
  }
}

// Should be called every X iterations to regularly update coverage
void update_coverage_dump(void) {
  upload_file_to_host(perm_trace_buffer, perm_trace_buffer_size, "covmap.dump");
}
