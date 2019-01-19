/* License */

#ifndef BCC_BTF_H
#define BCC_BTF_H

#include <stdbool.h>
#include <stdint.h>
#include <string>
#include <map>
#include <vector>

struct btf;
struct btf_ext;

namespace ebpf {

class StringTable {
 private:
  uint32_t Size;
  std::map<uint32_t, uint32_t> OffsetToIdMap;
  std::vector<std::string> Table;

 public:
  StringTable(): Size(0) {}
  uint32_t getSize() { return Size; }
  std::vector<std::string> &getTable() { return Table; }
  uint32_t addString(std::string Str);
};

class BTF {
 public:
  BTF(uint8_t *btf_sec, uintptr_t btf_sec_size,
      uint8_t *btf_ext_sec, uintptr_t btf_ext_sec_size,
      std::map<std::string, std::string> remapped_sources);
  void adjust();
  int load();
  int get_btf_info(const char *fname, int *btf_fd,
                   void **func_info, unsigned *func_info_cnt,
                   unsigned *finfo_rec_size,
                   void **line_info, unsigned *line_info_cnt,
                   unsigned *linfo_rec_size);
  int get_map_tids(std::string map_name,
		   unsigned expected_ksize, unsigned expected_vsize,
		   unsigned *key_tid, unsigned *value_tid);
  unsigned get_fd();

 private:
  uint8_t *btf_sec_;
  uintptr_t btf_sec_size_;
  uint8_t *btf_ext_sec_;
  uintptr_t btf_ext_sec_size_;
  std::map<std::string, std::string> remapped_src_;
  struct btf *btf_;
  struct btf_ext *btf_ext_;
};

} // namespace ebpf

#endif
