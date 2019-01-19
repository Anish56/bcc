#include "btf.h"
#include <string.h>
#include <linux/btf.h>
#include "libbpf.h"
#include "libbpf/src/btf.h"
#include <vector>

namespace ebpf {

uint32_t StringTable::addString(std::string S) {
  // Check whether the string already exists.
  for (auto &OffsetM : OffsetToIdMap) {
    if (Table[OffsetM.second] == S)
      return OffsetM.first;
  }
  // Not find, add to the string table.
  uint32_t Offset = Size;
  OffsetToIdMap[Offset] = Table.size();
  Table.push_back(S);
  Size += S.size() + 1;
  return Offset;
}

BTF::BTF(uint8_t *btf_sec, uintptr_t btf_sec_size,
         uint8_t *btf_ext_sec, uintptr_t btf_ext_sec_size,
         std::map<std::string, std::string> remapped_sources) {
  uint8_t *tmp_p = new uint8_t[btf_sec_size];
  memcpy(tmp_p, btf_sec, btf_sec_size);
  btf_sec_ = tmp_p;
  btf_sec_size_ = btf_sec_size;

  tmp_p = new uint8_t[btf_ext_sec_size];
  memcpy(tmp_p, btf_ext_sec, btf_ext_sec_size);
  btf_ext_sec_ = tmp_p;
  btf_ext_sec_size_ = btf_ext_sec_size;

  remapped_src_ = remapped_sources;
}

void BTF::adjust() {
  struct btf_ext_header *ehdr = (struct btf_ext_header *)btf_ext_sec_;
  struct btf_header *hdr = (struct btf_header *)btf_sec_;
  unsigned lrec_size, linfo_len, strings_len;
  char *strings;
  unsigned *linfo_s;

  // Line cache for the module file
  std::map<std::string, std::vector<std::string>> LineCaches;
  for (auto it = remapped_src_.begin(); it != remapped_src_.end(); ++it) {
    size_t FileBufSize = it->second.size();
    std::vector<std::string> LineCache;
    LineCache.push_back(std::string());
    for (uint32_t start = 0, end = start; end < FileBufSize; end++) {
      if (it->second[end] == '\n' || end == FileBufSize - 1 ||
          (it->second[end] == '\r' && it->second[end + 1] == '\n')) {
        // Not including the endline
        LineCache.push_back(std::string(it->second.substr(start, end - start)));
        if (it->second[end] == '\r')
          end++;
        start = end + 1;
      }
    }
    LineCaches[it->first] = LineCache;
  }

  strings = (char *)(btf_sec_ + hdr->hdr_len + hdr->str_off);
  strings_len = hdr->str_len;
  linfo_s = (unsigned *)(btf_ext_sec_ + ehdr->hdr_len + ehdr->line_info_off);
  lrec_size = *linfo_s;
  linfo_s++;
  linfo_len = ehdr->line_info_len - 4;

  StringTable new_strings;
  while (linfo_len) {
    unsigned num_recs = linfo_s[1];
   linfo_s += 2;
    for (int i = 0; i < num_recs; i++) {
      struct bpf_line_info *linfo = (struct bpf_line_info *)linfo_s;
      if (linfo->line_off == 0) {
        for (auto it = LineCaches.begin(); it != LineCaches.end(); ++it) {
          if (strcmp(strings + linfo->file_name_off, it->first.c_str()) == 0) {
            unsigned line_num = BPF_LINE_INFO_LINE_NUM(linfo->line_col);
            if (line_num < it->second.size())
               linfo->line_off = strings_len + new_strings.addString(it->second[line_num]);
          }
        }
      }
      linfo_s += lrec_size >> 2;
    }
    linfo_len -= 8 + num_recs * lrec_size;
  }

  if (new_strings.getSize() > 0) {
    uint8_t *tmp_p = new uint8_t[btf_sec_size_ + new_strings.getSize()];
    memcpy(tmp_p, btf_sec_, btf_sec_size_);

    struct btf_header *nhdr = (struct btf_header *)tmp_p;
    nhdr->str_len += new_strings.getSize();

    uint8_t *new_str = tmp_p + nhdr->hdr_len + nhdr->str_off + strings_len;
    std::vector<std::string> &Table = new_strings.getTable();
    for (int i = 0; i < Table.size(); i++) {
      strcpy((char *)new_str, Table[i].c_str());
      new_str += Table[i].size() + 1;
    }

    btf_sec_ = tmp_p;
    btf_sec_size_ = btf_sec_size_ + new_strings.getSize();
  }
}

unsigned BTF::get_fd() {
  return btf__fd(btf_);
}

int BTF::load() {
  struct btf *btf;
  struct btf_ext *btf_ext;

  btf = btf__new(btf_sec_, btf_sec_size_);
  btf_ext = btf_ext__new(btf_ext_sec_, btf_ext_sec_size_);
  int ret = !!btf && !!btf_ext;
  if (!ret)
    return -1;
  btf_ = btf;
  btf_ext_ = btf_ext;
  return 0;
}

int BTF::get_btf_info(const char *fname, int *btf_fd,
                      void **func_info, unsigned *func_info_cnt,
                      unsigned *finfo_rec_size,
                      void **line_info, unsigned *line_info_cnt,
                      unsigned *linfo_rec_size) {
  int ret;

  *func_info = *line_info = NULL;
  *func_info_cnt = *line_info_cnt = NULL;

  *btf_fd = btf__fd(btf_);
  *finfo_rec_size = btf_ext__func_info_rec_size(btf_ext_);
  *linfo_rec_size = btf_ext__line_info_rec_size(btf_ext_);

  ret = btf_ext__reloc_func_info(btf_, btf_ext_, fname, 0,
        func_info, func_info_cnt);
  if (ret) {
    fprintf(stderr, "reloc func_info not successful\n");
    return -1;
  } else
    fprintf(stderr, "reloc func_info successful\n");

  ret = btf_ext__reloc_line_info(btf_, btf_ext_, fname, 0,
        line_info, line_info_cnt);
  if (ret) {
    fprintf(stderr, "reloc line_info not successful\n");
    return -1;
  } else
    fprintf(stderr, "reloc line_info successful\n");

  return 0;
}

int BTF::get_map_tids(std::string map_name,
                      unsigned expected_ksize, unsigned expected_vsize,
		      unsigned *key_tid, unsigned *value_tid) {
  return btf__get_map_kv_tids(btf_, map_name.c_str(),
			  expected_ksize, expected_vsize, key_tid, value_tid);
}

} // namespace ebpf
