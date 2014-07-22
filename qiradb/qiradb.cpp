#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>

#include "qiradb.h"

#define MP make_pair
#define PAGE_MASK 0xFFFFF000

void *thread_entry(void *trace_class) {
  Trace *t = (Trace *)trace_class;  // best c++ casting
  while (1) {   // running?
    t->process();
    usleep(10 * 1000);
  }
}

Trace::Trace() {
  entries_done_ = 1;
  fd_ = 0;
  backing_ = NULL;
  did_update_ = false;
}

char Trace::get_type_from_flags(uint32_t flags) {
  if (!(flags & IS_VALID)) return '?';
  if (flags & IS_START) return 'I';
  if (flags & IS_SYSCALL) return 's';

  if (flags & IS_MEM) {
    if (flags & IS_WRITE) return 'S';
    else return 'L';
  } else {
    if (flags & IS_WRITE) return 'W';
    else return 'R';
  }
  return '?';
}

void Trace::commit_memory(Clnum clnum, Address a, uint8_t d) {
  MemoryCell mc;
  mc.insert(MP(clnum, d));
  pair<map<Address, MemoryCell>::iterator, bool> ret = memory_.insert(MP(a, mc));
  if (ret.second == false) {
    ret.first->second.insert(MP(clnum, d));
  }
}

bool Trace::ConnectToFileAndStart(char *filename, int register_size, int register_count) {
  register_size_ = register_size;
  register_count_ = register_count;

  registers_.resize(register_count_);

  fd_ = open(filename, O_RDONLY);
  if (fd_ <= 0) return false;

  backing_ = (struct change *)mmap(NULL, sizeof(struct change), PROT_READ, MAP_SHARED, fd_, 0);
  if (backing_ == NULL) return false;

  return pthread_create(&thread, NULL, thread_entry, (void *)this) == 0;
}

void Trace::process() {
  EntryNumber entry_count = *((EntryNumber*)backing_);  // don't let this change under me
  if (entries_done_ >= entry_count) return;       // handle the > case better
  did_update_ = true;

  backing_ = (struct change *)mmap(NULL, sizeof(struct change)*entry_count, PROT_READ, MAP_SHARED, fd_, 0);
  // what if this fails?

  while (entries_done_ != entry_count) {
    struct change *c = &backing_[entries_done_];

    char type = get_type_from_flags(c->flags);

    // clnum_to_entry_number_, instruction_pages_
    if (type == 'I') {
      clnum_to_entry_number_.insert(MP(c->clnum, entries_done_));
      instruction_pages_.insert(c->address & PAGE_MASK);
    }

    // addresstype_to_clnums_
    set<Clnum> single_entry;
    single_entry.insert(c->clnum);
    pair<map<pair<Address, char>, set<Clnum> >::iterator, bool> ret =
      addresstype_to_clnums_.insert(MP(MP(c->address, type), single_entry));
    if (!ret.second) {
      ret.first->second.insert(c->clnum);
    }

    // registers_
    if ((type == 'R' || type == 'W') && c->address < (register_size_ * register_count_)) {
      registers_[c->address / register_size_].insert(MP(c->clnum, c->data));
    }

    // memory_, data_pages_
    if (type == 'L' || type == 'S') {
      data_pages_.insert(c->address & PAGE_MASK);
      int byte_count = (c->flags&SIZE_MASK)/8;
      uint64_t data = c->data;
      for (int i = 0; i < byte_count; i++) {
        // little endian
        commit_memory(c->clnum, c->address+i, c->data&0xFF);
        c->data >>= 8;
      }
    }

    // max_clnum_
    if (max_clnum_ < c->clnum) {
      max_clnum_ = c->clnum;
    }
    
    entries_done_++;
  }
}

