#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

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

inline char Trace::get_type_from_flags(uint32_t flags) {
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

inline void Trace::commit_memory(Clnum clnum, Address a, uint8_t d) {
  MemoryCell mc;
  mc.insert(MP(clnum, d));
  pair<map<Address, MemoryCell>::iterator, bool> ret = memory_.insert(MP(a, mc));
  if (ret.second == false) {
    ret.first->second.insert(MP(clnum, d));
  }
}

inline MemoryWithValid Trace::get_byte(Clnum clnum, Address a) {
  map<Address, MemoryCell>::iterator it = memory_.find(a);
  if (it == memory_.end()) return 0;

  MemoryCell::iterator it2 = it->second.upper_bound(clnum);
  if (it2 == it->second.begin()) return 0;
  else { --it2; return MEMORY_VALID & it2->second; }
}

bool Trace::ConnectToFileAndStart(char *filename, int register_size, int register_count) {
  register_size_ = register_size;
  register_count_ = register_count;
  pthread_mutex_init(&backing_mutex_, NULL);

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

  
  pthread_mutex_lock(&backing_mutex_);
  backing_ = (struct change *)mmap(NULL, sizeof(struct change)*entry_count, PROT_READ, MAP_SHARED, fd_, 0);
  pthread_mutex_unlock(&backing_mutex_);
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

vector<Clnum> Trace::FetchClnumsByAddressAndType(Address address, char type, Clnum start_clnum, int limit) {
  vector<Clnum> ret;
  pair<Address, char> p = MP(address, type);
  map<pair<Address, char>, set<Clnum> >::iterator it = addresstype_to_clnums_.find(p);
  if (it != addresstype_to_clnums_.end()) {
    for (set<Clnum>::iterator it2 = it->second.lower_bound(start_clnum);
         it2 != it->second.end(); ++it2) {
      ret.push_back(*it2);
      if (ret.size() == limit) break;
    }
  }
  return ret;
}

vector<struct change> Trace::FetchChangesByClnum(Clnum clnum, int limit) {
  vector<struct change> ret;
  map<Clnum, EntryNumber>::iterator it = clnum_to_entry_number_.find(clnum);
  if (it != clnum_to_entry_number_.end()) {
    pthread_mutex_lock(&backing_mutex_);
    for (int i = 0; i < limit; i++) {
      struct change* c = &backing_[it->second];
      if (it->first != clnum) break; // on next change already
      ret.push_back(*c);  // copy?
    }
    pthread_mutex_unlock(&backing_mutex_);
  }
  return ret;
}

vector<MemoryWithValid> Trace::FetchMemory(Clnum clnum, Address address, int len) {
  vector<MemoryWithValid> ret; 
  for (Address i = address; i < address+len; i++) {
    ret.push_back(get_byte(clnum, i));
  }
  return ret;
}

vector<uint64_t> Trace::FetchRegisters(Clnum clnum) {
  vector<uint64_t> ret;
  for (int i = 0; i < register_count_; i++) {
    RegisterCell::iterator it = registers_[i].upper_bound(clnum);
    if (it == registers_[i].begin()) ret.push_back(0);
    else { --it; ret.push_back(it->second); }
  }
  return ret;
}

