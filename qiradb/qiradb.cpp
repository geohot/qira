#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "qiradb.h"

#define MP make_pair
#define PAGE_MASK 0xFFFFFFFFFFFFF000LL
#define INVALID_CLNUM 0xFFFFFFFF

void *thread_entry(void *trace_class) {
  Trace *t = (Trace *)trace_class;  // best c++ casting

  // lower priority thread for lock
  setpriority(PRIO_PROCESS, 0, getpriority(PRIO_PROCESS, 0)+1);
  while (t->is_running_) {   // running?
    t->process();
    usleep(10 * 1000);
  }
  return NULL;
}

Trace::Trace(unsigned int trace_index) {
  entries_done_ = 1;
  fd_ = 0;
  backing_ = NULL;
  did_update_ = false;
  max_clnum_ = 0;
  min_clnum_ = INVALID_CLNUM;
  backing_size_ = 0;
  trace_index_ = trace_index;
  is_running_ = true;
}

// the destructor isn't thread safe wrt to the accessor functions
Trace::~Trace() {
  is_running_ = false;
  pthread_join(thread, NULL);
  // mutex lock isn't required now that the thread stopped
  munmap((void*)backing_, backing_size_);
  close(fd_);
  //printf("dead\n");
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

inline void Trace::commit_memory(Clnum clnum, Address a, uint8_t d) {
  pair<map<Address, MemoryCell>::iterator, bool> ret = memory_.insert(MP(a, MemoryCell()));
  ret.first->second[clnum] = d;
}

inline MemoryWithValid Trace::get_byte(Clnum clnum, Address a) {
  //printf("get_byte %u %llx\n", clnum, a);
  map<Address, MemoryCell>::iterator it = memory_.find(a);
  if (it == memory_.end()) return 0;

  MemoryCell::iterator it2 = it->second.upper_bound(clnum);
  if (it2 == it->second.begin()) return 0;
  else { --it2; return MEMORY_VALID | it2->second; }
}

bool Trace::remap_backing(uint64_t new_size) {
  if (backing_size_ == new_size) return true;
  pthread_mutex_lock(&backing_mutex_);
  munmap((void*)backing_, backing_size_);
  backing_size_ = new_size;
  backing_ = (const struct change *)mmap(NULL, backing_size_, PROT_READ, MAP_SHARED, fd_, 0);
  pthread_mutex_unlock(&backing_mutex_);
  return (backing_ != NULL);
}

bool Trace::ConnectToFileAndStart(char *filename, int register_size, int register_count, bool is_big_endian) {
  is_big_endian_ = is_big_endian;
  register_size_ = register_size;
  register_count_ = register_count;
  pthread_rwlock_init(&db_lock_, NULL);
  pthread_mutex_init(&backing_mutex_, NULL);

  registers_.resize(register_count_);

  fd_ = open(filename, O_RDONLY);
  if (fd_ <= 0) return false;

  if (!remap_backing(sizeof(struct change))) return false;

  return pthread_create(&thread, NULL, thread_entry, (void *)this) == 0;
}

void Trace::process() {
  pthread_mutex_lock(&backing_mutex_);
  EntryNumber entry_count = *((EntryNumber*)backing_);  // don't let this change under me
  pthread_mutex_unlock(&backing_mutex_);

  if (entries_done_ >= entry_count) return;       // handle the > case better

  remap_backing(sizeof(struct change)*entry_count); // what if this fails?

  printf("on %u going from %u to %u...", trace_index_, entries_done_, entry_count);
  fflush(stdout);

  struct timeval tv_start, tv_end;
  gettimeofday(&tv_start, NULL);

  // clamping
  if ((entries_done_ + 1000000) < entry_count) {
    entry_count = entries_done_ + 1000000;
  }

  while (entries_done_ != entry_count) {
    // no need to lock this here, because this is the only thread that changes it
    const struct change *c = &backing_[entries_done_];
    char type = get_type_from_flags(c->flags);

    pthread_rwlock_wrlock(&db_lock_);
    // clnum_to_entry_number_, instruction_pages_
    if (type == 'I') {
      if (clnum_to_entry_number_.size() < c->clnum) {
        // there really shouldn't be holes
        clnum_to_entry_number_.resize(c->clnum);
      }
      clnum_to_entry_number_.push_back(entries_done_);
      instruction_pages_.insert(c->address & PAGE_MASK);
    }

    // addresstype_to_clnums_
    // ** this is 75% of the perf, real unordered_map should improve, but c++11 is hard to build
    pair<unordered_map<pair<Address, char>, set<Clnum> >::iterator, bool> ret =
      addresstype_to_clnums_.insert(MP(MP(c->address, type), set<Clnum>()));
    ret.first->second.insert(c->clnum);

    // registers_
    if (type == 'W' && c->address < (register_size_ * register_count_)) {
      registers_[c->address / register_size_][c->clnum] = c->data;
    }

    // memory_, data_pages_
    if (type == 'L' || type == 'S') {
      data_pages_.insert(c->address & PAGE_MASK);
      if (type == 'S') {
        int byte_count = (c->flags&SIZE_MASK)/8;
        uint64_t data = c->data;
        if (is_big_endian_) {
          for (int i = byte_count-1; i >= 0; --i) {
            commit_memory(c->clnum, c->address+i, data&0xFF);
            data >>= 8;
          }
        } else {
          // little endian
          for (int i = 0; i < byte_count; i++) {
            commit_memory(c->clnum, c->address+i, data&0xFF);
            data >>= 8;
          }
        }
      }
    }
    pthread_rwlock_unlock(&db_lock_);

    // max_clnum_
    if (max_clnum_ < c->clnum) {
      max_clnum_ = c->clnum;
    }

    if (min_clnum_ == INVALID_CLNUM || c->clnum < min_clnum_) {
      min_clnum_ = c->clnum;
    }
    
    entries_done_++;
  }

  gettimeofday(&tv_end, NULL);
  double t = (tv_end.tv_usec-tv_start.tv_usec)/1000.0 +
             (tv_end.tv_sec-tv_start.tv_sec)*1000.0;
  printf("done %f ms\n", t);

  // set this at the end
  did_update_ = true;
}

vector<Clnum> Trace::FetchClnumsByAddressAndType(Address address, char type, Clnum start_clnum, unsigned int limit) {
  pthread_rwlock_rdlock(&db_lock_);
  vector<Clnum> ret;
  pair<Address, char> p = MP(address, type);
  unordered_map<pair<Address, char>, set<Clnum> >::iterator it = addresstype_to_clnums_.find(p);
  if (it != addresstype_to_clnums_.end()) {
    for (set<Clnum>::iterator it2 = it->second.lower_bound(start_clnum);
         it2 != it->second.end(); ++it2) {
      ret.push_back(*it2);
      if (ret.size() == limit) break;
    }
  }
  pthread_rwlock_unlock(&db_lock_);
  return ret;
}

vector<struct change> Trace::FetchChangesByClnum(Clnum clnum, unsigned int limit) {
  pthread_rwlock_rdlock(&db_lock_);
  vector<struct change> ret;
  EntryNumber en = 0;
  if (clnum < clnum_to_entry_number_.size()) {
    en = clnum_to_entry_number_[clnum];
  }
  pthread_rwlock_unlock(&db_lock_);

  if (en != 0) {
    pthread_mutex_lock(&backing_mutex_);
    const struct change* c = &backing_[en];
    for (unsigned int i = 0; i < limit; i++) {
      if (en+i >= entries_done_) break;  // don't run off the end
      if (c->clnum != clnum) break; // on next change already
      ret.push_back(*c);  // copy?
      ++c;
    }
    pthread_mutex_unlock(&backing_mutex_);
  }
  return ret;
}

vector<MemoryWithValid> Trace::FetchMemory(Clnum clnum, Address address, int len) {
  pthread_rwlock_rdlock(&db_lock_);
  vector<MemoryWithValid> ret; 
  for (Address i = address; i < address+len; i++) {
    ret.push_back(get_byte(clnum, i));
  }
  pthread_rwlock_unlock(&db_lock_);
  return ret;
}

vector<uint64_t> Trace::FetchRegisters(Clnum clnum) {
  pthread_rwlock_rdlock(&db_lock_);
  vector<uint64_t> ret;
  for (int i = 0; i < register_count_; i++) {
    RegisterCell::iterator it = registers_[i].upper_bound(clnum);
    if (it == registers_[i].begin()) ret.push_back(0);
    else { --it; ret.push_back(it->second); }
  }
  pthread_rwlock_unlock(&db_lock_);
  return ret;
}

set<Address> Trace::GetInstructionPages() {
  pthread_rwlock_rdlock(&db_lock_);
  set<Address> ret = instruction_pages_;
  pthread_rwlock_unlock(&db_lock_);
  return ret;
}

set<Address> Trace::GetDataPages() {
  pthread_rwlock_rdlock(&db_lock_);
  set<Address> ret = data_pages_;
  pthread_rwlock_unlock(&db_lock_);
  return ret;
}

