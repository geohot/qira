#include <vector>
#include <map>
#if __cplusplus == 201103L
  #include <unordered_map>
#else
  //#define USE_BOOST
  #ifdef USE_BOOST
    #include <boost/unordered_map.hpp>
    #define unordered_map boost::unordered_map
  #else
    #define unordered_map map
  #endif
#endif
#include <set>
#include <stdint.h>

#ifndef _WIN32
#include <pthread.h>
#define THREAD pthread_t
#define THREAD_CREATE(x, fxn, dat) pthread_create(&x, NULL, fxn, (void*)dat)
#define THREAD_JOIN(x) pthread_join(x, NULL)

#define MUTEX pthread_mutex_t
#define MUTEX_INIT(x) pthread_mutex_init(&x, NULL)
#define MUTEX_LOCK(x) pthread_mutex_lock(&x)
#define MUTEX_UNLOCK(x) pthread_mutex_unlock(&x)

#define RWLOCK pthread_rwlock_t
#define RWLOCK_INIT(x) pthread_rwlock_init(&x, NULL)
#define RWLOCK_RDLOCK(x) pthread_rwlock_rdlock(&x)
#define RWLOCK_WRLOCK(x) pthread_rwlock_wrlock(&x)
#define RWLOCK_UNLOCK(x) pthread_rwlock_unlock(&x)
#define RWLOCK_WRUNLOCK(x) pthread_rwlock_unlock(&x)
#else
#include <Windows.h>
#define THREAD HANDLE
#define THREAD_CREATE(x, fxn, dat) x=CreateThread(NULL, 0, fxn, dat, 0, NULL)
#define THREAD_JOIN(x) WaitForSingleObject(x, INFINITE)

#define RWLOCK SRWLOCK
#define RWLOCK_INIT(x) InitializeSRWLock(&x)
#define RWLOCK_RDLOCK(x) AcquireSRWLockShared(&x)
#define RWLOCK_WRLOCK(x) AcquireSRWLockExclusive(&x)
#define RWLOCK_UNLOCK(x) ReleaseSRWLockShared(&x)
#define RWLOCK_WRUNLOCK(x) ReleaseSRWLockExclusive(&x)

#define MUTEX SRWLOCK
#define MUTEX_INIT(x) RWLOCK_INIT(x)
#define MUTEX_LOCK(x) RWLOCK_WRLOCK(x)
#define MUTEX_UNLOCK(x) RWLOCK_WRUNLOCK(x)
#endif


using namespace std;

typedef uint32_t EntryNumber;
typedef uint32_t Clnum;
typedef uint16_t MemoryWithValid;
#define MEMORY_VALID 0x100
typedef uint64_t Address;
typedef map<Clnum, uint8_t> MemoryCell;
typedef map<Clnum, uint64_t> RegisterCell;

// copied from qemu_mods/tci.c 
struct change {
  Address address;
  uint64_t data;
  Clnum clnum;
  uint32_t flags;
};

#define IS_VALID      0x80000000
#define IS_WRITE      0x40000000
#define IS_MEM        0x20000000
#define IS_START      0x10000000
#define IS_SYSCALL    0x08000000
#define SIZE_MASK     0xFF

void *thread_entry(void *);

class Trace {
public:
  Trace(unsigned int trace_index);
  ~Trace();
  bool ConnectToFileAndStart(char *filename, int register_size, int register_count, bool is_big_endian);

  // these must be threadsafe
  vector<Clnum> FetchClnumsByAddressAndType(Address address, char type, Clnum start_clnum, unsigned int limit);
  vector<struct change> FetchChangesByClnum(Clnum clnum, unsigned int limit);
  vector<MemoryWithValid> FetchMemory(Clnum clnum, Address address, int len);
  vector<uint64_t> FetchRegisters(Clnum clnum);

  // simple ones
  set<Address> GetInstructionPages();
  set<Address> GetDataPages();
  Clnum GetMaxClnum() { return max_clnum_; }
  Clnum GetMinClnum() { return min_clnum_; }

  bool GetDidUpdate() { bool ret = did_update_; if (ret) { did_update_ = false; } return ret; }

  static char get_type_from_flags(uint32_t flags);

  // should be private
  void process();
  bool is_running_;
private:
  THREAD thread;

  inline void commit_memory(Clnum clnum, Address a, uint8_t d);
  inline MemoryWithValid get_byte(Clnum clnum, Address a);

  bool is_big_endian_;
  // the backing of the database
  RWLOCK db_lock_;
  unordered_map<pair<Address, char>, set<Clnum> > addresstype_to_clnums_;
  vector<EntryNumber> clnum_to_entry_number_;
  vector<RegisterCell> registers_; int register_size_, register_count_;
  map<Address, MemoryCell> memory_;
  set<Address> instruction_pages_;
  set<Address> data_pages_;
  Clnum max_clnum_, min_clnum_;
  
  bool remap_backing(uint64_t);
  MUTEX backing_mutex_;
  const struct change* backing_;
  uint64_t backing_size_;
  int fd_;
  EntryNumber entries_done_;

  bool did_update_;
  unsigned int trace_index_;
};

