
#include <vector>
#include <map>
#if __cplusplus == 201103L
  #include <unordered_map>
#else
  #define USE_BOOST
  #ifdef USE_BOOST
    #include <boost/unordered_map.hpp>
    #define unordered_map boost::unordered_map
  #else
    #define unordered_map map
  #endif
#endif
#include <set>
#include <stdint.h>
#include <pthread.h>

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
  bool ConnectToFileAndStart(char *filename, int register_size, int register_count);

  // these must be threadsafe
  vector<Clnum> FetchClnumsByAddressAndType(Address address, char type, Clnum start_clnum, unsigned int limit);
  vector<struct change> FetchChangesByClnum(Clnum clnum, unsigned int limit);
  vector<MemoryWithValid> FetchMemory(Clnum clnum, Address address, int len);
  vector<uint64_t> FetchRegisters(Clnum clnum);

  // simple ones
  set<Address> GetInstructionPages() { return instruction_pages_; }
  set<Address> GetDataPages() { return data_pages_; }
  Clnum GetMaxClnum() { return max_clnum_; }
  Clnum GetMinClnum() { return min_clnum_; }

  bool GetDidUpdate() { bool ret = did_update_; if (ret) { did_update_ = false; } return ret; }

  static char get_type_from_flags(uint32_t flags);

  // should be private
  void process();
  bool is_running_;
private:
  pthread_t thread;

  inline void commit_memory(Clnum clnum, Address a, uint8_t d);
  inline MemoryWithValid get_byte(Clnum clnum, Address a);

  // the backing of the database
  unordered_map<pair<Address, char>, set<Clnum> > addresstype_to_clnums_;
  vector<EntryNumber> clnum_to_entry_number_;
  vector<RegisterCell> registers_; int register_size_, register_count_;
  map<Address, MemoryCell> memory_;
  set<Address> instruction_pages_;
  set<Address> data_pages_;
  Clnum max_clnum_, min_clnum_;
  
  bool remap_backing(uint64_t);
  pthread_mutex_t backing_mutex_;
  const struct change* backing_;
  uint64_t backing_size_;
  int fd_;
  EntryNumber entries_done_;

  bool did_update_;
  unsigned int trace_index_;
};

