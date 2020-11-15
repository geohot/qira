struct librarymap {
  struct librarymap *next;
  abi_ulong begin;
  abi_ulong end;
  const char *name;
};

struct librarymap *GLOBAL_librarymap;

void init_librarymap(void);
void add_to_librarymap(const char *name, abi_ulong begin, abi_ulong end);
bool is_library_addr(abi_ulong addr);

void init_librarymap(void){
  GLOBAL_librarymap = malloc(sizeof(struct librarymap));
  memset(GLOBAL_librarymap, 0, sizeof(struct librarymap));
  GLOBAL_librarymap->name = "dummy";
}

void add_to_librarymap(const char *name, abi_ulong begin, abi_ulong end){
  struct librarymap *cur, *newmap;
  for(cur = GLOBAL_librarymap; cur->next != NULL; cur = cur->next);
  newmap = malloc(sizeof(struct librarymap));
  newmap->next = NULL;
  newmap->begin = begin;
  newmap->end = end;
  newmap->name = strdup(name);
  cur->next = newmap;
}

bool is_library_addr(abi_ulong addr){
  struct librarymap *cur = GLOBAL_librarymap;
  while(cur != NULL){
    if (addr >= cur->begin && addr <= cur->end) return true;
    cur = cur->next;
  }
  return false;
}
