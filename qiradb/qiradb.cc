#include <stdio.h>
#include <pthread.h>
#include <mongoc.h>
#include <bson.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>

#define MONGO_DEBUG printf
//#define MONGO_DEBUG(...) {}

// use like an include maybe?
// struct storing change data
struct change {
  uint64_t address;
  uint64_t data;
  uint32_t changelist_number;
  uint32_t flags;
};

#define IS_VALID      0x80000000
#define IS_WRITE      0x40000000
#define IS_MEM        0x20000000
#define IS_START      0x10000000
#define SIZE_MASK 0xFF

int main(int argc, char* argv[]) {
  bool ret;

  mongoc_init();
  mongoc_client_t *client;
  mongoc_collection_t *collection;
  client = mongoc_client_new("mongodb://localhost:3001");
  collection = mongoc_client_get_collection(client, "meteor", "change");
  ret = mongoc_collection_drop(collection, NULL);
  if (!ret) MONGO_DEBUG("drop failed\n");

  uint32_t mongo_qira_log_fd = open("/tmp/qira_log", O_RDONLY);
  uint32_t mongo_change_count = 0;

  struct change *GLOBAL_change_buffer;
  uint32_t *GLOBAL_change_count;

  GLOBAL_change_buffer =
    (struct change *)mmap(NULL, 4, PROT_READ, MAP_SHARED, mongo_qira_log_fd, 0);
  GLOBAL_change_count = (uint32_t*)GLOBAL_change_buffer;

  // begin thread run loop
  while (1) {
    // poll the websocket

    // commit every 10ms
    usleep(10*1000);  

    // check for new changes
    uint32_t change_count = *GLOBAL_change_count;
    if (mongo_change_count == change_count) continue;

    // set up bulk operation
    mongoc_bulk_operation_t *bulk;
    bson_t reply;
    bson_error_t error;
    bson_t *doc;
    bulk = mongoc_collection_create_bulk_operation(collection, true, NULL);

    // add new changes
    GLOBAL_change_buffer =
      (struct change *)mmap(NULL, change_count*sizeof(struct change),
      PROT_READ, MAP_SHARED, mongo_qira_log_fd, 0);
    GLOBAL_change_count = (uint32_t*)GLOBAL_change_buffer;

    while (mongo_change_count < change_count) {
      struct change *tmp = &GLOBAL_change_buffer[mongo_change_count];

      char typ[2]; typ[1] = '\0';
      uint32_t flags = tmp->flags;
      if (flags & IS_START) typ[0] = 'I';
      else if ((flags & IS_WRITE) && (flags & IS_MEM)) typ[0] = 'S';
      else if (!(flags & IS_WRITE) && (flags & IS_MEM)) typ[0] = 'L';
      else if ((flags & IS_WRITE) && !(flags & IS_MEM)) typ[0] = 'W';
      else if (!(flags & IS_WRITE) && !(flags & IS_MEM)) typ[0] = 'R';

      doc = bson_new();
      BSON_APPEND_INT64(doc, "address", tmp->address);
      BSON_APPEND_UTF8(doc, "type", typ);
      BSON_APPEND_INT32(doc, "size", tmp->flags & SIZE_MASK);
      BSON_APPEND_INT32(doc, "clnum", tmp->changelist_number);
      BSON_APPEND_INT64(doc, "data", tmp->data);
      mongoc_bulk_operation_insert(bulk, doc);
      bson_destroy(doc);

      mongo_change_count++;
    }

    // do bulk operation
    timespec ts_start, ts_end;
    MONGO_DEBUG("commit to %d...", mongo_change_count);
    fflush(stdout);
    clock_gettime(CLOCK_REALTIME, &ts_start);
    ret = mongoc_bulk_operation_execute(bulk, &reply, &error);
    clock_gettime(CLOCK_REALTIME, &ts_end);
    double secs = ts_end.tv_sec - ts_start.tv_sec;
    secs += (ts_end.tv_nsec - ts_start.tv_nsec) / 1000000000.0; 
    MONGO_DEBUG("done in %f seconds\n", secs);

    // debugging
    char *str = bson_as_json(&reply, NULL);
    printf("%s\n", str);
    bson_free(str);
    if (!ret) MONGO_DEBUG("mongo error: %s\n", error.message);

    // did bulk operation
    bson_destroy(&reply);
    mongoc_bulk_operation_destroy(bulk);
  }

  // thread exit
  mongoc_collection_destroy(collection);
  mongoc_client_destroy(client);
  mongoc_cleanup();
  return 0;
}

