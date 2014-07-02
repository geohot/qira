#include <stdio.h>
#include <pthread.h>
#include <mongoc.h>
#include <bson.h>

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

  GLOBAL_change_buffer =
    mmap(NULL, GLOBAL_change_size * sizeof(struct change),
         PROT_READ | PROT_WRITE, MAP_SHARED, GLOBAL_qira_log_fd, 0);

  // begin thread run loop
  while (1) {
    usleep(10*1000);  // commit every 10ms

    mongoc_bulk_operation_t *bulk;
    bson_t reply;
    bson_error_t error;
    bson_t *doc;

    // set up bulk operation
    bulk = mongoc_collection_create_bulk_operation(collection, true, NULL);

    // add new changes
    int lcount = 0;
    while (mongo_change_count < GLOBAL_change_count) {
      struct change tmp;
      int a = read(mongo_qira_log_fd, &tmp, sizeof(struct change));
      if (a != sizeof(struct change)) {
        qemu_log("READ ERROR");
        break;
      }

      char typ[2]; typ[1] = '\0';
      uint32_t flags = tmp.flags;
      if (flags & IS_START) typ[0] = 'I';
      else if ((flags & IS_WRITE) && (flags & IS_MEM)) typ[0] = 'S';
      else if (!(flags & IS_WRITE) && (flags & IS_MEM)) typ[0] = 'L';
      else if ((flags & IS_WRITE) && !(flags & IS_MEM)) typ[0] = 'W';
      else if (!(flags & IS_WRITE) && !(flags & IS_MEM)) typ[0] = 'R';

      doc = bson_new();
      BSON_APPEND_INT32(doc, "address", tmp.address);
      BSON_APPEND_UTF8(doc, "type", typ);
      BSON_APPEND_INT32(doc, "size", tmp.flags & SIZE_MASK);
      BSON_APPEND_INT32(doc, "clnum", tmp.changelist_number);
      BSON_APPEND_INT32(doc, "data", tmp.data);
      mongoc_bulk_operation_insert(bulk, doc);
      bson_destroy(doc);

      mongo_change_count++;
      lcount++;
    }

    if (lcount > 0) {
      MONGO_DEBUG("commit %d\n", mongo_change_count);

      // do bulk operation
      ret = mongoc_bulk_operation_execute(bulk, &reply, &error);
      if (!ret) MONGO_DEBUG("mongo error: %s\n", error.message);

      // did bulk operation
      bson_destroy(&reply);
    }
    mongoc_bulk_operation_destroy(bulk);
  }

  // thread exit
  mongoc_collection_destroy(collection);
  mongoc_client_destroy(client);
  mongoc_cleanup();
  return NULL;
}
