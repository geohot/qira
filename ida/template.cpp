#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <bytes.hpp>
#include <dbg.hpp>

//#define DEBUG

// ***************** WEBSOCKETS *******************
#include "libwebsockets.h"

static int callback_http(struct libwebsocket_context* context,
    struct libwebsocket* wsi,
    enum libwebsocket_callback_reasons reason, void* user,
    void* in, size_t len) {
  return 0;
}

ea_t qira_address = BADADDR;

static void set_qira_address(ea_t la) {
  if (qira_address != BADADDR) { del_bpt(qira_address); }
  qira_address = la;
  add_bpt(qira_address);
  disable_bpt(qira_address);
}

static void thread_safe_jump_to(ea_t a) {
  struct uireq_jumpto_t: public ui_request_t {
    uireq_jumpto_t(ea_t a) {
      la = a;
    }
    virtual bool idaapi run() {
      if (qira_address != la) {
        set_qira_address(la);
        jumpto(la, -1, 0);  // don't UIJMP_ACTIVATE to not steal focus
      }
      return false;
    }
    ea_t la;
  };
  execute_ui_requests(new uireq_jumpto_t(a), NULL);
}

struct libwebsocket* gwsi = NULL;

static int callback_qira(struct libwebsocket_context* context,
      struct libwebsocket* wsi,
      enum libwebsocket_callback_reasons reason, void* user,
      void* in, size_t len) {
  //msg("QIRA CALLBACK: %d\n", reason);
  switch(reason) {
    case LWS_CALLBACK_ESTABLISHED:
      // we only support one client
      gwsi = wsi;
      msg("QIRA web connected\n");
      break;
    case LWS_CALLBACK_RECEIVE:
      #ifdef DEBUG
        msg("QIRARX:%s\n", (char *)in);
      #endif
      if (memcmp(in, "setaddress ", sizeof("setaddress ")-1) == 0) {
        // untested
        #ifdef __EA64__
          ea_t addr = strtoull((char*)in+sizeof("setaddress ")-1, NULL, 0);
        #else
          ea_t addr = strtoul((char*)in+sizeof("setaddress ")-1, NULL, 0);
        #endif
        thread_safe_jump_to(addr);
      }
      break;
    default:
      break;
  }
  return 0;
}

static void ws_send(char *str) {
  #ifdef DEBUG
    msg("QIRATX:%s\n", str);
  #endif
  int len = strlen(str);
  unsigned char *buf = (unsigned char*)
    malloc(LWS_SEND_BUFFER_PRE_PADDING + len + LWS_SEND_BUFFER_POST_PADDING);
  memcpy(&buf[LWS_SEND_BUFFER_PRE_PADDING], str, len);
  if (gwsi != NULL) {
    libwebsocket_write(gwsi, &buf[LWS_SEND_BUFFER_PRE_PADDING], len, LWS_WRITE_TEXT);
  }
  free(buf);
}


// ***************** IDAPLUGIN *******************

static void update_address(const char *type, ea_t addr) {
  char tmp[100];
  #ifdef __EA64__
    qsnprintf(tmp, 100-1, "set%s 0x%llx", type, addr);
  #else
    qsnprintf(tmp, 100-1, "set%s 0x%x", type, addr);
  #endif
  ws_send(tmp);
}

static int idaapi hook(void *user_data, int event_id, va_list va) {
  static ea_t old_addr = 0;
  ea_t addr;
  if (event_id == view_curpos) {
    addr = get_screen_ea();
    if (old_addr != addr) {
      if (isCode(getFlags(addr))) {
        // don't update the address if it's already the qira address
        if (addr != qira_address) {
          set_qira_address(addr);
          update_address("iaddr", addr);
        }
      } else {
        update_address("daddr", addr);
      }
    }
    old_addr = addr;
  }
  return 0;
}

// ***************** WEBSOCKETS BOILERPLATE *******************

static struct libwebsocket_protocols protocols[] = {
  { "http-only", callback_http, 0 },
  { "qira", callback_qira, 0 },
  { NULL, NULL, 0 }
};

qthread_t websockets_thread;
int websockets_running;

int idaapi websocket_thread(void *) {
  struct libwebsocket_context* context;

	struct lws_context_creation_info info;
	memset(&info, 0, sizeof info);
  info.port = 3003;
	info.iface = NULL;
	info.protocols = protocols;
	info.extensions = libwebsocket_get_internal_extensions();
	info.gid = -1;
	info.uid = -1;
	info.options = 0;

  // i assume this does the bind?
  context = libwebsocket_create_context(&info);

  if (context == NULL) {
    msg("websocket init failed\n");
    return -1;
  }

  msg("yay websockets\n");

  while (websockets_running) {
    libwebsocket_service(context, 50);
  }
  libwebsocket_context_destroy(context);
  return 0;
}

void start_websocket_thread() {
  websockets_running = 1;
  websockets_thread = qthread_create(websocket_thread, NULL);
}

void exit_websocket_thread() {
  websockets_running = 0;
  qthread_join(websockets_thread);
}

// ***************** IDAPLUGIN BOILERPLATE *******************

int idaapi IDAP_init(void) {
  hook_to_notification_point(HT_VIEW, hook, NULL);
  start_websocket_thread();
	return PLUGIN_KEEP;
}

void idaapi IDAP_term(void) {
  unhook_from_notification_point(HT_VIEW, hook);
  exit_websocket_thread();
	return;
}

void idaapi IDAP_run(int arg) {
  msg("installing book\n");
  return;
}

char IDAP_comment[] 	= "This is my test plug-in";
char IDAP_help[] 		= "My plugin";
char IDAP_name[] 		= "QIRA server";
char IDAP_hotkey[] 	= "Alt-X";

plugin_t PLUGIN = {
  IDP_INTERFACE_VERSION,	// IDA version plug-in is written for
  0,					    // Flags (see below)
  IDAP_init,			// Initialisation function
  IDAP_term,			// Clean-up function
  IDAP_run,				// Main plug-in body
  IDAP_comment,	  // Comment 
  IDAP_help,			// As above
  IDAP_name,			// Plug-in name shown in 
  IDAP_hotkey			// Hot key to run the plug-in
};

