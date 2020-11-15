/* OpenFirmware interface */


/* 6.3.2.1 Client interface */


typedef struct _of1275_test_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	const char *name;
	/*out */
	int missing;
} of1275_test_service;

int of1275_test(const char *name, int *missing);


/* 6.3.2.2 Device tree */


typedef struct _of1275_peer_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	int phandle;
	/*out */
	int sibling_phandle;
} of1275_peer_service;

int of1275_peer(int phandle, int *sibling_phandle);


typedef struct _of1275_child_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	int phandle;
	/*out */
	int child_phandle;
} of1275_child_service;

int of1275_child(int phandle, int *child_phandle);


typedef struct _of1275_parent_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	int phandle;
	/*out */
	int parent_phandle;
} of1275_parent_service;

int of1275_child(int phandle, int *parent_phandle);


typedef struct _of1275_instance_to_package_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	int ihandle;
	/*out */
	int phandle;
} of1275_instance_to_package_service;

int of1275_instance_to_package(int ihandle, int *phandle);


typedef struct _of1275_getproplen_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	int phandle;
	const char *name;
	/*out */
	int proplen;
} of1275_getproplen_service;

int of1275_getproplen(int phandle, const char *name, int *proplen);


typedef struct _of1275_getprop_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	int phandle;
	const char *name;
	void *buf;
	int buflen;
	/*out */
	int size;
} of1275_getprop_service;

int of1275_getprop(int phandle, const char *name, void *buf, int buflen,
		   int *size);


typedef struct _of1275_nextprop_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	int phandle;
	const char *previous;
	void *buf;
	/*out */
	int flag;
} of1275_nextprop_service;

int of1275_nextprop(int phandle, const char *previous, void *buf,
		    int *flag);


typedef struct _of1275_setprop_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	int phandle;
	const char *name;
	void *buf;
	int len;
	/*out */
	int size;
} of1275_setprop_service;

int of1275_setprop(int phandle, const char *name, void *buf, int len,
		   int *size);


typedef struct _of1275_canon_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	const char *device_specifier;
	void *buf;
	int buflen;
	/*out */
	int length;
} of1275_canon_service;

int of1275_canon(const char *device_specifier, void *buf, int buflen,
		 int *length);


typedef struct _of1275_finddevice_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	const char *device_specifier;
	/*out */
	int phandle;
} of1275_finddevice_service;

int of1275_finddevice(const char *device_specifier, int *phandle);


typedef struct _of1275_instance_to_path_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	int ihandle;
	void *buf;
	int buflen;
	/*out */
	int length;
} of1275_instance_to_path_service;

int of1275_instance_to_path(int ihandle, void *buf, int buflen,
			    int *length);


typedef struct _of1275_package_to_path_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	int phandle;
	void *buf;
	int buflen;
	/*out */
	int length;
} of1275_package_to_path_service;

int of1275_package_to_path(int phandle, void *buf, int buflen,
			   int *length);


typedef struct _of1275_call_method_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	const char *method;
	int ihandle;
	/*... */
	int args[0];
} of1275_call_method_service;

int of1275_call_method(const char *method, int ihandle, ...);


/* 6.3.2.3 Device I/O */


typedef struct _of1275_open_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	const char *device_specifier;
	/*out */
	int ihandle;
} of1275_open_service;

int of1275_open(const char *device_specifier, int *ihandle);


typedef struct _of1275_close_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	int ihandle;
	/*out */
} of1275_close_service;

int of1275_close(int ihandle);


typedef struct _of1275_read_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	int ihandle;
	void *addr;
	int len;
	/*out */
	int actual;
} of1275_read_service;

int of1275_read(int ihandle, void *addr, int len, int *actual);


typedef struct _of1275_write_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	int ihandle;
	void *addr;
	int len;
	/*out */
	int actual;
} of1275_write_service;

int of1275_write(int ihandle, void *addr, int len, int *actual);


typedef struct _of1275_seek_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	int ihandle;
	int pos_hi;
	int pos_lo;
	/*out */
	int status;
} of1275_seek_service;

int of1275_seek(int ihandle, int pos_hi, int pos_lo, int *status);


/* 6.3.2.4 Memory */


typedef struct _of1275_claim_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	void *virt;
	int size;
	int align;
	/*out */
	void *baseaddr;
} of1275_claim_service;

int of1275_claim(void *virt, int size, int align, void **baseaddr);


typedef struct _of1275_release_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	void *virt;
	int size;
	int align;
	/*out */
} of1275_release_service;

int of1275_release(void *virt, int size);


/* 6.3.2.5 Control transfer */


typedef struct _of1275_boot_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	const char *bootspec;
	/*out */
} of1275_boot_service;

int of1275_boot(const char *bootspec);


typedef struct _of1275_enter_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	/*out */
} of1275_enter_service;

int of1275_enter(void);

typedef struct _of1275_exit_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	int status;
	/*out */
} of1275_exit_service;

int of1275_exit(int status);


typedef struct _of1275_chain_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	void *virt;
	int size;
	void *entry;
	void *args;
	int len;
	/*out */
} of1275_chain_service;

int of1275_chain(void *virt, int size, void *entry, void *args, int len);


/* 6.3.2.6 User interface */


typedef struct _of1275_interpret_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	const char *cmd;
	int args[0];
	/*... */
	/*out */
	/*... */
} of1275_interpret_service;

int of1275_interpret(const char *arg, ...);


typedef struct _of1275_set_callback_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	void *newfunc;
	/*out */
	void *oldfunc;
} of1275_set_callback_service;

int of1275_set_callback(void *newfunc, void **oldfunc);


typedef struct _of1275_set_symbol_lookup_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	void *sym_to_value;
	void *value_to_sym;
	/*out */
} of1275_set_symbol_lookup_service;

int of1275_set_symbol_lookup(void *sym_to_value, void *value_to_sym);


/* 6.3.2.7 Time */


typedef struct _of1275_milliseconds_service {
	const char *service;
	int n_args;
	int n_returns;
	/*in */
	/*out */
	int ms;
} of1275_milliseconds_service;

int of1275_milliseconds(int *ms);


/* Common and useful utilities */


int of_find_integer_property(const char *path, const char *property);

void of_find_string_property(const char *path, const char *property,
			     char *string, int sizeof_string);
