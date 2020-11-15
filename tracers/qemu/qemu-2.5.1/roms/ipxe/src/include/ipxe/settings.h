#ifndef _IPXE_SETTINGS_H
#define _IPXE_SETTINGS_H

/** @file
 *
 * Configuration settings
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <ipxe/tables.h>
#include <ipxe/list.h>
#include <ipxe/refcnt.h>

struct settings;
struct in_addr;
struct in6_addr;
union uuid;

/** A setting */
struct setting {
	/** Name
	 *
	 * This is the human-readable name for the setting.
	 */
	const char *name;
	/** Description */
	const char *description;
	/** Setting type
	 *
	 * This identifies the type of setting (e.g. string, IPv4
	 * address, etc.).
	 */
	const struct setting_type *type;
	/** Setting tag, if applicable
	 *
	 * The setting tag is a numerical description of the setting
	 * (such as a DHCP option number, or an SMBIOS structure and
	 * field number).
	 */
	unsigned int tag;
	/** Setting scope (or NULL)
	 *
	 * For historic reasons, a NULL scope with a non-zero tag
	 * indicates a DHCPv4 option setting.
	 */
	const struct settings_scope *scope;
};

/** Configuration setting table */
#define SETTINGS __table ( struct setting, "settings" )

/** Declare a configuration setting */
#define __setting( setting_order, name ) \
	__table_entry ( SETTINGS, setting_order.name )

/** @defgroup setting_order Setting ordering
 * @{
 */

#define SETTING_NETDEV		01 /**< Network device settings */
#define SETTING_NETDEV_EXTRA	02 /**< Network device additional settings */
#define SETTING_IP		03 /**< IPv4 settings */
#define SETTING_IP_EXTRA	04 /**< IPv4 additional settings */
#define SETTING_BOOT		05 /**< Generic boot settings */
#define SETTING_BOOT_EXTRA	06 /**< Generic boot additional settings */
#define SETTING_SANBOOT		07 /**< SAN boot settings */
#define SETTING_SANBOOT_EXTRA	08 /**< SAN boot additional settings */
#define SETTING_HOST		09 /**< Host identity settings */
#define SETTING_HOST_EXTRA	10 /**< Host identity additional settings */
#define SETTING_AUTH		11 /**< Authentication settings */
#define SETTING_AUTH_EXTRA	12 /**< Authentication additional settings */
#define SETTING_CRYPTO		13 /**< Cryptography settings */
#define SETTING_MISC		14 /**< Miscellaneous settings */

/** @} */

/** Settings block operations */
struct settings_operations {
	/** Redirect to underlying settings block (if applicable)
	 *
	 * @v settings		Settings block
	 * @ret settings	Underlying settings block
	 */
	struct settings * ( * redirect ) ( struct settings *settings );
	/** Check applicability of setting
	 *
	 * @v settings		Settings block
	 * @v setting		Setting
	 * @ret applies		Setting applies within this settings block
	 */
	int ( * applies ) ( struct settings *settings,
			    const struct setting *setting );
	/** Store value of setting
	 *
	 * @v settings		Settings block
	 * @v setting		Setting to store
	 * @v data		Setting data, or NULL to clear setting
	 * @v len		Length of setting data
	 * @ret rc		Return status code
	 */
	int ( * store ) ( struct settings *settings,
			  const struct setting *setting,
			  const void *data, size_t len );
	/** Fetch value of setting
	 *
	 * @v settings		Settings block
	 * @v setting		Setting to fetch
	 * @v data		Buffer to fill with setting data
	 * @v len		Length of buffer
	 * @ret len		Length of setting data, or negative error
	 *
	 * The actual length of the setting will be returned even if
	 * the buffer was too small.
	 */
	int ( * fetch ) ( struct settings *settings, struct setting *setting,
			  void *data, size_t len );
	/** Clear settings block
	 *
	 * @v settings		Settings block
	 */
	void ( * clear ) ( struct settings *settings );
};

/** A settings block */
struct settings {
	/** Reference counter */
	struct refcnt *refcnt;
	/** Name */
	const char *name;
	/** Parent settings block */
	struct settings *parent;
	/** Sibling settings blocks */
	struct list_head siblings;
	/** Child settings blocks */
	struct list_head children;
	/** Settings block operations */
	struct settings_operations *op;
	/** Default scope for numerical settings constructed for this block */
	const struct settings_scope *default_scope;
};

/**
 * A setting scope
 *
 * Users can construct tags for settings that are not explicitly known
 * to iPXE using the generic syntax for numerical settings.  For
 * example, the setting name "60" will be interpreted as referring to
 * DHCP option 60 (the vendor class identifier).
 *
 * This creates a potential for namespace collisions, since the
 * interpretation of the numerical description will vary according to
 * the settings block.  When a user attempts to fetch a generic
 * numerical setting, we need to ensure that only the intended
 * settings blocks interpret this numerical description.  (For
 * example, we do not want to attempt to retrieve the subnet mask from
 * SMBIOS, or the system UUID from DHCP.)
 *
 * This potential problem is resolved by including a user-invisible
 * "scope" within the definition of each setting.  Settings blocks may
 * use this to determine whether or not the setting is applicable.
 * Any settings constructed from a numerical description
 * (e.g. "smbios/1.4.0") will be assigned the default scope of the
 * settings block specified in the description (e.g. "smbios"); this
 * provides behaviour matching the user's expectations in most
 * circumstances.
 */
struct settings_scope {
	/** Dummy field
	 *
	 * This is included only to ensure that pointers to different
	 * scopes always compare differently.
	 */
	uint8_t dummy;
} __attribute__ (( packed ));

/**
 * A setting type
 *
 * This represents a type of setting (e.g. string, IPv4 address,
 * etc.).
 */
struct setting_type {
	/** Name
	 *
	 * This is the name exposed to the user (e.g. "string").
	 */
	const char *name;
	/** Parse formatted string to setting value
	 *
	 * @v type		Setting type
	 * @v value		Formatted setting value
	 * @v buf		Buffer to contain raw value
	 * @v len		Length of buffer
	 * @ret len		Length of raw value, or negative error
	 */
	int ( * parse ) ( const struct setting_type *type, const char *value,
			  void *buf, size_t len );
	/** Format setting value as a string
	 *
	 * @v type		Setting type
	 * @v raw		Raw setting value
	 * @v raw_len		Length of raw setting value
	 * @v buf		Buffer to contain formatted value
	 * @v len		Length of buffer
	 * @ret len		Length of formatted value, or negative error
	 */
	int ( * format ) ( const struct setting_type *type, const void *raw,
			   size_t raw_len, char *buf, size_t len );
	/** Convert number to setting value
	 *
	 * @v type		Setting type
	 * @v value		Numeric value
	 * @v buf		Buffer to contain raw value
	 * @v len		Length of buffer
	 * @ret len		Length of raw value, or negative error
	 */
	int ( * denumerate ) ( const struct setting_type *type,
			       unsigned long value,
			       void *buf, size_t len );
	/** Convert setting value to number
	 *
	 * @v type		Setting type
	 * @v raw		Raw setting value
	 * @v raw_len		Length of raw setting value
	 * @v value		Numeric value to fill in
	 * @ret rc		Return status code
	 */
	int ( * numerate ) ( const struct setting_type *type, const void *raw,
			     size_t raw_len, unsigned long *value );
};

/** Configuration setting type table */
#define SETTING_TYPES __table ( struct setting_type, "setting_types" )

/** Declare a configuration setting type */
#define __setting_type __table_entry ( SETTING_TYPES, 01 )

/**
 * A settings applicator
 *
 */
struct settings_applicator {
	/** Apply updated settings
	 *
	 * @ret rc		Return status code
	 */
	int ( * apply ) ( void );
};

/** Settings applicator table */
#define SETTINGS_APPLICATORS \
	__table ( struct settings_applicator, "settings_applicators" )

/** Declare a settings applicator */
#define __settings_applicator __table_entry ( SETTINGS_APPLICATORS, 01 )

/** A built-in setting */
struct builtin_setting {
	/** Setting */
	const struct setting *setting;
	/** Fetch setting value
	 *
	 * @v data		Buffer to fill with setting data
	 * @v len		Length of buffer
	 * @ret len		Length of setting data, or negative error
	 */
	int ( * fetch ) ( void *data, size_t len );
};

/** Built-in settings table */
#define BUILTIN_SETTINGS __table ( struct builtin_setting, "builtin_settings" )

/** Declare a built-in setting */
#define __builtin_setting __table_entry ( BUILTIN_SETTINGS, 01 )

/** Built-in setting scope */
extern const struct settings_scope builtin_scope;

/** IPv6 setting scope */
extern const struct settings_scope ipv6_scope;

/**
 * A generic settings block
 *
 */
struct generic_settings {
	/** Settings block */
	struct settings settings;
	/** List of generic settings */
	struct list_head list;
};

/** A child settings block locator function */
typedef struct settings * ( *get_child_settings_t ) ( struct settings *settings,
						      const char *name );
extern struct settings_operations generic_settings_operations;
extern int generic_settings_store ( struct settings *settings,
				    const struct setting *setting,
				    const void *data, size_t len );
extern int generic_settings_fetch ( struct settings *settings,
				    struct setting *setting,
				    void *data, size_t len );
extern void generic_settings_clear ( struct settings *settings );

extern int register_settings ( struct settings *settings,
			       struct settings *parent, const char *name );
extern void unregister_settings ( struct settings *settings );

extern struct settings * settings_target ( struct settings *settings );
extern int setting_applies ( struct settings *settings,
			     const struct setting *setting );
extern int store_setting ( struct settings *settings,
			   const struct setting *setting,
			   const void *data, size_t len );
extern int fetch_setting ( struct settings *settings,
			   const struct setting *setting,
			   struct settings **origin, struct setting *fetched,
			   void *data, size_t len );
extern int fetch_setting_copy ( struct settings *settings,
				const struct setting *setting,
				struct settings **origin,
				struct setting *fetched, void **data );
extern int fetch_raw_setting ( struct settings *settings,
			       const struct setting *setting,
			       void *data, size_t len );
extern int fetch_raw_setting_copy ( struct settings *settings,
				    const struct setting *setting,
				    void **data );
extern int fetch_string_setting ( struct settings *settings,
				  const struct setting *setting,
				  char *data, size_t len );
extern int fetch_string_setting_copy ( struct settings *settings,
				       const struct setting *setting,
				       char **data );
extern int fetch_ipv4_array_setting ( struct settings *settings,
				      const struct setting *setting,
				      struct in_addr *inp, unsigned int count );
extern int fetch_ipv4_setting ( struct settings *settings,
				const struct setting *setting,
				struct in_addr *inp );
extern int fetch_ipv6_array_setting ( struct settings *settings,
				      const struct setting *setting,
				      struct in6_addr *inp, unsigned int count);
extern int fetch_ipv6_setting ( struct settings *settings,
				const struct setting *setting,
				struct in6_addr *inp );
extern int fetch_int_setting ( struct settings *settings,
			       const struct setting *setting, long *value );
extern int fetch_uint_setting ( struct settings *settings,
				const struct setting *setting,
				unsigned long *value );
extern long fetch_intz_setting ( struct settings *settings,
				 const struct setting *setting );
extern unsigned long fetch_uintz_setting ( struct settings *settings,
					   const struct setting *setting );
extern int fetch_uuid_setting ( struct settings *settings,
				const struct setting *setting,
				union uuid *uuid );
extern void clear_settings ( struct settings *settings );
extern int setting_cmp ( const struct setting *a, const struct setting *b );

extern struct settings * find_child_settings ( struct settings *parent,
					       const char *name );
extern struct settings * autovivify_child_settings ( struct settings *parent,
						     const char *name );
extern const char * settings_name ( struct settings *settings );
extern struct settings * find_settings ( const char *name );
extern struct setting * find_setting ( const char *name );
extern int parse_setting_name ( char *name, get_child_settings_t get_child,
				struct settings **settings,
				struct setting *setting );
extern int setting_name ( struct settings *settings,
			  const struct setting *setting,
			  char *buf, size_t len );
extern int setting_format ( const struct setting_type *type, const void *raw,
			    size_t raw_len, char *buf, size_t len );
extern int setting_parse ( const struct setting_type *type, const char *value,
			   void *buf, size_t len );
extern int setting_numerate ( const struct setting_type *type, const void *raw,
			      size_t raw_len, unsigned long *value );
extern int setting_denumerate ( const struct setting_type *type,
				unsigned long value, void *buf, size_t len );
extern int fetchf_setting ( struct settings *settings,
			    const struct setting *setting,
			    struct settings **origin, struct setting *fetched,
			    char *buf, size_t len );
extern int fetchf_setting_copy ( struct settings *settings,
				 const struct setting *setting,
				 struct settings **origin,
				 struct setting *fetched, char **value );
extern int storef_setting ( struct settings *settings,
			    const struct setting *setting, const char *value );
extern int fetchn_setting ( struct settings *settings,
			    const struct setting *setting,
			    struct settings **origin, struct setting *fetched,
			    unsigned long *value );
extern int storen_setting ( struct settings *settings,
			    const struct setting *setting,
			    unsigned long value );
extern char * expand_settings ( const char *string );

extern const struct setting_type setting_type_string __setting_type;
extern const struct setting_type setting_type_uristring __setting_type;
extern const struct setting_type setting_type_ipv4 __setting_type;
extern const struct setting_type setting_type_ipv6 __setting_type;
extern const struct setting_type setting_type_int8 __setting_type;
extern const struct setting_type setting_type_int16 __setting_type;
extern const struct setting_type setting_type_int32 __setting_type;
extern const struct setting_type setting_type_uint8 __setting_type;
extern const struct setting_type setting_type_uint16 __setting_type;
extern const struct setting_type setting_type_uint32 __setting_type;
extern const struct setting_type setting_type_hex __setting_type;
extern const struct setting_type setting_type_hexhyp __setting_type;
extern const struct setting_type setting_type_hexraw __setting_type;
extern const struct setting_type setting_type_base64 __setting_type;
extern const struct setting_type setting_type_uuid __setting_type;
extern const struct setting_type setting_type_busdevfn __setting_type;
extern const struct setting_type setting_type_dnssl __setting_type;

extern const struct setting
ip_setting __setting ( SETTING_IP, ip );
extern const struct setting
netmask_setting __setting ( SETTING_IP, netmask );
extern const struct setting
gateway_setting __setting ( SETTING_IP, gateway );
extern const struct setting
dns_setting __setting ( SETTING_IP_EXTRA, dns );
extern const struct setting
hostname_setting __setting ( SETTING_HOST, hostname );
extern const struct setting
domain_setting __setting ( SETTING_IP_EXTRA, domain );
extern const struct setting
filename_setting __setting ( SETTING_BOOT, filename );
extern const struct setting
root_path_setting __setting ( SETTING_SANBOOT, root-path );
extern const struct setting
username_setting __setting ( SETTING_AUTH, username );
extern const struct setting
password_setting __setting ( SETTING_AUTH, password );
extern const struct setting
priority_setting __setting ( SETTING_MISC, priority );
extern const struct setting
uuid_setting __setting ( SETTING_HOST, uuid );
extern const struct setting
next_server_setting __setting ( SETTING_BOOT, next-server );
extern const struct setting
mac_setting __setting ( SETTING_NETDEV, mac );
extern const struct setting
busid_setting __setting ( SETTING_NETDEV, busid );
extern const struct setting
user_class_setting __setting ( SETTING_HOST_EXTRA, user-class );

/**
 * Initialise a settings block
 *
 * @v settings		Settings block
 * @v op		Settings block operations
 * @v refcnt		Containing object reference counter, or NULL
 * @v default_scope	Default scope
 */
static inline void settings_init ( struct settings *settings,
				   struct settings_operations *op,
				   struct refcnt *refcnt,
				   const struct settings_scope *default_scope ){
	INIT_LIST_HEAD ( &settings->siblings );
	INIT_LIST_HEAD ( &settings->children );
	settings->op = op;
	settings->refcnt = refcnt;
	settings->default_scope = default_scope;
}

/**
 * Initialise a settings block
 *
 * @v generics		Generic settings block
 * @v refcnt		Containing object reference counter, or NULL
 */
static inline void generic_settings_init ( struct generic_settings *generics,
					   struct refcnt *refcnt ) {
	settings_init ( &generics->settings, &generic_settings_operations,
			refcnt, NULL );
	INIT_LIST_HEAD ( &generics->list );
}

/**
 * Delete setting
 *
 * @v settings		Settings block
 * @v setting		Setting to delete
 * @ret rc		Return status code
 */
static inline int delete_setting ( struct settings *settings,
				   const struct setting *setting ) {
	return store_setting ( settings, setting, NULL, 0 );
}

/**
 * Check existence of predefined setting
 *
 * @v settings		Settings block, or NULL to search all blocks
 * @v setting		Setting to fetch
 * @ret exists		Setting exists
 */
static inline int setting_exists ( struct settings *settings,
				   const struct setting *setting ) {
	return ( fetch_setting ( settings, setting, NULL, NULL,
				 NULL, 0 ) >= 0 );
}

#endif /* _IPXE_SETTINGS_H */
