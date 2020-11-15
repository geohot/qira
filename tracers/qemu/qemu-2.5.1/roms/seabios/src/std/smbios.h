#ifndef __SMBIOS_H
#define __SMBIOS_H

#include "types.h" // u32

/* SMBIOS entry point -- must be written to a 16-bit aligned address
   between 0xf0000 and 0xfffff.
 */
struct smbios_entry_point {
    char anchor_string[4];
    u8 checksum;
    u8 length;
    u8 smbios_major_version;
    u8 smbios_minor_version;
    u16 max_structure_size;
    u8 entry_point_revision;
    u8 formatted_area[5];
    char intermediate_anchor_string[5];
    u8 intermediate_checksum;
    u16 structure_table_length;
    u32 structure_table_address;
    u16 number_of_structures;
    u8 smbios_bcd_revision;
} PACKED;

/* This goes at the beginning of every SMBIOS structure. */
struct smbios_structure_header {
    u8 type;
    u8 length;
    u16 handle;
} PACKED;

/* SMBIOS type 0 - BIOS Information */
struct smbios_type_0 {
    struct smbios_structure_header header;
    u8 vendor_str;
    u8 bios_version_str;
    u16 bios_starting_address_segment;
    u8 bios_release_date_str;
    u8 bios_rom_size;
    u8 bios_characteristics[8];
    u8 bios_characteristics_extension_bytes[2];
    u8 system_bios_major_release;
    u8 system_bios_minor_release;
    u8 embedded_controller_major_release;
    u8 embedded_controller_minor_release;
} PACKED;

/* SMBIOS type 1 - System Information */
struct smbios_type_1 {
    struct smbios_structure_header header;
    u8 manufacturer_str;
    u8 product_name_str;
    u8 version_str;
    u8 serial_number_str;
    u8 uuid[16];
    u8 wake_up_type;
    u8 sku_number_str;
    u8 family_str;
} PACKED;

/* SMBIOS type 3 - System Enclosure (v2.3) */
struct smbios_type_3 {
    struct smbios_structure_header header;
    u8 manufacturer_str;
    u8 type;
    u8 version_str;
    u8 serial_number_str;
    u8 asset_tag_number_str;
    u8 boot_up_state;
    u8 power_supply_state;
    u8 thermal_state;
    u8 security_status;
    u32 oem_defined;
    u8 height;
    u8 number_of_power_cords;
    u8 contained_element_count;
    // contained elements follow
} PACKED;

/* SMBIOS type 4 - Processor Information (v2.0) */
struct smbios_type_4 {
    struct smbios_structure_header header;
    u8 socket_designation_str;
    u8 processor_type;
    u8 processor_family;
    u8 processor_manufacturer_str;
    u32 processor_id[2];
    u8 processor_version_str;
    u8 voltage;
    u16 external_clock;
    u16 max_speed;
    u16 current_speed;
    u8 status;
    u8 processor_upgrade;
    u16 l1_cache_handle;
    u16 l2_cache_handle;
    u16 l3_cache_handle;
} PACKED;

/* SMBIOS type 16 - Physical Memory Array
 *   Associated with one type 17 (Memory Device).
 */
struct smbios_type_16 {
    struct smbios_structure_header header;
    u8 location;
    u8 use;
    u8 error_correction;
    u32 maximum_capacity;
    u16 memory_error_information_handle;
    u16 number_of_memory_devices;
} PACKED;

/* SMBIOS type 17 - Memory Device
 *   Associated with one type 19
 */
struct smbios_type_17 {
    struct smbios_structure_header header;
    u16 physical_memory_array_handle;
    u16 memory_error_information_handle;
    u16 total_width;
    u16 data_width;
    u16 size;
    u8 form_factor;
    u8 device_set;
    u8 device_locator_str;
    u8 bank_locator_str;
    u8 memory_type;
    u16 type_detail;
} PACKED;

/* SMBIOS type 19 - Memory Array Mapped Address */
struct smbios_type_19 {
    struct smbios_structure_header header;
    u32 starting_address;
    u32 ending_address;
    u16 memory_array_handle;
    u8 partition_width;
} PACKED;

/* SMBIOS type 20 - Memory Device Mapped Address */
struct smbios_type_20 {
    struct smbios_structure_header header;
    u32 starting_address;
    u32 ending_address;
    u16 memory_device_handle;
    u16 memory_array_mapped_address_handle;
    u8 partition_row_position;
    u8 interleave_position;
    u8 interleaved_data_depth;
} PACKED;

/* SMBIOS type 32 - System Boot Information */
struct smbios_type_32 {
    struct smbios_structure_header header;
    u8 reserved[6];
    u8 boot_status;
} PACKED;

/* SMBIOS type 127 -- End-of-table */
struct smbios_type_127 {
    struct smbios_structure_header header;
} PACKED;

#endif // smbios.h
