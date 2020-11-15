ACPI_EXTRACT_ALL_CODE ssdp_pcihp_aml

DefinitionBlock ("ssdt-pcihp.aml", "SSDT", 0x01, "BXPC", "BXSSDTPCIHP", 0x1)
{

/****************************************************************
 * PCI hotplug
 ****************************************************************/

    /* Objects supplied by DSDT */
    External(\_SB.PCI0, DeviceObj)
    External(\_SB.PCI0.PCEJ, MethodObj)

    Scope(\_SB.PCI0) {

        /* Bulk generated PCI hotplug devices */
        ACPI_EXTRACT_DEVICE_START ssdt_pcihp_start
        ACPI_EXTRACT_DEVICE_END ssdt_pcihp_end
        ACPI_EXTRACT_DEVICE_STRING ssdt_pcihp_name

        // Method _EJ0 can be patched by BIOS to EJ0_
        // at runtime, if the slot is detected to not support hotplug.
        // Extract the offset of the address dword and the
        // _EJ0 name to allow this patching.
        Device(SAA) {
            ACPI_EXTRACT_NAME_BYTE_CONST ssdt_pcihp_id
            Name(_SUN, 0xAA)
            ACPI_EXTRACT_NAME_DWORD_CONST ssdt_pcihp_adr
            Name(_ADR, 0xAA0000)
            ACPI_EXTRACT_METHOD_STRING ssdt_pcihp_ej0
            Method(_EJ0, 1) {
                PCEJ(_SUN)
            }
        }
    }
}
