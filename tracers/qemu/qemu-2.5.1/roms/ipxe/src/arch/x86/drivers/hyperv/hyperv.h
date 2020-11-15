#ifndef _HYPERV_H
#define _HYPERV_H

/** @file
 *
 * Hyper-V driver
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** Get vendor identification */
#define HV_CPUID_VENDOR_ID 0x40000000UL

/** Get interface identification */
#define HV_CPUID_INTERFACE_ID 0x40000001UL

/** Get hypervisor identification */
#define HV_CPUID_HYPERVISOR_ID 0x40000002UL

/** Get hypervisor features */
#define HV_CPUID_FEATURES 0x40000003UL

/** SynIC MSRs are available */
#define HV_FEATURES_AVAIL_SYNIC_MSR 0x00000004UL

/** Hypercall MSRs are available */
#define HV_FEATURES_AVAIL_HYPERCALL_MSR 0x00000020UL

/** Guest may post messages */
#define HV_FEATURES_PERM_POST_MESSAGES 0x00000010UL

/** Guest may signal events */
#define HV_FEATURES_PERM_SIGNAL_EVENTS 0x00000020UL

/** Guest OS identity MSR */
#define HV_X64_MSR_GUEST_OS_ID 0x40000000UL

/** Hypercall page MSR */
#define HV_X64_MSR_HYPERCALL 0x40000001UL

/** SynIC control MSR */
#define HV_X64_MSR_SCONTROL 0x40000080UL

/** SynIC event flags page MSR */
#define HV_X64_MSR_SIEFP 0x40000082UL

/** SynIC message page MSR */
#define HV_X64_MSR_SIMP 0x40000083UL

/** SynIC end of message MSR */
#define HV_X64_MSR_EOM 0x40000084UL

/** SynIC interrupt source MSRs */
#define HV_X64_MSR_SINT(x) ( 0x40000090UL + (x) )

#endif /* _HYPERV_H */
