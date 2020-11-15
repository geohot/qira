#ifndef __LIBHVCALL_H__
#define __LIBHVCALL_H__

#define H_SUCCESS		0
#define H_HARDWARE		-1

#define H_GET_TCE		0x1C
#define H_PUT_TCE		0x20
#define H_LOGICAL_CI_LOAD	0x3c
#define H_LOGICAL_CI_STORE	0x40
#define H_GET_TERM_CHAR		0x54
#define H_PUT_TERM_CHAR		0x58
#define H_REG_CRQ		0xFC
#define H_FREE_CRQ		0x100
#define H_SEND_CRQ		0x108
#define H_REGISTER_LOGICAL_LAN	0x114
#define H_FREE_LOGICAL_LAN	0x118
#define H_ADD_LOGICAL_LAN_BUFFER 0x11C
#define H_SEND_LOGICAL_LAN	0x120

/* KVM specific ones */
#define KVMPPC_HCALL_BASE       0xf000
#define KVMPPC_H_RTAS           (KVMPPC_HCALL_BASE + 0x0)
#define KVMPPC_H_LOGICAL_MEMOP  (KVMPPC_HCALL_BASE + 0x1)
/* Client Architecture support */
#define KVMPPC_H_CAS            (KVMPPC_HCALL_BASE + 0x2)
#define KVMPPC_H_RTAS_UPDATE    (KVMPPC_HCALL_BASE + 0x3)
#define KVMPPC_H_REPORT_MC_ERR  (KVMPPC_HCALL_BASE + 0x4)
#define KVMPPC_HCALL_MAX        KVMPPC_H_NMI_MCE

#ifndef __ASSEMBLY__

extern long hv_generic(unsigned long opcode, ...);

extern void hv_putchar(char c, int hvtermno);
extern char hv_getchar(int hvtermno);
extern char hv_haschar(int hvtermno);
extern void get_print_banner(unsigned long addr);

extern int hv_send_crq(unsigned int unit, uint64_t *msgaddr);

static inline long hv_reg_crq(unsigned int unit, unsigned long qaddr,
			      unsigned long qsize)
{
	return hv_generic(H_REG_CRQ, unit, qaddr, qsize);
}

static inline void hv_free_crq(unsigned int unit)
{
	hv_generic(H_FREE_CRQ, unit);
}

extern long  hv_send_logical_lan(unsigned long unit_address,
				 unsigned long desc1, unsigned long desc2,
				 unsigned long desc3, unsigned long desc4,
				 unsigned long desc5, unsigned long desc6);

static inline long h_register_logical_lan(unsigned long unit_address,
					  unsigned long buf_list,
					  unsigned long rec_q,
					  unsigned long filter_list,
					  unsigned long mac_address)
{
	return hv_generic(H_REGISTER_LOGICAL_LAN, unit_address,
			  buf_list, rec_q, filter_list, mac_address);
}

static inline long h_free_logical_lan(unsigned long unit_address)
{
	return hv_generic(H_FREE_LOGICAL_LAN, unit_address);
}

static inline long h_add_logical_lan_buffer(unsigned long unit_address,
					    unsigned long buffer)
{
	return hv_generic(H_ADD_LOGICAL_LAN_BUFFER, unit_address, buffer);
}

#define HV_RTAS_MAX_ARGRET	5

struct hv_rtas_call {
	uint32_t token;
	uint32_t nargs;
	uint32_t nrets;
	uint32_t argret[HV_RTAS_MAX_ARGRET];
};

static inline unsigned long h_rtas(struct hv_rtas_call *rtas_buf)
{
	return hv_generic(KVMPPC_H_RTAS, (unsigned long)rtas_buf);
}

extern unsigned long hv_logical_ci_load(unsigned long size, unsigned long addr);
extern unsigned long hv_logical_ci_store(unsigned long size, unsigned long addr,
					 unsigned long value);

extern unsigned long hv_logical_memop(unsigned long dst, unsigned long src,
				      unsigned long esize, unsigned long count,
				      unsigned long op);
extern int patch_broken_sc1(void *start, void *end, uint32_t *test_ins);

extern unsigned long hv_cas(unsigned long vec, unsigned long buf,
			unsigned long size);

#endif /* __ASSEMBLY__ */

#endif /* __LIBHVCALL_H__ */
