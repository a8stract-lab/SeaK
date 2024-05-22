static const char *mmap_prot[] = {
	[ilog2(0x1) + 1] = "READ",
#ifndef PROT_READ
#define PROT_READ 0x1
#endif
	[ilog2(0x2) + 1] = "WRITE",
#ifndef PROT_WRITE
#define PROT_WRITE 0x2
#endif
	[ilog2(0x4) + 1] = "EXEC",
#ifndef PROT_EXEC
#define PROT_EXEC 0x4
#endif
	[ilog2(0x8) + 1] = "SEM",
#ifndef PROT_SEM
#define PROT_SEM 0x8
#endif
	[ilog2(0x01000000) + 1] = "GROWSDOWN",
#ifndef PROT_GROWSDOWN
#define PROT_GROWSDOWN 0x01000000
#endif
	[ilog2(0x02000000) + 1] = "GROWSUP",
#ifndef PROT_GROWSUP
#define PROT_GROWSUP 0x02000000
#endif
};
