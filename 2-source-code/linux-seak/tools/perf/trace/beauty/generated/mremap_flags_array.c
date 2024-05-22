static const char *mremap_flags[] = {
	[ilog2(1) + 1] = "MAYMOVE",
#ifndef MREMAP_MAYMOVE
#define MREMAP_MAYMOVE 1
#endif
	[ilog2(2) + 1] = "FIXED",
#ifndef MREMAP_FIXED
#define MREMAP_FIXED 2
#endif
	[ilog2(4) + 1] = "DONTUNMAP",
#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif
};
