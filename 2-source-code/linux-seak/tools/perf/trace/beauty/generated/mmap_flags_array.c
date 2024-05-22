static const char *mmap_flags[] = {
	[ilog2(0x40) + 1] = "32BIT",
#ifndef MAP_32BIT
#define MAP_32BIT 0x40
#endif
	[ilog2(0x01) + 1] = "SHARED",
#ifndef MAP_SHARED
#define MAP_SHARED 0x01
#endif
	[ilog2(0x02) + 1] = "PRIVATE",
#ifndef MAP_PRIVATE
#define MAP_PRIVATE 0x02
#endif
	[ilog2(0x10) + 1] = "FIXED",
#ifndef MAP_FIXED
#define MAP_FIXED 0x10
#endif
	[ilog2(0x20) + 1] = "ANONYMOUS",
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif
	[ilog2(0x008000) + 1] = "POPULATE",
#ifndef MAP_POPULATE
#define MAP_POPULATE 0x008000
#endif
	[ilog2(0x010000) + 1] = "NONBLOCK",
#ifndef MAP_NONBLOCK
#define MAP_NONBLOCK 0x010000
#endif
	[ilog2(0x020000) + 1] = "STACK",
#ifndef MAP_STACK
#define MAP_STACK 0x020000
#endif
	[ilog2(0x040000) + 1] = "HUGETLB",
#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x040000
#endif
	[ilog2(0x080000) + 1] = "SYNC",
#ifndef MAP_SYNC
#define MAP_SYNC 0x080000
#endif
	[ilog2(0x100000) + 1] = "FIXED_NOREPLACE",
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
	[ilog2(0x0100) + 1] = "GROWSDOWN",
#ifndef MAP_GROWSDOWN
#define MAP_GROWSDOWN 0x0100
#endif
	[ilog2(0x0800) + 1] = "DENYWRITE",
#ifndef MAP_DENYWRITE
#define MAP_DENYWRITE 0x0800
#endif
	[ilog2(0x1000) + 1] = "EXECUTABLE",
#ifndef MAP_EXECUTABLE
#define MAP_EXECUTABLE 0x1000
#endif
	[ilog2(0x2000) + 1] = "LOCKED",
#ifndef MAP_LOCKED
#define MAP_LOCKED 0x2000
#endif
	[ilog2(0x4000) + 1] = "NORESERVE",
#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0x4000
#endif
};
