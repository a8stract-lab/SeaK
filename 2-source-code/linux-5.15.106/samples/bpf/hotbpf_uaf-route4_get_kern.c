

#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// sudo cat /sys/kernel/debug/tracing/trace_pipe

#define ERROR_CODE 0xffffffffdeadbeef

#define VMALLOC_FREE_PATH "/proc/vmalloc_free"

#define ___GFP_DMA		0x01u
#define ___GFP_RECLAIMABLE	0x10u
#define ___GFP_ACCOUNT		0x400000u


struct kmem_cache {
        unsigned long    cpu_slab;             /*     0     8 */
        unsigned int               flags;                /*     8     4 */

        /* XXX 4 bytes hole, try to pack */

        long unsigned int          min_partial;          /*    16     8 */
        unsigned int               size;                 /*    24     4 */
        unsigned int               object_size;          /*    28     4 */
        unsigned long   reciprocal_size;      /*    32     8 */

        /* XXX last struct has 2 bytes of padding */

        unsigned int               offset;               /*    40     4 */
        unsigned int               cpu_partial;          /*    44     4 */
        unsigned int oo;              /*    48     4 */
        unsigned int max;             /*    52     4 */
        unsigned int min;             /*    56     4 */
        unsigned int                      allocflags;           /*    60     4 */
        /* --- cacheline 1 boundary (64 bytes) --- */
        int                        refcount;             /*    64     4 */

        /* size: 8408, cachelines: 132, members: 26 */
        /* sum members: 8392, holes: 4, sum holes: 16 */
        /* paddings: 1, sum paddings: 2 */
        /* last cacheline: 24 bytes */
};

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 40960);
//     __type(key, u64);  // index: ip+size+priv
//     __type(value, u64); // addr(stack top)
// } infree_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 40960);
    __type(key, u64); // addr
    __type(value, u64); // index: ip+size+priv+
} addr2key SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 40960);
    __type(key, u64); 	// addr 
    __type(value, u64); // next addr
} key2cache SEC(".maps");

#define ALLOCNUM 6
bool is_target_alloc_site(unsigned long curr_ip) {
	unsigned long alloc_site_array[ALLOCNUM] = {
		0xffffffff81b4149e, // route4_change
		0xffffffff81b414d7,
		0xffffffff81b416f4,
		0xffffffff81b31032, // mq_init
		0xffffffff81b40e7e, // rout4_init
		0xffffffff81b37085, // tcf_chain_create
		// 0xffffffff81ba2fb3, // ip_set_alloc, kvmalloc_node
	};
	int cnt = 0;
	for (cnt = 0; cnt < ALLOCNUM; cnt++) {
		if (curr_ip - alloc_site_array[cnt] < 0x200) {
			return true;
		}
			
	}
	return false;
}

// spinlock_t lock;
// ip size priv zone
u64 get_key(u64 ip, u32 size, u32 uid, u32 zone)
{
	u64 ret = zone << 59;
	u64 priv = (uid == 0 ? 1 : 0);
	if (priv == 1)
		ret = ret | (1 << 62);
	ret = ret | (size << 31);
	ret = ret & ip;
	return ret;
}

u32 get_size(u32 size)
{
	u32 ret = (size + 4096) / 4096;
	return (ret + 1) * 4096;
}

u32 get_zone(u32 gfp_flags)
{
	u32 ret = 0;
	if (gfp_flags & ___GFP_DMA) {
		ret = 1;
	} else if (gfp_flags & ___GFP_RECLAIMABLE) {
		ret = 2;
	} else if (gfp_flags & ___GFP_ACCOUNT) {
		ret = 3;
	}
	return ret;
}

// ffffffff81b40e10 <route4_delete_filter_work>:
// ...
// ffffffff81b40e57:       4c 89 e7                mov    %r12,%rdi
// ffffffff81b40e5a:       e8 b1 f1 7a ff          call   ffffffff812f0010 <kfree> ffffffff81b40e5b: R_X86_64_PLT32        kfree-0x4
// ffffffff81b40e5f:       e8 6c b3 fa ff          call   ffffffff81aec1d0 <rtnl_unlock>   ffffffff81b40e60: R_X86_64_PLT32        rtnl_unlock-0x4
// python3 -c 'print(hex(0xffffffff81b40e5a-0xffffffff81b40e10))'


SEC("kprobe/route4_delete_filter_work+0x4a")
int probe_kfree(struct pt_regs* ctx) 
{
	u64 ip = 0;
	u64 pid = 0;
	u64 ip_size_priv = 0;
	u64 alloc_size = 0;
	u64 alloc_addr = PT_REGS_PARM1(ctx);
	int err = 0;

	// check if it is a hotbpf object
	u64 *pkey = bpf_map_lookup_elem(&addr2key, &alloc_addr);
	if (pkey) {
		err = bpf_map_delete_elem(&addr2key, &alloc_addr);
		if (err < 0) {
			bpf_printk("kfree addr2key delete failed: %d\n", err);
			return err;
		}

		// cancel guard page
		u64 *pcache = bpf_map_lookup_elem(&key2cache, pkey);
		if (pcache) {
			struct kmem_cache *cache = (struct kmem_cache*)(*pcache);
			alloc_size = BPF_CORE_READ(cache, size);
			bpf_printk("alloc_size: %016lx  %016lx, %lu\n", alloc_addr, *pcache, alloc_size);
			err = bpf_set_pt_present((alloc_addr + alloc_size - 4096), 1);
			if (err == 0) {
				// bpf_printk("cancel pt guard page failed: %016lx,%lu\n", alloc_addr, alloc_size);
			}
		}


		// free memory, not recycle
		// bpf_cache_free(alloc_addr);

		
		
		// err = bpf_override_return(ctx, (unsigned long)0);
	}
	
	return 0;
}

// void *kmem_cache_alloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)

// ffffffff81b413f0 <route4_change>:
// ....
// ffffffff81b414b9:       be c0 0d 00 00          mov    $0xdc0,%esi
// ffffffff81b414be:       e8 cd 1d 7b ff          call   ffffffff812f3290 <kmem_cache_alloc_trace>        ffffffff81b414bf: R_X86_64_PLT32        kmem_cache_alloc_trace-0x4
// ffffffff81b414c3:       48 89 c3                mov    %rax,%rbx
// python3 -c 'print(hex(0xffffffff81b414be-0xffffffff81b413f0))'

SEC("kprobe/route4_change+0xce")
int probe_kmalloc(struct pt_regs *ctx)
{
	u64 ip = 0;
	u64 *pv;
	u64 alloc_size = 0;
	u64 alloc_addr = ctx->dx;
	u32 gfp_flags = (u32) ctx->si;
	u64 key = 0;
	u32 uid = 0;
	u32 zone = 0;
	u64 cache_addr = 0;
	int err = 0;
	struct kmem_cache *cache;
	ip = ctx->ip;
	// BPF_KPROBE_READ_RET_IP(ip, ctx);
	// if (is_target_alloc_site(ip)) {
		// get key
		cache = (struct kmem_cache*) PT_REGS_PARM1(ctx);
		alloc_size = BPF_CORE_READ(cache, size);
		alloc_size = get_size(alloc_size);
		gfp_flags = (u32) PT_REGS_PARM2(ctx);
		zone = get_zone(gfp_flags);
		uid = bpf_get_current_uid_gid() >> 32;
		key = get_key(ip, alloc_size, uid, zone);

		// if there is a slab cache
		u64 *pcache = bpf_map_lookup_elem(&key2cache, &key);
		if (!pcache) {
			cache_addr = bpf_create_slab_cache(alloc_size, gfp_flags, key);
			if (!cache_addr) {
				bpf_printk("probe create cache failed\n");
				return -1;
			}
			err = bpf_map_update_elem(&key2cache, &key, &cache_addr, BPF_ANY);
			if (err < 0) {
				bpf_printk("update key2cache failed: %d\n", err);
				return err;
			}
		} else {
			cache_addr = *pcache;
		}

		// alloc a new object
		alloc_addr = bpf_cache_alloc(cache_addr, gfp_flags);
		if (alloc_addr == 0) {
			bpf_printk("probe kmalloc failed\n");
			return -1;
		}

		// add new object to inuse map for free.
		err = bpf_map_update_elem(&addr2key, &alloc_addr, &key, BPF_ANY);
		if (err < 0) {
			bpf_printk("addr2key update failed: %d\n", err);
			return err;
		}

		// set guard page
		err = bpf_set_pt_present((alloc_addr + alloc_size - 4096), 1);
		if (err == 0) {
			// bpf_printk("set pt guard page failed: %016lx,%lu\n", alloc_addr, alloc_size);
		}

	// 	err = bpf_override_return(ctx, (unsigned long)alloc_addr);
	// }
	bpf_jmp_next(ctx, (u64) ctx->ip + 4, alloc_addr);

	return 0;
}


// SEC("kprobe/__kmalloc")
// int probe___kmalloc(struct pt_regs *ctx)
// {
// 	u64 ip = 0;
// 	u64 *pv;
// 	u64 alloc_size = 0;
// 	u64 alloc_addr = ctx->di;
// 	u32 gfp_flags = (u32) ctx->si;
// 	u64 key = 0;
// 	u32 uid = 0;
// 	u32 zone = 0;
// 	u64 cache_addr = 0;
// 	int err = 0;

// 	BPF_KPROBE_READ_RET_IP(ip, ctx);
// 	if (is_target_alloc_site(ip)) {
// 		// get key
// 		alloc_size = PT_REGS_PARM1(ctx);
// 		alloc_size = get_size(alloc_size);
// 		gfp_flags = (u32) PT_REGS_PARM2(ctx);
// 		zone = get_zone(gfp_flags);
// 		uid = bpf_get_current_uid_gid() >> 32;
// 		key = get_key(ip, alloc_size, uid, zone);

// 		// if there is a slab cache
// 		u64 *pcache = bpf_map_lookup_elem(&key2cache, &key);
// 		if (!pcache) {
// 			cache_addr = bpf_create_slab_cache(alloc_size, gfp_flags, key);
// 			if (!cache_addr) {
// 				bpf_printk("probe create cache failed\n");
// 				return -1;
// 			}
// 			err = bpf_map_update_elem(&key2cache, &key, &cache_addr, BPF_ANY);
// 			if (err < 0) {
// 				bpf_printk("update key2cache failed: %d\n", err);
// 				return err;
// 			}
// 		} else {
// 			cache_addr = *pcache;
// 		}

// 		// alloc a new object
// 		alloc_addr = bpf_cache_alloc(cache_addr, gfp_flags);
// 		if (alloc_addr == 0) {
// 			bpf_printk("probe kmalloc failed\n");
// 			return -1;
// 		}

// 		// add new object to inuse map for free.
// 		err = bpf_map_update_elem(&addr2key, &alloc_addr, &key, BPF_ANY);
// 		if (err < 0) {
// 			bpf_printk("addr2key update failed: %d\n", err);
// 			return err;
// 		}

// 		// set guard page
// 		err = bpf_set_pt_present((alloc_addr + alloc_size - 4096), 1);
// 		if (err == 0) {
// 			// bpf_printk("set pt guard page failed: %016lx,%lu\n", alloc_addr, alloc_size);
// 		}

// 		err = bpf_override_return(ctx, (unsigned long)alloc_addr);
// 	}

// 	return 0;
// }


char _license[] SEC("license") = "GPL";
