
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

#define ALLOCNUM 1
bool is_target_alloc_site(unsigned long curr_ip) {
    unsigned long alloc_site_array[ALLOCNUM] = {
            0xffffffff81da2b5d,  // qrtr_tun_write_iter
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


//Dump of assembler code for function free_msg:
//....
//0xffffffff8149c5fc <+28>:	call   0xffffffff812efff0 <kfree>
//0xffffffff8149c601 <+33>:	test   %rbx,%rbx
//0xffffffff8149c604 <+36>:	je     0xffffffff8149c61e <free_msg+62>


SEC("kprobe/free_msg+0x1c")
int probe_kfree_msg(struct pt_regs* ctx)
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


        // // free memory, not recycle
        // bpf_cache_free(alloc_addr);



        // err = bpf_override_return(ctx, (unsigned long)0);
    }

    return 0;
}



//Dump of assembler code for function load_msg:
//0xffffffff8149c1d0 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff8149c204 <+52>:	call   0xffffffff812f2990 <__kmalloc>
//0xffffffff8149c209 <+57>:	mov    %rax,-0x38(%rbp)
//0xffffffff8149c20d <+61>:	test   %rax,%rax
//0xffffffff8149c210 <+64>:	je     0xffffffff8149c38e <load_msg+446>


// python3 -c 'print(hex(0xffffffff81da2b7d - 0xffffffff81da2b40))'


SEC("kprobe/load_msg+0x34")
int probe_kmalloc_msg(struct pt_regs *ctx)
{
    u64 ip = 0;
    u64 *pv;
    u64 alloc_size = 0;
    u64 alloc_addr = ctx->di;
    u32 gfp_flags = (u32) ctx->si;
    u64 key = 0;
    u32 uid = 0;
    u32 zone = 0;
    u64 cache_addr = 0;
    int err = 0;

    ip = ctx->ip;
    // BPF_KPROBE_READ_RET_IP(ip, ctx);
    // if (is_target_alloc_site(ip)) {
    // get key
    alloc_size = PT_REGS_PARM1(ctx);
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

    // err = bpf_override_return(ctx, (unsigned long)alloc_addr);
    // }
    bpf_jmp_next(ctx, (u64) ctx->ip + 4, alloc_addr);

    return 0;
}



char _license[] SEC("license") = "GPL";
