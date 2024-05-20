#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

//  kmem_cache_alloc_trace+0x15b/0x780 mm/slab.c:3551
//  kmalloc include/linux/slab.h:556 [inline]
//  kzalloc include/linux/slab.h:670 [inline]
//  nf_tables_newtable+0x27f/0x14e0 net/netfilter/nf_tables_api.c:979
//  nfnetlink_rcv_batch+0xc75/0x15b0 net/netfilter/nfnetlink.c:433

//  kfree+0x108/0x2c0 mm/slab.c:3757
//  nf_tables_table_destroy.isra.61+0xd0/0x110 net/netfilter/nf_tables_api.c:1152
//  nft_commit_release net/netfilter/nf_tables_api.c:6798 [inline]
//  nf_tables_trans_destroy_work+0x45c/0x6e0 net/netfilter/nf_tables_api.c:6848


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
            0xffffffff81b81b4f  // nf_tables_newtable
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

// ffffffff81b79a30 <nf_tables_table_destroy>:
// ...
// ffffffff81b79a78:       48 8b 7b 08             mov    0x8(%rbx),%rdi
// ffffffff81b79a7c:       e8 8f 65 77 ff          call   ffffffff812f0010 <kfree> ffffffff81b79a7d: R_X86_64_PLT32        kfree-0x4
// ffffffff81b79a81:       48 8b 5d f8             mov    -0x8(%rbp),%rbx
// python3 -c 'print(hex(0xffffffff81b79a7c-0xffffffff81b79a30 ))'


SEC("kprobe/nf_tables_table_destroy+0x4c")
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
            //bpf_printk("alloc_size: %016lx  %016lx, %lu\n", alloc_addr, *pcache, alloc_size);
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
// SEC("kprobe/kmem_cache_alloc_trace")


// ffffffff81b818c0 <nf_tables_newtable>:
// ...
// ffffffff81b81b67:       4c 89 55 98             mov    %r10,-0x68(%rbp)
// ffffffff81b81b6b:       4c 89 4d 90             mov    %r9,-0x70(%rbp)
// ffffffff81b81b6f:       e8 1c 17 77 ff          call   ffffffff812f3290 <kmem_cache_alloc_trace>        ffffffff81b81b70: R_X86_64_PLT32        kmem_cache_alloc_trace-0x4
// ffffffff81b81b74:       49 89 c7                mov    %rax,%r15
// python3 -c 'print(hex(0xffffffff81b81b6f-0xffffffff81b818c0))'

SEC("kprobe/nf_tables_newtable+0x2af")
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

    // err = bpf_override_return(ctx, (unsigned long)alloc_addr);

    bpf_jmp_next(ctx, (u64) ctx->ip + 4, alloc_addr);
    // }

    return 0;
}




SEC("kprobe/device_release+0x21")
int probe_kfree1(struct pt_regs* ctx)
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
            //bpf_printk("alloc_size: %016lx  %016lx, %lu\n", alloc_addr, *pcache, alloc_size);
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
// SEC("kprobe/kmem_cache_alloc_trace")


// ffffffff81d06f20 <hci_conn_add>:
// ....
// ffffffff81d06f4e:       be c0 0d 00 00          mov    $0xdc0,%esi
// ffffffff81d06f53:       e8 38 c3 5e ff          call   ffffffff812f3290 <kmem_cache_alloc_trace>        ffffffff81d06f54: R_X86_64_PLT32        kmem_cache_alloc_trace-0x4
// ffffffff81d06f58:       49 89 c4                mov    %rax,%r12
// python3 -c 'print(hex(0xffffffff81d06f58-0xffffffff81d06f20))'

SEC("kprobe/hci_conn_add+0x38")
int probe_kmalloc1(struct pt_regs *ctx)
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

    // err = bpf_override_return(ctx, (unsigned long)alloc_addr);

    bpf_jmp_next(ctx, (u64) ctx->ip + 4, alloc_addr);
    // }

    return 0;
}



SEC("kprobe/__vb2_queue_free+0x2c4")
int probe_kfree2(struct pt_regs* ctx)
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
            //bpf_printk("alloc_size: %016lx  %016lx, %lu\n", alloc_addr, *pcache, alloc_size);
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



// ffffffff819a4830 <__vb2_queue_alloc>:
// ...
// ffffffff819a4885:       be c0 0d 00 00          mov    $0xdc0,%esi
// ffffffff819a488a:       e8 21 e1 94 ff          call   ffffffff812f29b0 <__kmalloc>     ffffffff819a488b: R_X86_64_PLT32        __kmalloc-0x4
// ffffffff819a488f:       49 89 c4                mov    %rax,%r12
// python3 -c 'print(hex(0xffffffff819a488a-0xffffffff819a4830))'

SEC("kprobe/__vb2_queue_alloc+0x5a")
int probe_kmalloc2(struct pt_regs *ctx)
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

    // 	err = bpf_override_return(ctx, (unsigned long)alloc_addr);
    // }

    bpf_jmp_next(ctx, (u64) ctx->ip + 4, alloc_addr);

    return 0;
}



SEC("kprobe/_destroy_id+0x18f")
int probe_kfree3(struct pt_regs* ctx)
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
            //bpf_printk("alloc_size: %016lx  %016lx, %lu\n", alloc_addr, *pcache, alloc_size);
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

// ffffffff81a6d620 <__rdma_create_id>:
// ...
// ffffffff81a6d65d:       44 89 45 d0             mov    %r8d,-0x30(%rbp)
// ffffffff81a6d661:       e8 2a 5c 88 ff          call   ffffffff812f3290 <kmem_cache_alloc_trace>        ffffffff81a6d662: R_X86_64_PLT32        kmem_cache_alloc_trace-0x4
// ffffffff81a6d666:       48 85 c0                test   %rax,%rax
// python3 -c 'print(hex(0xffffffff81a6d661-0xffffffff81a6d620))'


SEC("kprobe/__rdma_create_id+0x41")
int probe_kmalloc3(struct pt_regs *ctx)
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

SEC("kprobe/l2cap_chan_create+0x1d")
int probe_kmalloc4(struct pt_regs *ctx)
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
    struct kmem_cache *cache;

    // BPF_KPROBE_READ_RET_IP(ip, ctx);
    ip = ctx->ip;
    // if (is_target_alloc_site(ip)) {
    // get ip_size_priv
    // alloc_size = PT_REGS_PARM1(ctx);
    cache = (struct kmem_cache*) PT_REGS_PARM1(ctx);
    alloc_size = BPF_CORE_READ(cache, size);
    // bpf_printk("======alloc_size: %0lx========\n", alloc_size);

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
    bpf_jmp_next(ctx, (u64) ctx->ip + 4, alloc_addr);
    // }
    return 0;
}




// ffffffff81d2cb80 <l2cap_chan_put>:
// ....
// ffffffff81d2cc19:       4c 89 e7                mov    %r12,%rdi
// ffffffff81d2cc1c:       e8 ef 33 5c ff          call   ffffffff812f0010 <kfree> ffffffff81d2cc1d: R_X86_64_PLT32        kfree-0x4
// ffffffff81d2cc21:       4c 8b 65 f8             mov    -0x8(%rbp),%r12
// python3 -c 'print(hex(0xffffffff81d2cc1c-0xffffffff81d2cb80))'
SEC("kprobe/l2cap_chan_put+0x9c")
int probe_kmem_cache_free4(struct pt_regs* ctx)
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
            //bpf_printk("alloc_size: %016lx  %016lx, %lu\n", alloc_addr, *pcache, alloc_size);
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




SEC("kprobe/route4_delete_filter_work+0x4a")
int probe_kfree5(struct pt_regs* ctx)
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
            // bpf_printk("alloc_size: %016lx  %016lx, %lu\n", alloc_addr, *pcache, alloc_size);
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
int probe_kmalloc5(struct pt_regs *ctx)
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

SEC("kprobe/alloc_netdev_mqs+0x5c")
int probe_kmalloc6(struct pt_regs *ctx)
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
    struct kmem_cache *cache;

    ip = ctx->ip;
    // BPF_KPROBE_READ_RET_IP(ip, ctx);
    // if (is_target_alloc_site(ip)) {
    // get ip_size_priv
    // alloc_size = PT_REGS_PARM1(ctx);
    cache = (struct kmem_cache*) PT_REGS_PARM1(ctx);
    alloc_size = BPF_CORE_READ(cache, size);
    // bpf_printk("======alloc_size: %0lx========\n", alloc_size);

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
    bpf_jmp_next(ctx, (u64) ctx->ip + 4, alloc_addr);
    // }
    return 0;
}



// void kmem_cache_free(struct kmem_cache *s, void *x)
// SEC("kprobe/kmem_cache_free")


// ffffffff81ae2fc0 <netdev_freemem>:
// ffffffff81ae2fc0:       e8 bb ec 58 ff          call   ffffffff81071c80 <__fentry__>    ffffffff81ae2fc1: R_X86_64_PLT32        __fentry__-0x4
// ffffffff81ae2fc5:       55                      push   %rbp
// ffffffff81ae2fc6:       0f b7 87 56 02 00 00    movzwl 0x256(%rdi),%eax
// ffffffff81ae2fcd:       48 29 c7                sub    %rax,%rdi
// ffffffff81ae2fd0:       48 89 e5                mov    %rsp,%rbp
// ffffffff81ae2fd3:       e8 18 e5 79 ff          call   ffffffff812814f0 <kvfree>        ffffffff81ae2fd4: R_X86_64_PLT32        kvfree-0x4
// ffffffff81ae2fd8:       5d                      pop    %rbp

SEC("kprobe/netdev_freemem+0x13")
int probe_kmem_cache_free6(struct pt_regs* ctx)
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
            // bpf_printk("alloc_size: %016lx  %016lx, %lu\n", alloc_addr, *pcache, alloc_size);
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



SEC("kprobe/nft_obj_destroy+0x4c")
int probe_kfree7(struct pt_regs* ctx)
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
            //bpf_printk("alloc_size: %016lx  %016lx, %lu\n", alloc_addr, *pcache, alloc_size);
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


// ffffffff81b7d230 <nft_obj_init>:
// ...
// ffffffff81b7d254:       48 c1 e7 03             shl    $0x3,%rdi
// ffffffff81b7d258:       e8 53 57 77 ff          call   ffffffff812f29b0 <__kmalloc>     ffffffff81b7d259: R_X86_64_PLT32        __kmalloc-0x4
// ffffffff81b7d25d:       48 85 c0                test   %rax,%rax
// ...
// ffffffff81b7d2c3:       48 81 c7 c0 00 00 00    add    $0xc0,%rdi
// ffffffff81b7d2ca:       e8 e1 56 77 ff          call   ffffffff812f29b0 <__kmalloc>     ffffffff81b7d2cb: R_X86_64_PLT32        __kmalloc-0x4
// ffffffff81b7d2cf:       49 89 c4                mov    %rax,%r12
// python3 -c 'print(hex(0xffffffff81b7d258-0xffffffff81b7d230))'
// python3 -c 'print(hex(0xffffffff81b7d2ca-0xffffffff81b7d230))'

SEC("kprobe/nft_obj_init+0x28")
int probe_kmalloc7(struct pt_regs *ctx)
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
    bpf_jmp_next(ctx, (u64) ctx->ip + 4, alloc_addr);
    // }

    return 0;
}




SEC("kprobe/nft_obj_init+0x9a")
int probe_kmalloc71(struct pt_regs *ctx)
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

    // 	err = bpf_override_return(ctx, (unsigned long)alloc_addr);
    // }

    bpf_jmp_next(ctx, (u64) ctx->ip + 4, alloc_addr);

    return 0;
}


// ffffffff81b7bed0 <nft_trans_alloc_gfp>:
// ...
// ffffffff81b7bee7:       8d 7a 48                lea    0x48(%rdx),%edi
// ffffffff81b7beea:       e8 c1 6a 77 ff          call   ffffffff812f29b0 <__kmalloc>     ffffffff81b7beeb: R_X86_64_PLT32        __kmalloc-0x4
// ffffffff81b7beef:       48 85 c0                test   %rax,%rax
// python3 -c 'print(hex(0xffffffff81b7beea-0xffffffff81b7bed0))'

SEC("kprobe/nft_trans_alloc_gfp+0x1a")
int probe_kmalloc72(struct pt_regs *ctx)
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

    // 	err = bpf_override_return(ctx, (unsigned long)alloc_addr);
    // }

    bpf_jmp_next(ctx, (u64) ctx->ip + 4, alloc_addr);

    return 0;
}


SEC("kprobe/qrtr_tun_write_iter+0x96")
int probe_kfree811(struct pt_regs* ctx)
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
            //bpf_printk("alloc_size: %016lx  %016lx, %lu\n", alloc_addr, *pcache, alloc_size);
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


SEC("kprobe/qrtr_tun_write_iter+0xc5")
int probe_kfree8(struct pt_regs* ctx)
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
            //bpf_printk("alloc_size: %016lx  %016lx, %lu\n", alloc_addr, *pcache, alloc_size);
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





// ffffffff81da2b40 <qrtr_tun_write_iter>:
// ...
// ffffffff81da2b78:       be c0 0d 00 00          mov    $0xdc0,%esi
// ffffffff81da2b7d:       e8 2e fe 54 ff          call   ffffffff812f29b0 <__kmalloc>     ffffffff81da2b7e: R_X86_64_PLT32        __kmalloc-0x4
// ffffffff81da2b82:       49 89 c4                mov    %rax,%r12
// python3 -c 'print(hex(0xffffffff81da2b7d - 0xffffffff81da2b40))'


SEC("kprobe/qrtr_tun_write_iter+0x3d")
int probe_kmalloc8(struct pt_regs *ctx)
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



SEC("kprobe/selinux_xfrm_policy_free+0x15")
int probe_kfree9(struct pt_regs* ctx)
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
            //bpf_printk("alloc_size: %016lx  %016lx, %lu\n", alloc_addr, *pcache, alloc_size);
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



// ffffffff814e3b80 <selinux_xfrm_alloc_user>:
// ...
// ffffffff814e3bf6:       89 55 c8                mov    %edx,-0x38(%rbp)
// ffffffff814e3bf9:       e8 b2 ed e0 ff          call   ffffffff812f29b0 <__kmalloc>     ffffffff814e3bfa: R_X86_64_PLT32        __kmalloc-0x4
// ffffffff814e3bfe:       49 89 c4                mov    %rax,%r12

// python3 -c 'print(hex(0xffffffff814e3bf9-0xffffffff814e3b80))'

SEC("kprobe/selinux_xfrm_alloc_user+0x79")
int probe_kmalloc9(struct pt_regs *ctx)
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

    // 	err = bpf_override_return(ctx, (unsigned long)alloc_addr);
    // }
    bpf_jmp_next(ctx, (u64) ctx->ip + 4, alloc_addr);

    return 0;
}


SEC("kprobe/tcf_action_cleanup+0x89")
int probe_kfree10(struct pt_regs* ctx)
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
            //bpf_printk("alloc_size: %016lx  %016lx, %lu\n", alloc_addr, *pcache, alloc_size);
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



// ffffffff81b3dbe0 <tcf_idr_create>:
// ...
// ffffffff81b3dc13:       44 89 4d d4             mov    %r9d,-0x2c(%rbp)
// ffffffff81b3dc17:       e8 94 4d 7b ff          call   ffffffff812f29b0 <__kmalloc>     ffffffff81b3dc18: R_X86_64_PLT32        __kmalloc-0x4
// ffffffff81b3dc1c:       49 89 c6                mov    %rax,%r14
// python3 -c 'print(hex(0xffffffff81b3dc17 - 0xffffffff81b3dbe0))'



SEC("kprobe/tcf_idr_create+0x37")
int probe_kmalloc10(struct pt_regs *ctx)
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

    // 	err = bpf_override_return(ctx, (unsigned long)alloc_addr);
    // }
    bpf_jmp_next(ctx, (u64) ctx->ip + 4, alloc_addr);

    return 0;
}


SEC("kprobe/bio_kmalloc+0x2e")
int probe_kmalloc11(struct pt_regs *ctx)
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

    // BPF_KPROBE_READ_RET_IP(ip, ctx);
    ip = ctx->ip;
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
    //bpf_printk("==============key: %016lx  %016lx %016lx============\n", key, alloc_size, ctx->di);

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
        bpf_printk("set pt guard page failed: %016lx,%lu\n", alloc_addr, alloc_size);
    }
    //bpf_printk("kmalloc addr : %016lx\n", alloc_addr);
    // err = bpf_override_return(ctx, (unsigned long)alloc_addr);
    bpf_jmp_next(ctx, (u64) ctx->ip + 4, alloc_addr);
    // }

    return 0;
}






// ffffffff81556870 <bio_free>:
// ...
// ffffffff815568bb:       4c 89 e7                mov    %r12,%rdi
// ffffffff815568be:       e8 4d 97 d9 ff          call   ffffffff812f0010 <kfree> ffffffff815568bf: R_X86_64_PLT32        kfree-0x4
// ffffffff815568c3:       5b                      pop    %rbx
// python3 -c 'print(hex(0xffffffff815568be - 0xffffffff81556870))'
SEC("kprobe/bio_free+0x4e")
int probe_kfree11(struct pt_regs* ctx)
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
            // bpf_printk("alloc_size: %016lx  %016lx, %lu\n", alloc_addr, *pcache, alloc_size);
            err = bpf_set_pt_present((alloc_addr + alloc_size - 4096), 1);
            if (err == 0) {
                bpf_printk("cancel pt guard page failed: %016lx,%lu\n", alloc_addr, alloc_size);
            }
        }


        // free memory, not recycle
        // bpf_cache_free(alloc_addr);



        // err = bpf_override_return(ctx, (unsigned long)0);
    }

    return 0;
}



SEC("kprobe/ip_set_free+0x13")
int probe_kfree12(struct pt_regs* ctx)
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
            //bpf_printk("alloc_size: %016lx  %016lx, %lu\n", alloc_addr, *pcache, alloc_size);
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


// ffffffff81ba2fc0 <ip_set_alloc>:
// ...
// ffffffff81ba2fd0:       48 89 e5                mov    %rsp,%rbp
// ffffffff81ba2fd3:       e8 78 e4 6d ff          call   ffffffff81281450 <kvmalloc_node> ffffffff81ba2fd4: R_X86_64_PLT32        kvmalloc_node-0x4
// ffffffff81ba2fd8:       5d                      pop    %rbp
// python3 -c 'print(hex(0xffffffff81ba2fd3-0xffffffff81ba2fc0))'

SEC("kprobe/ip_set_alloc+0x13")
int probe_kmalloc12(struct pt_regs *ctx)
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




SEC("kprobe/sctp_auth_destroy_hmacs+0x35")
int probe_kfree13(struct pt_regs* ctx)
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
            //bpf_printk("alloc_size: %016lx  %016lx, %lu\n", alloc_addr, *pcache, alloc_size);
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

// ffffffff81d87890 <sctp_auth_init_hmacs>:
// ...
// ffffffff81d878e1:       48 8b b8 88 65 97 82    mov    -0x7d689a78(%rax),%rdi   ffffffff81d878e4: R_X86_64_32S  kmalloc_caches+0x28
// ffffffff81d878e8:       e8 a3 b9 56 ff          call   ffffffff812f3290 <kmem_cache_alloc_trace>        ffffffff81d878e9: R_X86_64_PLT32        kmem_cache_alloc_trace-0x4
// ffffffff81d878ed:       49 89 84 24 c0 00 00 00         mov    %rax,0xc0(%r12)
// python3 -c 'print(hex(0xffffffff81d878e8-0xffffffff81d87890))'


SEC("kprobe/sctp_auth_init_hmacs+0x58")
int probe_kmalloc13(struct pt_regs *ctx)
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



SEC("kprobe/rtnl_newlink+0x4f")
int probe_kfree14(struct pt_regs* ctx)
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
            //bpf_printk("alloc_size: %016lx  %016lx, %lu\n", alloc_addr, *pcache, alloc_size);
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
SEC("kprobe/rtnl_newlink+0x2b")
int probe_kmalloc14(struct pt_regs *ctx)
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

    // err = bpf_override_return(ctx, (unsigned long)alloc_addr);
    // }
    bpf_jmp_next(ctx, (u64) ctx->ip + 4, alloc_addr);

    return 0;
}

char _license[] SEC("license") = "GPL";