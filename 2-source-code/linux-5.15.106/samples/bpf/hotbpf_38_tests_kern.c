

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
//Dump of assembler code for function alloc_bprm:
//0xffffffff81332f80 <+0>:	call   0xffffffff81071c80 <__fentry__>
//0xffffffff81332f85 <+5>:	push   %rbp
//0xffffffff81332f86 <+6>:	mov    $0x1a0,%edx
//0xffffffff81332f8b <+11>:	mov    %rsp,%rbp
//0xffffffff81332f8e <+14>:	push   %r15
//0xffffffff81332f90 <+16>:	push   %r14
//0xffffffff81332f92 <+18>:	mov    %rsi,%r14
//0xffffffff81332f95 <+21>:	mov    $0xdc0,%esi
//0xffffffff81332f9a <+26>:	push   %r13
//0xffffffff81332f9c <+28>:	mov    %edi,%r13d
//0xffffffff81332f9f <+31>:	push   %r12
//0xffffffff81332fa1 <+33>:	push   %rbx
//0xffffffff81332fa2 <+34>:	sub    $0x8,%rsp
//0xffffffff81332fa6 <+38>:	mov    0x16435fb(%rip),%rdi        # 0xffffffff829765a8 <kmalloc_caches+72>
//0xffffffff81332fad <+45>:	call   0xffffffff812f3270 <kmem_cache_alloc_trace>


SEC("kprobe/alloc_bprm+0x2d")
int probe_kmem_cache_alloc_trace_bprm(struct pt_regs *ctx)
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
    //bpf_printk("allocated %016llx\n",cache_addr);
    alloc_addr = bpf_cache_alloc(cache_addr, gfp_flags);
    //bpf_printk("%016llx\n",alloc_addr);
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



//Dump of assembler code for function free_bprm:
//....
//0xffffffff813316ed <+157>:	mov    %r12,%rdi
//0xffffffff813316f0 <+160>:	call   0xffffffff812efff0 <kfree>


SEC("kprobe/free_bprm+0xa0")
int probe_kfree_bprm(struct pt_regs* ctx)
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


//Dump of assembler code for function copy_cgroup_ns:
//0xffffffff811726f0 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff811727e1 <+241>:	mov    0x1803e18(%rip),%rdi        # 0xffffffff82976600 <kmalloc_caches+160>
//0xffffffff811727e8 <+248>:	mov    $0x30,%edx
//0xffffffff811727ed <+253>:	mov    $0x400dc0,%esi
//0xffffffff811727f2 <+258>:	call   0xffffffff812f3270 <kmem_cache_alloc_trace>


SEC("kprobe/copy_cgroup_ns+0x102")
int probe_kmem_cache_alloc_trace_cgroup(struct pt_regs *ctx)
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
    //bpf_printk("allocated %016llx\n",cache_addr);
    alloc_addr = bpf_cache_alloc(cache_addr, gfp_flags);
    //bpf_printk("%016llx\n",alloc_addr);
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


//Dump of assembler code for function copy_cgroup_ns:
//0xffffffff811726f0 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff811728f2 <+514>:	mov    -0x30(%rbp),%r12
//0xffffffff811728f6 <+518>:	jmp    0xffffffff8117273b <copy_cgroup_ns+75>
//0xffffffff811728fb <+523>:	mov    %r12,%rdi
//0xffffffff811728fe <+526>:	mov    %eax,-0x30(%rbp)
//0xffffffff81172901 <+529>:	call   0xffffffff812efff0 <kfree>



SEC("kprobe/copy_cgroup_ns+0x211")
int probe_kfree_cgroup(struct pt_regs* ctx)
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


//Dump of assembler code for function free_cgroup_ns:
//0xffffffff811724a0 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff81172524 <+132>:	call   0xffffffff813c9130 <proc_free_inum>
//0xffffffff81172529 <+137>:	mov    %r12,%rdi
//0xffffffff8117252c <+140>:	call   0xffffffff812efff0 <kfree>

SEC("kprobe/free_cgroup_ns+0x84")
int probe_kfree2_cgroup(struct pt_regs* ctx)
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

//Dump of assembler code for function acpi_cpufreq_cpu_init:
//Address range 0xffffffff81a15180 to 0xffffffff81a15aef:
//0xffffffff81a15180 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff81a1524a <+202>:	mov    0xf6133f(%rip),%rdi        # 0xffffffff82976590 <kmalloc_caches+48>
//0xffffffff81a15251 <+209>:	mov    $0x28,%edx
//0xffffffff81a15256 <+214>:	mov    $0xdc0,%esi
//0xffffffff81a1525b <+219>:	call   0xffffffff812f3270 <kmem_cache_alloc_trace>



SEC("kprobe/acpi_cpufreq_cpu_init+0xdb")
int probe_kmem_cache_alloc_trace_cpufreq(struct pt_regs *ctx)
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
    //bpf_printk("allocated %016llx\n",cache_addr);
    alloc_addr = bpf_cache_alloc(cache_addr, gfp_flags);
    //bpf_printk("%016llx\n",alloc_addr);
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



//Dump of assembler code for function acpi_cpufreq_cpu_exit:
//0xffffffff81a148b0 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff81a148fa <+74>:	mov    %r12,%rdi
//0xffffffff81a148fd <+77>:	call   0xffffffff812efff0 <kfree>



SEC("kprobe/acpi_cpufreq_cpu_exit+0x4d")
int probe_kfree_cpufreq(struct pt_regs* ctx)
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

//Dump of assembler code for function acpi_cpufreq_cpu_init:
//Address range 0xffffffff81a15180 to 0xffffffff81a15aef:
//0xffffffff81a15180 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff81a15433 <+691>:	mov    %r11,%rdi
//0xffffffff81a15436 <+694>:	call   0xffffffff812efff0 <kfree>


SEC("kprobe/acpi_cpufreq_cpu_init+0x2b6")
int probe_kfree2_cpufreq(struct pt_regs* ctx)
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

//Dump of assembler code for function __fsnotify_alloc_group:
//0xffffffff8137db50 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff8137db8e <+62>:	shl    $0x4,%rax
//0xffffffff8137db92 <+66>:	mov    -0x7d689a60(%rax),%rdi
//0xffffffff8137db99 <+73>:	call   0xffffffff812f3270 <kmem_cache_alloc_trace>



SEC("kprobe/__fsnotify_alloc_group+0x49")
int probe_kmem_cache_alloc_trace_fsnotify(struct pt_regs *ctx)
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
    //bpf_printk("allocated %016llx\n",cache_addr);
    alloc_addr = bpf_cache_alloc(cache_addr, gfp_flags);
    //bpf_printk("%016llx\n",alloc_addr);
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



//Dump of assembler code for function fsnotify_put_group:
//0xffffffff8137dc60 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff8137dcb5 <+85>:	call   0xffffffff8112a210 <rcu_read_unlock_strict>
//0xffffffff8137dcba <+90>:	mov    %r12,%rdi
//0xffffffff8137dcbd <+93>:	call   0xffffffff812efff0 <kfree>


SEC("kprobe/fsnotify_put_group+0x5d")
int probe_kfree_fsnotify(struct pt_regs* ctx)
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

//Dump of assembler code for function iommu_group_alloc:
//0xffffffff817a6af0 <+0>:	call   0xffffffff81071c80 <__fentry__>
//0xffffffff817a6af5 <+5>:	push   %rbp
//0xffffffff817a6af6 <+6>:	mov    $0xe8,%edx
//0xffffffff817a6afb <+11>:	mov    $0xdc0,%esi
//0xffffffff817a6b00 <+16>:	mov    0x11cfa99(%rip),%rdi        # 0xffffffff829765a0 <kmalloc_caches+64>
//0xffffffff817a6b07 <+23>:	mov    %rsp,%rbp
//0xffffffff817a6b0a <+26>:	push   %r12
//0xffffffff817a6b0c <+28>:	mov    $0xfffffffffffffff4,%r12
//0xffffffff817a6b13 <+35>:	push   %rbx
//0xffffffff817a6b14 <+36>:	call   0xffffffff812f3270 <kmem_cache_alloc_trace>


SEC("kprobe/iommu_group_alloc+0x24")
int probe_kmem_cache_alloc_trace_iommu(struct pt_regs *ctx)
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
    //bpf_printk("allocated %016llx\n",cache_addr);
    alloc_addr = bpf_cache_alloc(cache_addr, gfp_flags);
    //bpf_printk("%016llx\n",alloc_addr);
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



//Dump of assembler code for function iommu_group_alloc:
//0xffffffff817a6af0 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff817a6c78 <+392>:	mov    %r12,%rdi
//0xffffffff817a6c7b <+395>:	movslq %ebx,%r12
//0xffffffff817a6c7e <+398>:	call   0xffffffff812efff0 <kfree>

SEC("kprobe/iommu_group_alloc+0x18e")
int probe_kfree_iommu(struct pt_regs* ctx)
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

//Dump of assembler code for function iommu_group_release:
//0xffffffff817a8850 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff817a88b9 <+105>:	mov    %r12,%rdi
//0xffffffff817a88bc <+108>:	call   0xffffffff812efff0 <kfree>

SEC("kprobe/iommu_group_release+0x6c")
int probe_kfree2_iommu(struct pt_regs* ctx)
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

//Dump of assembler code for function ioctx_alloc:
//0xffffffff81390c80 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff81390cf9 <+121>:	mov    0x311a730(%rip),%rdi        # 0xffffffff844ab430 <kioctx_cachep>
//0xffffffff81390d00 <+128>:	mov    $0xdc0,%esi
//0xffffffff81390d05 <+133>:	call   0xffffffff812f2cb0 <kmem_cache_alloc>

SEC("kprobe/ioctx_alloc+0x85")
int probe_kmem_cache_alloc_ioctx(struct pt_regs *ctx)
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
    //bpf_printk("allocated %016llx\n",cache_addr);
    alloc_addr = bpf_cache_alloc(cache_addr, gfp_flags);
    //bpf_printk("%016llx\n",alloc_addr);
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



//Dump of assembler code for function ioctx_alloc:
//0xffffffff81390c80 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff81390de2 <+354>:	mov    %r14,%rsi
//0xffffffff81390de5 <+357>:	call   0xffffffff812f03f0 <kmem_cache_free>



SEC("kprobe/ioctx_alloc+0x165")
int probe_kmem_cache_free_ioctx(struct pt_regs* ctx)
{
    u64 ip = 0;
    u64 pid = 0;
    u64 ip_size_priv = 0;
    u64 alloc_size = 0;
    u64 alloc_addr = PT_REGS_PARM2(ctx);
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
//Dump of assembler code for function free_ioctx:
//0xffffffff8138f290 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff8138f2c7 <+55>:	mov    0x311c162(%rip),%rdi        # 0xffffffff844ab430 <kioctx_cachep>
//0xffffffff8138f2ce <+62>:	mov    %r12,%rsi
//0xffffffff8138f2d1 <+65>:	call   0xffffffff812f03f0 <kmem_cache_free>

SEC("kprobe/free_ioctx+0x41")
int probe_kmem_cache_free2_ioctx(struct pt_regs* ctx)
{
    u64 ip = 0;
    u64 pid = 0;
    u64 ip_size_priv = 0;
    u64 alloc_size = 0;
    u64 alloc_addr = PT_REGS_PARM2(ctx);
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

//Dump of assembler code for function __kthread_create_on_node:
//0xffffffff810c5c00 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff810c5c57 <+87>:	mov    %rax,-0x50(%rbp)
//0xffffffff810c5c5b <+91>:	mov    %rax,-0x48(%rbp)
//0xffffffff810c5c5f <+95>:	call   0xffffffff812f3270 <kmem_cache_alloc_trace>

SEC("kprobe/__kthread_create_on_node+0x5f")
int probe_kmem_cache_alloc_trace_kthread(struct pt_regs *ctx)
{
    //bpf_printk("allocated");
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
    //bpf_printk("allocated %016llx\n",cache_addr);
    alloc_addr = bpf_cache_alloc(cache_addr, gfp_flags);
    //bpf_printk("%016llx\n",alloc_addr);
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

//Dump of assembler code for function __kthread_create_on_node:
//0xffffffff810c5c00 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff810c5d2c <+300>:	call   0xffffffff810dbc60 <set_cpus_allowed_ptr>
//0xffffffff810c5d31 <+305>:	mov    %r13,%rdi
//0xffffffff810c5d34 <+308>:	call   0xffffffff812efff0 <kfree>


SEC("kprobe/__kthread_create_on_node+0x134")
int probe_kfree_kthread(struct pt_regs* ctx)
{
    //bpf_printk("free1");
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


//Dump of assembler code for function kthread:
//0xffffffff810c66a0 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff810c67c7 <+295>:	jmp    0xffffffff810c678e <kthread+238>
//0xffffffff810c67c9 <+297>:	mov    %r12,%rdi
//0xffffffff810c67cc <+300>:	call   0xffffffff812efff0 <kfree>



SEC("kprobe/kthread+0x12c")
int probe_kfree2_kthread(struct pt_regs* ctx)
{
    //bpf_printk("free2");
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
//Dump of assembler code for function kthreadd:
//0xffffffff810c69b0 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff810c6c64 <+692>:	jmp    0xffffffff810c6bc8 <kthreadd+536>
//0xffffffff810c6c69 <+697>:	mov    %r15,%rdi
//0xffffffff810c6c6c <+700>:	call   0xffffffff812efff0 <kfree>

SEC("kprobe/kthreadd+0x2bc")
int probe_kfree3_kthread(struct pt_regs* ctx)
{
    //bpf_printk("free3");
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

//Dump of assembler code for function loop_add:
//0xffffffff817ea4a0 <+0>:	call   0xffffffff81071c80 <__fentry__>
//0xffffffff817ea4a5 <+5>:	push   %rbp
//0xffffffff817ea4a6 <+6>:	mov    $0x2e8,%edx
//0xffffffff817ea4ab <+11>:	mov    $0xdc0,%esi
//0xffffffff817ea4b0 <+16>:	mov    %rsp,%rbp
//0xffffffff817ea4b3 <+19>:	push   %r15
//0xffffffff817ea4b5 <+21>:	push   %r14
//0xffffffff817ea4b7 <+23>:	mov    %edi,%r14d
//0xffffffff817ea4ba <+26>:	mov    0x118c0ef(%rip),%rdi        # 0xffffffff829765b0 <kmalloc_caches+80>
//0xffffffff817ea4c1 <+33>:	push   %r13
//0xffffffff817ea4c3 <+35>:	push   %r12
//0xffffffff817ea4c5 <+37>:	call   0xffffffff812f3270 <kmem_cache_alloc_trace>

SEC("kprobe/loop_add+0x25")
int probe_kmem_cache_alloc_trace_loop(struct pt_regs *ctx)
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
    //bpf_printk("allocated %016llx\n",cache_addr);
    alloc_addr = bpf_cache_alloc(cache_addr, gfp_flags);
    //bpf_printk("%016llx\n",alloc_addr);
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





//Dump of assembler code for function loop_add:
//0xffffffff817ea4a0 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff817ea5bd <+285>:	call   0xffffffff81e4f990 <mutex_unlock>
//0xffffffff817ea5c2 <+290>:	mov    %r12,%rdi
//0xffffffff817ea5c5 <+293>:	call   0xffffffff812efff0 <kfree>

SEC("kprobe/loop_add+0x125")
int probe_kfree_loop(struct pt_regs* ctx)
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

//Dump of assembler code for function loop_remove:
//0xffffffff817ea160 <+0>:	call   0xffffffff81071c80 <__fentry__>
//0xffffffff817ea165 <+5>:	push   %rbp
//0xffffffff817ea166 <+6>:	mov    %rsp,%rbp
//0xffffffff817ea169 <+9>:	push   %r12
//0xffffffff817ea16b <+11>:	mov    %rdi,%r12
//0xffffffff817ea16e <+14>:	mov    0x2b8(%rdi),%rdi
//0xffffffff817ea175 <+21>:	call   0xffffffff815720c0 <del_gendisk>
//0xffffffff817ea17a <+26>:	mov    0x2b8(%r12),%rdi
//0xffffffff817ea182 <+34>:	call   0xffffffff81571390 <blk_cleanup_disk>
//0xffffffff817ea187 <+39>:	lea    0x1a0(%r12),%rdi
//0xffffffff817ea18f <+47>:	call   0xffffffff8156aa10 <blk_mq_free_tag_set>
//0xffffffff817ea194 <+52>:	mov    $0xffffffff83294300,%rdi
//0xffffffff817ea19b <+59>:	call   0xffffffff81e4ff80 <mutex_lock>
//0xffffffff817ea1a0 <+64>:	movslq (%r12),%rsi
//0xffffffff817ea1a4 <+68>:	mov    $0xffffffff83294320,%rdi
//0xffffffff817ea1ab <+75>:	call   0xffffffff815f6a40 <idr_remove>
//0xffffffff817ea1b0 <+80>:	mov    $0xffffffff83294300,%rdi
//0xffffffff817ea1b7 <+87>:	call   0xffffffff81e4f990 <mutex_unlock>
//0xffffffff817ea1bc <+92>:	mov    %r12,%rdi
//0xffffffff817ea1bf <+95>:	call   0xffffffff812efff0 <kfree>

SEC("kprobe/loop_remove+0x5f")
int probe_kfree2_loop(struct pt_regs* ctx)
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

//Dump of assembler code for function copy_pid_ns:
//0xffffffff8117ed20 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff8117ee11 <+241>:	mov    0x31f49c8(%rip),%rdi        # 0xffffffff843737e0 <pid_ns_cachep>
//0xffffffff8117ee18 <+248>:	mov    $0xdc0,%esi
//--Type <RET> for more, q to quit, c to continue without paging--
//0xffffffff8117ee1d <+253>:	call   0xffffffff812f2cb0 <kmem_cache_alloc>

SEC("kprobe/copy_pid_ns+0xfd")
int probe_kmem_cache_alloc_pidns(struct pt_regs *ctx)
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
    //bpf_printk("allocated %016llx\n",cache_addr);
    alloc_addr = bpf_cache_alloc(cache_addr, gfp_flags);
    //bpf_printk("%016llx\n",alloc_addr);
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




//Dump of assembler code for function copy_pid_ns:
//....
//0xffffffff8117efb7 <+663>:	call   0xffffffff815fad10 <idr_destroy>
//0xffffffff8117efbc <+668>:	mov    -0x48(%rbp),%rsi
//0xffffffff8117efc0 <+672>:	mov    0x31f4819(%rip),%rdi        # 0xffffffff843737e0 <pid_ns_cachep>
//0xffffffff8117efc7 <+679>:	call   0xffffffff812f03f0 <kmem_cache_free>

SEC("kprobe/copy_pid_ns+0x2a7")
int probe_kmem_cache_free_pidns(struct pt_regs* ctx)
{
    u64 ip = 0;
    u64 pid = 0;
    u64 ip_size_priv = 0;
    u64 alloc_size = 0;
    u64 alloc_addr = PT_REGS_PARM2(ctx);
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
//Dump of assembler code for function delayed_free_pidns:
//....
//0xffffffff8117e957 <+71>:	mov    0x31f4e82(%rip),%rdi        # 0xffffffff843737e0 <pid_ns_cachep>
//0xffffffff8117e95e <+78>:	mov    %r12,%rsi
//0xffffffff8117e961 <+81>:	call   0xffffffff812f03f0 <kmem_cache_free>
//0xffffffff8117e966 <+86>:	pop    %rbx
//0xffffffff8117e967 <+87>:	pop    %r12
//0xffffffff8117e969 <+89>:	pop    %rbp
//0xffffffff8117e96a <+90>:	ret
SEC("kprobe/delayed_free_pidns+0x51")
int probe_kmem_cache_free2_pidns(struct pt_regs* ctx)
{
    u64 ip = 0;
    u64 pid = 0;
    u64 ip_size_priv = 0;
    u64 alloc_size = 0;
    u64 alloc_addr = PT_REGS_PARM2(ctx);
    int err = 0;
    //bpf_printk("free");
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

//Dump of assembler code for function alloc_pipe_info:
//0xffffffff81335810 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff813358dc <+204>:	mov    $0x400dc0,%esi
//0xffffffff813358e1 <+209>:	shl    $0x3,%rdi
//0xffffffff813358e5 <+213>:	call   0xffffffff812f2990 <__kmalloc>




SEC("kprobe/alloc_pipe_info+0xd5")
int probe_kmem_cache_alloc_trace_pipe_buffer(struct pt_regs *ctx)
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
    //bpf_printk("allocated %016llx\n",cache_addr);
    alloc_addr = bpf_cache_alloc(cache_addr, gfp_flags);
    //bpf_printk("%016llx\n",alloc_addr);
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




//Dump of assembler code for function free_pipe_info:
//0xffffffff81335a40 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff81335ae1 <+161>:	xor    %esi,%esi
//0xffffffff81335ae3 <+163>:	call   0xffffffff812c22f0 <__free_pages>
//0xffffffff81335ae8 <+168>:	mov    0x98(%r12),%rdi
//0xffffffff81335af0 <+176>:	call   0xffffffff812efff0 <kfree>


SEC("kprobe/free_pipe_info+0xb0")
int probe_kfree_pipe_buffer(struct pt_regs* ctx)
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

//Dump of assembler code for function alloc_pipe_info:
//0xffffffff81335810 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff8133585a <+74>:	mov    0x1640d7f(%rip),%rdi        # 0xffffffff829765e0 <kmalloc_caches+128>
//0xffffffff81335861 <+81>:	mov    $0x400dc0,%esi
//0xffffffff81335866 <+86>:	mov    0x1eb82fc(%rip),%ebx        # 0xffffffff8--Type <RET> for more, q to quit, c to continue without paging--
//31edb68 <pipe_max_size>
//0xffffffff8133586c <+92>:	call   0xffffffff812f3270 <kmem_cache_alloc_trace>



SEC("kprobe/alloc_pipe_info+0x5c")
int probe_kmem_cache_alloc_trace_pipe_info(struct pt_regs *ctx)
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
    //bpf_printk("allocated %016llx\n",cache_addr);
    alloc_addr = bpf_cache_alloc(cache_addr, gfp_flags);
    //bpf_printk("%016llx\n",alloc_addr);
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



//Dump of assembler code for function alloc_pipe_info:
//0xffffffff81335810 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff8133598e <+382>:	mov    %r12,%rdi
//0xffffffff81335991 <+385>:	call   0xffffffff812efff0 <kfree>



SEC("kprobe/alloc_pipe_info+0x181")
int probe_kfree_pipe_info(struct pt_regs* ctx)
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

//Dump of assembler code for function free_pipe_info:
//0xffffffff81335a40 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff81335af5 <+181>:	mov    %r12,%rdi
//0xffffffff81335af8 <+184>:	call   0xffffffff812efff0 <kfree>

SEC("kprobe/free_pipe_info+0xb8")
int probe_kfree2_pipe_info(struct pt_regs* ctx)
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

//Dump of assembler code for function sel_open_policy:
//....
//0xffffffff814cf0a2 <+194>:	mov    0x14a74d7(%rip),%rdi        # 0xffffffff82976580 <kmalloc_caches+32>
//0xffffffff814cf0a9 <+201>:	mov    $0x10,%edx
//0xffffffff814cf0ae <+206>:	mov    $0xdc0,%esi
//0xffffffff814cf0b3 <+211>:	call   0xffffffff812f3270 <kmem_cache_alloc_trace>
//0xffffffff814cf0b8 <+216>:	mov    %rax,%r15
//0xffffffff814cf0bb <+219>:	test   %rax,%rax
//0xffffffff814cf0be <+222>:	je     0xffffffff814cf152 <sel_open_policy+370>
SEC("kprobe/sel_open_policy+0xd3")
int probe_kmalloc_plm(struct pt_regs *ctx)
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
    //bpf_printk("allocated %016llx\n",cache_addr);
    alloc_addr = bpf_cache_alloc(cache_addr, gfp_flags);
    //bpf_printk("%016llx\n",alloc_addr);
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




//Dump of assembler code for function sel_release_policy:
//0xffffffff814ce310 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff814ce33b <+43>:	call   0xffffffff812bd580 <vfree>
//0xffffffff814ce340 <+48>:	mov    %r12,%rdi
//0xffffffff814ce343 <+51>:	call   0xffffffff812efff0 <kfree>
//0xffffffff814ce348 <+56>:	mov    -0x8(%rbp),%r12
SEC("kprobe/sel_release_policy+0x33")
int probe_kfree_plm(struct pt_regs* ctx)
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

//Dump of assembler code for function pneigh_lookup:
//0xffffffff81ae5130 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff81ae51ef <+191>:	mov    $0xdc0,%esi
//0xffffffff81ae51f4 <+196>:	mov    %r9,-0x38(%rbp)
//0xffffffff81ae51f8 <+200>:	call   0xffffffff812f2990 <__kmalloc>



SEC("kprobe/pneigh_lookup+0xc8")
int probe_kmalloc_pneigh(struct pt_regs *ctx)
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

//Dump of assembler code for function pneigh_lookup:
//0xffffffff81ae5130 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff81ae528f <+351>:	xor    %ebx,%ebx
//0xffffffff81ae5291 <+353>:	call   0xffffffff812efff0 <kfree>
//0xffffffff81ae5296 <+358>:	jmp    0xffffffff81ae526b <pneigh_lookup+315>
//0xffffffff81ae5298 <+360>:	cmpb   $0x0,0x1838223(%rip)

SEC("kprobe/pneigh_lookup+0x161")
int probe_kfree_pneigh(struct pt_regs* ctx)
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


//Dump of assembler code for function pneigh_delete:
//0xffffffff81aebd50 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff81aebe37 <+231>:	mov    %r15,%rdi
//0xffffffff81aebe3a <+234>:	mov    %eax,-0x30(%rbp)
//0xffffffff81aebe3d <+237>:	call   0xffffffff812efff0 <kfree>
//0xffffffff81aebe42 <+242>:	mov    -0x30(%rbp),%eax



SEC("kprobe/pneigh_delete+0xed")
int probe_kfree2_pneigh(struct pt_regs* ctx)
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
//Dump of assembler code for function sg_read:
//0xffffffff81847160 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff81847223 <+195>:	mov    $0xdc0,%esi
//0xffffffff81847228 <+200>:	mov    %r9,0x18(%rsp)
//0xffffffff8184722d <+205>:	mov    0x112f35c(%rip),%rdi        # 0xffffffff82976590 <kmalloc_caches+48>
//0xffffffff81847234 <+212>:	call   0xffffffff812f3270 <kmem_cache_alloc_trace>



SEC("kprobe/sg_read+0xd4")
int probe_kmem_cache_alloc_trace_sg_read(struct pt_regs *ctx)
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
    //bpf_printk("allocated %016llx\n",cache_addr);
    alloc_addr = bpf_cache_alloc(cache_addr, gfp_flags);
    //bpf_printk("%016llx\n",alloc_addr);
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


//Dump of assembler code for function sg_read:
//0xffffffff81847160 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff81847447 <+743>:	mov    0x20(%rsp),%rsi
//0xffffffff8184744c <+748>:	mov    %r13,%rdi
//0xffffffff8184744f <+751>:	call   0xffffffff81844540 <sg_remove_request>
//0xffffffff81847454 <+756>:	mov    %r14,%rdi
//0xffffffff81847457 <+759>:	call   0xffffffff812efff0 <kfree>

SEC("kprobe/sg_read+0x2f7")
int probe_kfree_sg_read(struct pt_regs* ctx)
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

//Dump of assembler code for function __sk_attach_prog:
//0xffffffff81b07280 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff81b0729c <+28>:	mov    0xe6f2e5(%rip),%rdi        # 0xffffffff82976588 <kmalloc_caches+40>
//0xffffffff81b072a3 <+35>:	call   0xffffffff812f3270 <kmem_cache_alloc_trace>

SEC("kprobe/__sk_attach_prog+0x23")
int probe_kmem_cache_alloc_trace_sk_filter(struct pt_regs *ctx)
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
    //bpf_printk("allocated %016llx\n",cache_addr);
    alloc_addr = bpf_cache_alloc(cache_addr, gfp_flags);
    //bpf_printk("%016llx\n",alloc_addr);
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



//Dump of assembler code for function sk_filter_release_rcu:
//0xffffffff81b03860 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff81b0389d <+61>:	call   0xffffffff811f5db0 <bpf_prog_free>
//0xffffffff81b038a2 <+66>:	mov    %r14,%rdi
//0xffffffff81b038a5 <+69>:	call   0xffffffff812efff0 <kfree>


SEC("kprobe/sk_filter_release_rcu+0x45")
int probe_kfree_sk_filter(struct pt_regs* ctx)
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


//Dump of assembler code for function sk_filter_release_rcu:
//0xffffffff81b03860 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff81b038b5 <+85>:	call   0xffffffff811f9f40 <bpf_prog_put>
//0xffffffff81b038ba <+90>:	mov    %r14,%rdi
//0xffffffff81b038bd <+93>:	call   0xffffffff812efff0 <kfree>

SEC("kprobe/sk_filter_release_rcu+0x5d")
int probe_kfree2_sk_filter(struct pt_regs* ctx)
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
//Dump of assembler code for function __sk_attach_prog:
//0xffffffff81b07280 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff81b072d2 <+82>:	ja     0xffffffff81b072e6 <__sk_attach_prog+102>
//0xffffffff81b072d4 <+84>:	mov    %rax,%rdi
//0xffffffff81b072d7 <+87>:	call   0xffffffff812efff0 <kfree>

SEC("kprobe/__sk_attach_prog+0x57")
int probe_kfree3_sk_filter(struct pt_regs* ctx)
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

//Dump of assembler code for function selinux_sk_alloc_security:
//0xffffffff814c6130 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff814c615a <+42>:	sub    %rdx,%rax
//0xffffffff814c615d <+45>:	mov    $0x20,%edx
//0xffffffff814c6162 <+50>:	shl    $0x4,%rax
//0xffffffff814c6166 <+54>:	mov    -0x7d689a78(%rax),%rdi
//0xffffffff814c616d <+61>:	call   0xffffffff812f3270 <kmem_cache_alloc_trace>


SEC("kprobe/selinux_sk_alloc_security+0x3d")
int probe_kmem_cache_alloc_trace_sksec(struct pt_regs *ctx)
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
    //bpf_printk("allocated %016llx\n",cache_addr);
    alloc_addr = bpf_cache_alloc(cache_addr, gfp_flags);
    //bpf_printk("%016llx\n",alloc_addr);
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



//Dump of assembler code for function selinux_sk_free_security:
//0xffffffff814c44c0 <+0>:	call   0xffffffff81071c80 <__fentry__>
//0xffffffff814c44c5 <+5>:	push   %rbp
//0xffffffff814c44c6 <+6>:	mov    %rsp,%rbp
//0xffffffff814c44c9 <+9>:	push   %r12
//0xffffffff814c44cb <+11>:	mov    0x2a0(%rdi),%r12
//0xffffffff814c44d2 <+18>:	movq   $0x0,0x2a0(%rdi)
//0xffffffff814c44dd <+29>:	mov    %r12,%rdi
//0xffffffff814c44e0 <+32>:	call   0xffffffff814e43e0 <selinux_netlbl_sk_security_free>
//0xffffffff814c44e5 <+37>:	mov    %r12,%rdi
//0xffffffff814c44e8 <+40>:	call   0xffffffff812efff0 <kfree>



SEC("kprobe/selinux_sk_free_security+0x28")
int probe_kfree_sksec(struct pt_regs* ctx)
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

// void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
// void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)



//Dump of assembler code for function xt_alloc_table_info:
//0xffffffff81b9ef00 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff81b9ef21 <+33>:	mov    %rdi,%rbx
//0xffffffff81b9ef24 <+36>:	add    $0x40,%rdi
//0xffffffff81b9ef28 <+40>:	call   0xffffffff81281430 <kvmalloc_node>

// python3 -c 'print(hex(0xffffffff81ad932c - 0xffffffff81ad92d0))'
// void *kvmalloc_node(size_t size, gfp_t flags, int node)
SEC("kprobe/xt_alloc_table_info+0x28")
int probe_kmalloc_xt_table_info(struct pt_regs *ctx)
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


//Dump of assembler code for function xt_free_table_info:
//0xffffffff81b9ef70 <+0>:	call   0xffffffff81071c80 <__fentry__>
//....
//0xffffffff81b9efb9 <+73>:	mov    0x38(%r13),%rdi
//0xffffffff81b9efbd <+77>:	call   0xffffffff812814d0 <kvfree>
//0xffffffff81b9efc2 <+82>:	mov    %r13,%rdi
//0xffffffff81b9efc5 <+85>:	call   0xffffffff812814d0 <kvfree>

SEC("kprobe/xt_free_table_info+0x55")
int probe_kvfree_xt_table_info(struct pt_regs* ctx)
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

char _license[] SEC("license") = "GPL";
