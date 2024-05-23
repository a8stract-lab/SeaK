import argparse

def parse_arguments():
    # Create the parser
    parser = argparse.ArgumentParser(description="Process some integers.")
    
    # Add the `-name` argument which takes exactly one argument
    parser.add_argument('-name', type=str, required=True, help='Name argument (exactly one required)')
    
    # Add the `-alloc` argument which takes one or more arguments
    parser.add_argument('-alloc', type=str, nargs='+', required=True, help='Allocation arguments (one or more required)')
    
    # Add the `-free` argument which takes one or more arguments
    parser.add_argument('-free', type=str, nargs='+', required=True, help='Free arguments (one or more required)')
    
    # Parse the arguments
    args = parser.parse_args()
    
    return args

header = '''
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

#define ___GFP_DMA        0x01u
#define ___GFP_RECLAIMABLE    0x10u
#define ___GFP_ACCOUNT        0x400000u

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

/* Define all your maps and functions here */

char _license[] SEC("license") = "GPL";


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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 40960);
    __type(key, u32);
    __type(value, u32);
} allocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 40960);
    __type(key, u32);
    __type(value, u32);
} frees SEC(".maps");

#define ALLOCNUM 1
bool is_target_alloc_site(unsigned long curr_ip) {
    unsigned long alloc_site_array[ALLOCNUM] = {
            0xffffffff81556713  // bio_kmalloc
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
'''

allocs_frees = '''
int allocation(u32 pid)
{
    u32 *pval = NULL;
    pval = bpf_map_lookup_elem(&allocs, &pid);
    if (pval) {
        return 1;
    } else {
        return -1;
    }
    return 0;
}

int free(u32 pid)
{
    u32 *pval = NULL;
    pval = bpf_map_lookup_elem(&frees, &pid);
    if (pval) {
        return 1;
    } else {
        return -1;
    }
    return 0;
}


// kmem_cache_alloc_trace(kmalloc_caches[kmalloc_type(flags)][index], flags, size);
SEC("kprobe/kmem_cache_alloc_trace")
int probe_kmem_cache_alloc_file(struct pt_regs *ctx)
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
    u32 pid = bpf_get_current_pid_tgid();
    err = allocation(pid);
    if (err < 0) 
        return -1;

    ip = ctx->ip;

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
            return -1;
        }
        err = bpf_map_update_elem(&key2cache, &key, &cache_addr, BPF_ANY);
        if (err < 0) {
            return err;
        }
    } else {
        cache_addr = *pcache;
    }

    // alloc a new object
    alloc_addr = bpf_cache_alloc(cache_addr, gfp_flags);
    if (alloc_addr == 0) {
        return -1;
    }

    // add new object to inuse map for free.
    err = bpf_map_update_elem(&addr2key, &alloc_addr, &key, BPF_ANY);
    if (err < 0) {
        return err;
    }

    // set guard page
    err = bpf_set_pt_present((alloc_addr + alloc_size - 4096), 1);
    if (err == 0) {
    }

    err = bpf_override_return(ctx, (unsigned long)alloc_addr);


    return 0;
}


// kmem_cache_free(filp_cachep, f);
SEC("kprobe/kmem_cache_free")
int probe_kmem_cache_alloc_free_file(struct pt_regs* ctx)
{
    u64 ip = 0;
    u64 ip_size_priv = 0;
    u64 alloc_size = 0;
    u64 alloc_addr = PT_REGS_PARM2(ctx);
    int err = 0;
    u32 pid = bpf_get_current_pid_tgid();
    err = free(pid);
    if (err < 0) 
        return -1;

    // check if it is a hotbpf object
    u64 *pkey = bpf_map_lookup_elem(&addr2key, &alloc_addr);
    if (pkey) {
        err = bpf_map_delete_elem(&addr2key, &alloc_addr);
        if (err < 0) {
            bpf_printk("kfree addr2key delete failed: %d\\n", err);
            return err;
        }

        // cancel guard page
        u64 *pcache = bpf_map_lookup_elem(&key2cache, pkey);
        if (pcache) {
            struct kmem_cache *cache = (struct kmem_cache*)(*pcache);
            alloc_size = BPF_CORE_READ(cache, size);
            err = bpf_set_pt_present((alloc_addr + alloc_size - 4096), 1);
            if (err == 0) {
            }
        }


        err = bpf_override_return(ctx, (unsigned long)0);
    }

    return 0;
}


SEC("kprobe/__kmalloc")
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
    u32 pid = bpf_get_current_pid_tgid();
    err = allocation(pid);
    if (err < 0) 
        return -1;

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
            bpf_printk("probe create cache failed\\n");
            return -1;
        }
        err = bpf_map_update_elem(&key2cache, &key, &cache_addr, BPF_ANY);
        if (err < 0) {
            bpf_printk("update key2cache failed: %d\\n", err);
            return err;
        }
    } else {
        cache_addr = *pcache;
    }

    // alloc a new object
    alloc_addr = bpf_cache_alloc(cache_addr, gfp_flags);
    if (alloc_addr == 0) {
        bpf_printk("probe kmalloc failed\\n");
        return -1;
    }

    // add new object to inuse map for free.
    err = bpf_map_update_elem(&addr2key, &alloc_addr, &key, BPF_ANY);
    if (err < 0) {
        bpf_printk("addr2key update failed: %d\\n", err);
        return err;
    }

    // set guard page
    err = bpf_set_pt_present((alloc_addr + alloc_size - 4096), 1);
    if (err == 0) {
    }

    err = bpf_override_return(ctx, (unsigned long)alloc_addr);

	return 0;
}



SEC("kprobe/kfree")
int probe_kfree3(struct pt_regs* ctx) 
{
	u64 ip = 0;
	u64 ip_size_priv = 0;
	u64 alloc_size = 0;
	u64 alloc_addr = PT_REGS_PARM1(ctx);
	int err = 0;

    u32 pid = bpf_get_current_pid_tgid();
    err = free(pid);
    if (err < 0) 
        return -1;

	// check if it is a hotbpf object
	u64 *pkey = bpf_map_lookup_elem(&addr2key, &alloc_addr);
	if (pkey) {
		err = bpf_map_delete_elem(&addr2key, &alloc_addr);
		if (err < 0) {
			bpf_printk("kfree addr2key delete failed: %d\\n", err);
			return err;
		}

		// cancel guard page
		u64 *pcache = bpf_map_lookup_elem(&key2cache, pkey);
		if (pcache) {
			struct kmem_cache *cache = (struct kmem_cache*)(*pcache);
			alloc_size = BPF_CORE_READ(cache, size);
			bpf_printk("alloc_size: %016lx  %016lx, %lu\\n", alloc_addr, *pcache, alloc_size);
			err = bpf_set_pt_present((alloc_addr + alloc_size - 4096), 1);
			if (err == 0) {
			}
		}


		err = bpf_override_return(ctx, (unsigned long)0);
	}
	
	return 0;
}

// ============================================================================
'''

allocs = '''

SEC("kprobe/{alloc}")
int probe_alloc_start_{alloc}(struct pt_regs *ctx)
{{
    u32 pid = bpf_get_current_pid_tgid();
    u32 val = 1;
    int err = 0;
    err = bpf_map_update_elem(&allocs, &pid, &val, BPF_ANY);
    if (err < 0) {{
        return err;
    }}

    return 0;
}}

SEC("kretprobe/{alloc}")
int probe_alloc_end_{alloc}(struct pt_regs *ctx)
{{
    u32 pid = bpf_get_current_pid_tgid();
    int err = 0;
    u32* pval = NULL;
    u32 val = 0;
    pval = bpf_map_lookup_elem(&allocs, &pid);
    if (pval) {{
        err = bpf_map_delete_elem(&allocs, &pid);
        if (err < 0) {{
            return err;
        }}
    }} else {{
        return err;
    }}
    return 0;
}}

'''

frees = '''

SEC("kprobe/{free}")
int probe_start_{free}(struct pt_regs *ctx)
{{
    u32 pid = bpf_get_current_pid_tgid();
    u32 val = 1;
    int err = 0;
    err = bpf_map_update_elem(&frees, &pid, &val, BPF_ANY);
    if (err < 0) {{
        return err;
    }}

    return 0;
}}

SEC("kretprobe/{free}")
int probe_end_{free}(struct pt_regs *ctx)
{{
    u32 pid = bpf_get_current_pid_tgid();
    int err = 0;
    u32* pval = NULL;
    u32 val = 0;
    pval = bpf_map_lookup_elem(&frees, &pid);
    if (pval) {{
        err = bpf_map_delete_elem(&frees, &pid);
        if (err < 0) {{
            return err;
        }}
    }}
    return 0;
}}

'''

user = '''
/*
 * Software Name: hotbpf
 * Author: Yueqi Chen <yueqichen.0x0@gmail.com>
 *		   Zicheng Wang <wangzccs@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <fcntl.h>

#define VMALLOC_FREE_PATH "/proc/vmalloc_free"

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
    stop = 1;
}



int main(int argc, char **argv)
{
    struct bpf_link *links[2];
    struct bpf_program *prog;
    struct bpf_object *obj;
    char filename[256];
    int map_fd[3], i, j = 0;
    int vmalloc_fd = 0;
    __u64 key, next_key, val;
    int trace_fd;

    trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
    if (trace_fd < 0) {
        printf("cannot open trace_pipe %d\\n", trace_fd);
        return trace_fd;
    }


    snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\\n");
        return 0;
    }

    /* load BPF program */
    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\\n");
        goto cleanup;
    }

    map_fd[0] = bpf_object__find_map_fd_by_name(obj, "addr2key");
    if (map_fd[0] < 0) {
        fprintf(stderr, "ERROR: finding a map in obj file failed\\n");
        goto cleanup;
    }

    map_fd[1] = bpf_object__find_map_fd_by_name(obj, "key2cache");
    if (map_fd[1] < 0) {
        fprintf(stderr, "ERROR: finding a map in obj file failed\\n");
        goto cleanup;
    }

    bpf_object__for_each_program(prog, obj) {
        links[j] = bpf_program__attach(prog);
        if (libbpf_get_error(links[j])) {
            fprintf(stderr, "ERROR: bpf_program__attach failed\\n");
            links[j] = NULL;
            goto cleanup;
        }
        j++;
    }

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\\n", strerror(errno));
        goto cleanup;
    }

    printf("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\\n");


    printf("start tracing\\n");
    while (!stop) {
        // fprintf(stderr, ".");
        // sleep(1);
        static char buf[4096];
        ssize_t sz;
        sz = read(trace_fd, buf, sizeof(buf) - 1);
        if (sz > 0) {
            buf[sz] = '\\0';
            // printf("trace: %s\\n", buf);
            puts(buf);
        }
    }


    cleanup:
    // bpf_link__destroy(link);
    printf("\\nprint addr2key\\n");
    int count = 0;
    while (bpf_map_get_next_key(map_fd[0], &key, &next_key) == 0) {
        bpf_map_lookup_elem(map_fd[0], &next_key, &val);
        key = next_key;
        printf("%5d:%016llx:%016llx\\n", ++count, key, val);
    }

    key = 0;
    printf("\\nprint key2cache\\n");
    count = 0;
    while (bpf_map_get_next_key(map_fd[1], &key, &next_key) == 0) {
        bpf_map_lookup_elem(map_fd[1], &next_key, &val);
        key = next_key;
        printf("%5d:%016llx:%016llx\\n", ++count, key, val);
    }

    key = 0;

    for (j--; j >= 0; j--)
        bpf_link__destroy(links[j]);
    bpf_object__close(obj);

    close(trace_fd);
    return 0;

}
'''


if __name__ == "__main__":
    # Get the parsed arguments
    args = parse_arguments()
    
    # Print the parsed arguments to verify
    # print("Name Argument:", args.name)
    # print("Alloc Arguments:", args.alloc)
    # print("Free Arguments:", args.free)

    # print(allocs_frees)
    # print(allocs.format(alloc='a'))

    kern = header

    for elem in args.alloc:
        kern += allocs.format(alloc=elem)

    for elem in args.free:
        kern += frees.format(free=elem)

    kern += allocs_frees

    with open('hotbpf_'+args.name+'_kern.c', 'w') as f:
        f.write(kern)

    with open('hotbpf_'+args.name+'_user.c', 'w') as f:
        f.write(user)

    print('Makefile commands:\n')
    print('tprogs-y +=hotbpf_%s\n'%args.name)
    print('hotbpf_%s-objs := hotbpf_%s_user.o\n'%(args.name,args.name))
    print('always-y += hotbpf_%s_kern.o\n'%args.name)


    