# Copy this script into binja's console (no headless license)

alloc_funcs = [
    "__kmalloc", "kvmalloc_node", "kmem_cache_alloc",
    "kmem_cache_alloc_trace", "kmem_cache_alloc_node", 
    "kmem_cache_alloc_bulk", "kmem_cache_alloc_node_trace",
    "kmalloc_array", "kmalloc_array_node", "kmalloc_slab",
    "kzalloc", "kcalloc", "kcalloc_node", "kmemdup"
]

f = open("./vmlinux_addrs.txt", "w")

#with binaryninja.open_view("./vmlinux", update_analysis=False) as bv:
for func in alloc_funcs:
    for sym in bv.symbols[func]:
        sym_addr = sym.address
        refs = bv.get_code_refs(sym_addr)
        for ref in refs:
            f.write(hex(ref.address) + "\n")

f.close()
print("Done")
