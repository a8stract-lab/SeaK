# cannot find fixdep (/usr/src/linux-5.15.106/samples/bpf/libbpf/staticobjs//fixdep)
# using basic dep data

/usr/src/linux-5.15.106/samples/bpf/libbpf/staticobjs/str_error.o: \
 str_error.c /usr/include/stdc-predef.h /usr/include/string.h \
 /usr/include/x86_64-linux-gnu/bits/libc-header-start.h \
 /usr/include/features.h /usr/include/features-time64.h \
 /usr/include/x86_64-linux-gnu/bits/wordsize.h \
 /usr/include/x86_64-linux-gnu/bits/timesize.h \
 /usr/include/x86_64-linux-gnu/sys/cdefs.h \
 /usr/include/x86_64-linux-gnu/bits/long-double.h \
 /usr/include/x86_64-linux-gnu/gnu/stubs.h \
 /usr/include/x86_64-linux-gnu/gnu/stubs-64.h \
 /usr/lib/gcc/x86_64-linux-gnu/11/include/stddef.h \
 /usr/include/x86_64-linux-gnu/bits/types/locale_t.h \
 /usr/include/x86_64-linux-gnu/bits/types/__locale_t.h \
 /usr/include/strings.h \
 /usr/include/x86_64-linux-gnu/bits/strings_fortified.h \
 /usr/include/x86_64-linux-gnu/bits/string_fortified.h \
 /usr/include/stdio.h /usr/lib/gcc/x86_64-linux-gnu/11/include/stdarg.h \
 /usr/include/x86_64-linux-gnu/bits/types.h \
 /usr/include/x86_64-linux-gnu/bits/typesizes.h \
 /usr/include/x86_64-linux-gnu/bits/time64.h \
 /usr/include/x86_64-linux-gnu/bits/types/__fpos_t.h \
 /usr/include/x86_64-linux-gnu/bits/types/__mbstate_t.h \
 /usr/include/x86_64-linux-gnu/bits/types/__fpos64_t.h \
 /usr/include/x86_64-linux-gnu/bits/types/__FILE.h \
 /usr/include/x86_64-linux-gnu/bits/types/FILE.h \
 /usr/include/x86_64-linux-gnu/bits/types/struct_FILE.h \
 /usr/include/x86_64-linux-gnu/bits/stdio_lim.h \
 /usr/include/x86_64-linux-gnu/bits/floatn.h \
 /usr/include/x86_64-linux-gnu/bits/floatn-common.h \
 /usr/include/x86_64-linux-gnu/bits/stdio.h \
 /usr/include/x86_64-linux-gnu/bits/stdio2.h str_error.h

cmd_/usr/src/linux-5.15.106/samples/bpf/libbpf/staticobjs/str_error.o := gcc -Wp,-MD,/usr/src/linux-5.15.106/samples/bpf/libbpf/staticobjs/.str_error.o.d -Wp,-MT,/usr/src/linux-5.15.106/samples/bpf/libbpf/staticobjs/str_error.o -Wall -O2 -Wmissing-prototypes -Wstrict-prototypes -I./usr/include -I./tools/testing/selftests/bpf/ -I/usr/src/linux-5.15.106/samples/bpf/libbpf/include -I./tools/include -I./tools/perf -DHAVE_ATTR_TEST=0 -Wbad-function-cast -Wdeclaration-after-statement -Wformat-security -Wformat-y2k -Winit-self -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -Wno-system-headers -Wold-style-definition -Wpacked -Wredundant-decls -Wstrict-prototypes -Wswitch-default -Wswitch-enum -Wundef -Wwrite-strings -Wformat -Wno-type-limits -Wstrict-aliasing=3 -Wshadow -Wno-switch-enum -Werror -Wall -I. -I/usr/src/linux-5.15.106/samples/bpf/../..//tools/include -I/usr/src/linux-5.15.106/samples/bpf/../..//tools/include/uapi -fvisibility=hidden -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -D"BUILD_STR(s)=$(pound)s" -c -o /usr/src/linux-5.15.106/samples/bpf/libbpf/staticobjs/str_error.o str_error.c
