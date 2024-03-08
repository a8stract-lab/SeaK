cmd_/usr/src/linux-5.15.106/samples/bpf/modules.order := {  :; } | awk '!x[$$0]++' - > /usr/src/linux-5.15.106/samples/bpf/modules.order
