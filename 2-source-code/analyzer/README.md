# Crash report analyzer for HotBPF



### Find allocation sites of objects
General command:
```
./analyzer -struct <struct_name> `find <bitcode_path>`
```

Example for `bug-kobject_add_internal` sample, the vulnearable object is `hci_conn`, we run:
```
/home/hotbpf/analyzer/build/lib/analyzer -struct hci_conn `find /home/hotbpf/linux-5.15.106/net/bluetooth/ -name "*.bc"`
```

Output will be:
```
Total 38 file(s)
dumping location of allocating hci_conn
hci_conn_add net/bluetooth/hci_conn.c:525
Possible Caller for hci_conn_add
hci_connect_le_scan
hci_connect_sco
hci_conn_request_evt
hci_connect_acl
hci_cs_create_conn
le_conn_complete_evt
hci_conn_complete_evt
phylink_add
hci_connect_le
```