import os
files_path = "../Seak_memory_overhead/durable"
duration_time = (1,1000)
kernel_kinds = ["vanilla","l2cap","seq","sock","file2","fdtable","cred","64AAs"]
data_list = []
j = 0
for rt,ds,fs in os.walk(files_path):
    for filename in fs:
        j = j + 1
        kernel_kind = filename.split('.')[0].split('-')[0]
        with open(files_path+filename,'r') as file:
            i = 0
            for line in file:
                i = i + 1
                if duration_time[0] <= i <= duration_time[1]:
                    if j == 1:
                        data_list.append(float(line.split(' ')[0]))
                    else:
                        data_list[i-1]=data_list[i-1]+float(line.split(' ')[0])
        print(data_list)
data_list = [item / 3 for item in data_list]
with open("../Seak_memory_overhead/merged.txt","w") as file:
    for i in range(duration_time[0],duration_time[1]+1):
        file.write(f"{data_list[i-1]}\n")
file.close()