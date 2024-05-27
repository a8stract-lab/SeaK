import pandas as pd
import matplotlib.pyplot as plt
plt.rcParams["pdf.fonttype"] = 42
plt.rcParams["ps.fonttype"] = 42
import numpy as np
import os
files_path = "../SeaK_memory_overhead/"
length = 1000
height = 1300
duration_time = (1,length)
kernel_kinds = ["vanilla","l2cap","seq","merged","file","64AAs"]
#kernel_kinds = ["vanilla","freelist","kfence","slub"]
index = 0
apache = [15,-20,-25,15]
lmbench = [15,-15,-20,5]
dis = lmbench

kernels = {}
plt.figure(figsize=(8, 4))
x = np.linspace(1,duration_time[1]-duration_time[0]+1,duration_time[1]-duration_time[0]+1)
first_max = 0
for rt,ds,fs in os.walk(files_path):
    for filename in fs:
        values = []
        kernel_kind = filename.split('.')[0].split('-')[0]
        value_min = 100000000000
        with open(files_path+filename,'r') as file:
            i = 1
            for line in file:
                if duration_time[0] <= i <= duration_time[1]:
                    values.append(float(line.split(' ')[index]))
                    if value_min > float(line.split(' ')[index]):
                        value_min = float(line.split(' ')[index])
                i = i + 1
        for i in range(0,len(values)):
            if kernel_kind == "kfence":
                values[i] = (values[i] - value_min + 512000000)/1000000
            else:
                values[i] = (values[i] - value_min)/1000000
        kernels[kernel_kind] = values
    firsts = []
    for kind in kernel_kinds:
        print(kind)
        firsts.append(kernels[kind][0])
    print(firsts)
    # firsts.sort()
    # first_max = firsts[-1]
    # for kind in kernel_kinds:
    #     first_one = kernels[kind][0]
    #     for i in range(0,len(kernels[kind])):
    #         kernels[kind][i] = kernels[kind][i]+first_max-first_one
    plt.plot(x, kernels[kernel_kinds[0]], color = 'red',label = "Vanilla",zorder = 2)
    plt.plot(x, kernels[kernel_kinds[1]], color = 'pink',label = "Cold",zorder = 2)
    plt.plot(x, kernels[kernel_kinds[2]], color = 'blue',label = "Hot",zorder = 4)
    plt.plot(x, kernels[kernel_kinds[3]], color = 'orange',label = "Durable(avg.)",zorder = 3)
    plt.plot(x, kernels[kernel_kinds[4]], color = 'aquamarine',label = "file",zorder = 4)
    plt.plot(x, kernels[kernel_kinds[5]], color = 'purple',label = "64AAs",zorder = 1)
    max_idx_y1 = kernels[kernel_kinds[0]].index(max(kernels[kernel_kinds[0]]))
    plt.scatter(max_idx_y1+1,max(kernels[kernel_kinds[0]]) , color='black', s=20, label='Max Point',zorder=3)
    plt.plot([min(x), max_idx_y1], [max(kernels[kernel_kinds[0]]), max(kernels[kernel_kinds[0]])], '--k', lw = 1)
    # plt.annotate(f'{max(kernels["vanilla"])}', xy=(min(x), max(kernels["vanilla"])), xytext=(-15, 0), textcoords='offset points', va='center', ha='right', color='r')
    # plt.annotate(f'{int(max(kernels["vanilla"]))}',
    #              (x[max_idx_y1], kernels["vanilla"][max_idx_y1]),
    #              textcoords="offset points",
    #              xytext=(0,dis[0]),
    #              ha='center')
    #
    # # 找到并标注 y2 的最高点
    max_idx_y2 = kernels[kernel_kinds[1]].index(max(kernels[kernel_kinds[1]]))
    plt.scatter(max_idx_y2+1,max(kernels[kernel_kinds[1]]) , color='black', s=20,zorder=3)
    plt.plot([min(x), max_idx_y2], [max(kernels[kernel_kinds[1]]), max(kernels[kernel_kinds[1]])], '--k', lw = 1)
    # plt.annotate(f'freelist: {int(max(kernels["freelist"]))}',
    #              (x[max_idx_y2], kernels["freelist"][max_idx_y2]),
    #              textcoords="offset points",
    #              xytext=(0,dis[1]),
    #              ha='center',
    #              arrowprops=dict(facecolor='black', arrowstyle='->'))
    #
    max_idx_y3 = kernels[kernel_kinds[2]].index(max(kernels[kernel_kinds[2]]))
    plt.scatter(max_idx_y3+1,max(kernels[kernel_kinds[2]]) , color='black', s=20, zorder=3)
    plt.plot([min(x), max_idx_y3], [max(kernels[kernel_kinds[2]]), max(kernels[kernel_kinds[2]])], '--k',lw = 1)
    # plt.annotate(f'kfence: {int(max(kernels["kfence"]))}',
    #              (x[max_idx_y3], kernels["kfence"][max_idx_y3]),
    #              textcoords="offset points",
    #              xytext=(0,dis[2]),
    #              ha='center',
    #              arrowprops=dict(facecolor='black', arrowstyle='->'))
    #
    max_idx_y4 = kernels[kernel_kinds[3]].index(max(kernels[kernel_kinds[3]]))
    plt.scatter(max_idx_y4+1,max(kernels[kernel_kinds[3]]) , color='black', s=20,zorder=3)
    plt.plot([min(x), max_idx_y4], [max(kernels[kernel_kinds[3]]), max(kernels[kernel_kinds[3]])], '--k',lw = 1)
    # plt.annotate(f'slub: {int(max( kernels["slub"]))}',
    #              (x[max_idx_y4],  kernels["slub"][max_idx_y4]),
    #              textcoords="offset points",
    #              xytext=(0,dis[3]),
    #              ha='center',
    #              arrowprops=dict(facecolor='black', arrowstyle='->'))
    max_idx_y5 = kernels[kernel_kinds[4]].index(max(kernels[kernel_kinds[4]]))
    plt.scatter(max_idx_y5+1,max(kernels[kernel_kinds[4]]) , color='black', s=20,zorder=3)
    plt.plot([min(x), max_idx_y5], [max(kernels[kernel_kinds[4]]), max(kernels[kernel_kinds[4]])], '--k',lw = 1)

    max_idx_y6 = kernels[kernel_kinds[5]].index(max(kernels[kernel_kinds[5]]))
    plt.scatter(max_idx_y6+1,max(kernels[kernel_kinds[5]]) , color='black', s=20,zorder=3)
    plt.plot([min(x), max_idx_y6], [max(kernels[kernel_kinds[5]]), max(kernels[kernel_kinds[5]])], '--k',lw = 1)
plt.xlim(0, max(x))
plt.ylim(0,height)
plt.xlabel('Time Elapsed (s)', fontsize=11, color='black')
plt.ylabel('MBytes',rotation=0, labelpad=10, fontsize=11, color='black')
ax = plt.gca()
# 调整标签位置
ax.yaxis.set_label_coords(-0.05,1.06)
ax.yaxis.get_label().set_verticalalignment('top')
plt.legend(loc='upper left',fontsize=11)
#plt.title("lmbench")
plt.savefig('../Results/SeaK_memory_overhead.pdf',dpi=1000,bbox_inches='tight')
