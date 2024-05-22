import os
import pandas as pd
import numpy as np

testcases_name = "../EF_lmbench"
src_dirs = ['vanilla', 'C1', 'C2', "C3"]
index = ['Simple syscall', 'Simple read', 'Simple write', 'Select on 100 fd\'s', 'Signal handler installation', 'Signal handler overhead',  'Process fork+exit', 'Process fork+execve', 'Process fork+/bin/sh -c',  'UDP latency using localhost',  'TCP/IP connection cost to localhost', 'AF_UNIX sock stream bandwidth', 'Pipe bandwidth']
columns = []
assign_number = {'Simple syscall':1, 'Simple read':1, 'Simple write':1, 'Select on 100 fd\'s':1, 'Signal handler installation':1, 'Signal handler overhead':1,  'Process fork+exit':1, 'Process fork+execve':1, 'Process fork+/bin/sh -c':1,  'UDP latency using localhost':1,  'TCP/IP connection cost to localhost':1, 'AF_UNIX sock stream bandwidth':-1, 'Pipe bandwidth':-1}

for dir in src_dirs:
    kind = dir.split('/')[0]
    columns.append(kind)
    if kind != "vanilla":
        columns.append(kind + "_diff")

df = pd.DataFrame(columns=columns, index=index)

values_dict = {dir: {key: [] for key in index} for dir in src_dirs}

for dir in src_dirs:
    kind = dir.split('/')[0]
    for rt, ds, fs in os.walk(testcases_name + '/' + dir):
        test_num = len(fs)
        for filename in fs:
            with open(testcases_name + '/' + dir + '/' + filename, 'r') as file:
                for line in file:
                    if len(line.split(':')) > 1:
                        key = line.split(':')[0]
                        value = line.split(':')[1]
                        if key in index:
                            values_dict[dir][key].append(float(value.split(' ')[1]))
                            if pd.isna(df.loc[key, kind]):
                                df.loc[key, kind] = float(value.split(' ')[1])
                            else:
                                df.loc[key, kind] += float(value.split(' ')[1])
    df.loc[:, kind] = df.loc[:, kind] / test_num

for dir in src_dirs:
    kind = dir.split('/')[0]
    for key in index:
        if kind != "vanilla":
            df.loc[key, kind + "_diff"] = assign_number[key]*(df.loc[key, kind] - df.loc[key, 'vanilla']) / df.loc[key, 'vanilla']

df.to_excel('../Results/EF_lmbench.xlsx', sheet_name='Sheet1')
