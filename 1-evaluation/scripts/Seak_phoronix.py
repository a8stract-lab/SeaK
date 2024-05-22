import os
import pandas as pd
import numpy as np

testcases_name = "../Seak_phoronix"
src_dirs = ['vanilla', 'l2cap', 'seq', "cred","sk_filter","fdtable","file"]
index = ['Sockperf', 'OSBench', 'FFmpeg', '7-Zip Compression', 'OpenSSL', 'Redis','SQLite Speedtest',  'Apache HTTP Server']
columns = []
assign_number = {'Sockperf':-1, 'OSBench':1, 'FFmpeg':-1, '7-Zip Compression':-1, 'OpenSSL':-1, 'Redis':-1,'SQLite Speedtest':1,  'Apache HTTP Server':-1}

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
        test_num = 1
        for filename in fs:
            if filename == "result.txt":
                with open(testcases_name + '/' + dir + '/' + filename, 'r') as file:
                    print(filename)
                    i = 0
                    for line in file:
                        i = i+1
                        print(i)
                        print(line)
                        if len(line.split(':')) > 1:
                            key = line.split(':')[0]
                            value = line.split(':')[1]
                            if key in index:
                                values_dict[dir][key].append(float(value.split(' ')[1]))
                                if pd.isna(df.loc[key, kind]):
                                    df.loc[key, kind] = float(value.split(' ')[1])
                                else:
                                    df.loc[key, kind] += float(value.split(' ')[1])
                        if i == 8:
                            print(i)
                            break
    df.loc[:, kind] = df.loc[:, kind] / test_num

for dir in src_dirs:
    kind = dir.split('/')[0]
    for key in index:
        if kind != "vanilla":
            df.loc[key, kind + "_diff"] = assign_number[key]*(df.loc[key, kind] - df.loc[key, 'vanilla']) / df.loc[key, 'vanilla']

df.to_excel('../Results/Seak_phoronix.xlsx', sheet_name='Sheet1')
