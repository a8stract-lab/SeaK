import psutil
import time
import sys
def main(argv):
    FILE_NAME = argv[1]
    mem_list = list()
    print("start")
    try:
        i = 0
        while i<=int(argv[2]):
            time.sleep(1)
            d = dict(psutil.virtual_memory()._asdict())
            # print(d)
            mem_list.append(d)
            i=i+1
    except KeyboardInterrupt:
        print('end')
        with open(FILE_NAME, 'w') as f:
            for x in mem_list:
                line = str(x['used']) + ' ' + str(x['available']) + ' ' + str(x['free']) + ' ' + str(x['slab']) + '\n'
                f.write(line)
    print('end')
    with open(FILE_NAME, 'w') as f:
        for x in mem_list:
            line = str(x['used']) + ' ' + str(x['available']) + ' ' + str(x['free']) + ' ' + str(x['slab']) + '\n'
            f.write(line)
    # used available free slab

if __name__ == "__main__":
    main(sys.argv)
