import psutil
import time
import sys
def main(argv):
    FILE_NAME = argv[1]
    mem_list = list()
    try:
        while True:
            time.sleep(1)
            d = dict(psutil.virtual_memory()._asdict())
            # print(d)
            mem_list.append(d)
    finally:
        print('end')
        with open(FILE_NAME, 'w') as f:
            for x in mem_list:
                line = str(x['used']) + ' ' + str(x['available']) + ' ' + str(x['free']) + ' ' + str(x['slab']) + '\n'
                f.write(line)
    # used available free slab

if __name__ == "__main__":
    main(sys.argv)
