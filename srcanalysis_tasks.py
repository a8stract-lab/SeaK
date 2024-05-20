from utility import runCommand
from tqdm import tqdm
from celery import Celery

app = Celery('tasks', backend='rpc://', broker='pyamqp://guest@sched4sec.sl.res.ibm.com//')

@app.task
def addr2line_dist(start, end, vmlinux_addr, vmlinux):
  vmlinuxaddr = []
  with open(vmlinux_addr, "r") as f:
    vmlinuxaddr = f.readlines()
  for i in range(len(vmlinuxaddr)):
    vmlinuxaddr[i] = vmlinuxaddr[i].strip()

  line2bin = {}
  for s in tqdm(range(start, end)):
    ret, out, err = runCommand("llvm-symbolizer-10 --obj=" + vmlinux + " " + vmlinuxaddr[s])

    srcline = ''
    lines = out.split("\n")[:-2]
    for i in range(0, len(lines), 2):
      srcline += lines[i+1]+","

    if srcline not in line2bin:
      line2bin[srcline] = []
    line2bin[srcline].append(vmlinuxaddr[s])

  return line2bin