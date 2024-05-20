import os, sys
import argparse
import pickle
import subprocess
import signal
import time
import logging
from datetime import datetime
import shutil
from tqdm import tqdm

from utility import runCommand

class SrcMapping():
  symmap = {}

  def __init__(self, linuxpath):
    self.vmlinux = linuxpath + "/vmlinux"
    #self.readELF()

  def disassemble(self, funcname):
    ret, out, err = runCommand("gdb -batch --eval-command=\"disassemble " + funcname + "\" " + self.vmlinux)
    if "No symbol" in err:
      print("No symbol found")
      return []

    dump = out.split("\n")[1:-2]
    addr = []
    for l in dump:
      parts = l.split()
      if len(parts) < 5:
        addr.append((parts[0],parts[2],'None'))
      else:
        addr.append((parts[0],parts[2],parts[4]))
    return addr

  def addr2line(self, addr):
    ret, out, err = runCommand("/home/hotbpf/llvm-project/build/bin/llvm-symbolizer --obj=" + self.vmlinux + " " + addr)

    funcnames = {}
    lines = out.split("\n")[:-2]
    for i in range(0, len(lines), 2):
      funcnames[lines[i]] = lines[i+1].split(":")[-2]
    return funcnames

  def readELF(self):
    ret, out, err = runCommand("readelf -s " + self.vmlinux)
    syms = out.split("\n")[3:]
    for l in syms:
      if len(l.split()) < 8:
        continue
      self.symmap[l.split()[7]] = l.split()[3]

  def isFunc(self, funcname):
    if funcname in self.symmap:
      if self.symmap[funcname] == 'FUNC':
        return True
    return False

def src2addr_old(srclines, linuxpath):
  src = SrcMapping(linuxpath)

  with open(srclines, 'r') as f:
    lines = f.readlines()
  for l in lines:
    if len(l.split(':')) < 4:
      continue
    funcname = l.split(':')[1]
    linenum = l.split(':')[2]
    print(funcname, linenum)

    Callinst = False
    addrs = src.disassemble(funcname)
    for a in addrs:
      if 'call' in a[1] and 'alloc' in a[2]:
        funcnames = src.addr2line(a[0])
        for f,l in funcnames.items():
          if funcname == f and linenum == l:
            Callinst = True
        continue
      if 'call' not in a[1] and Callinst:
        Callinst = False
        print("found: ", a)

def get_symmap(linuxpath):
  symmap = {}
  ret, out, err = runCommand("readelf -s " + linuxpath)
  syms = out.split("\n")[3:]
  for l in syms:
    if len(l.split()) < 8:
      continue
    symmap[l.split()[7]] = int(l.split()[1], 16)
  return symmap

def src2addr_new(srclines, linuxpath, srcmapping):
  symmap = get_symmap(linuxpath)

  with open(srcmapping, "rb") as p:
    line2bin = pickle.load(p)

  with open(srclines, 'r') as f:
    lines = f.readlines()

  for l in lines:
    l = l.strip()
    funcname = l.split(' ')[0]
    filename = l.split(' ')[1].split(':')[0]
    linenum = l.split(' ')[1].split(':')[1]

    #for src,b in tqdm(line2bin.items()):
    for src,b in line2bin.items():
      if filename+":"+linenum+":" in src:
        for addr in b:
          print("{}+{}".format(funcname, hex(int(addr, 16) - symmap[funcname])))

      
if __name__ == '__main__':
  parser = argparse.ArgumentParser(prog=sys.argv[0], description='src2binary')
  parser.add_argument('action', action='store', type=str, choices=["old", "new"], help="")
  parser.add_argument('-s', dest='srclines', action='store', type=str, help="path to src lines")
  parser.add_argument('-k', dest='linuxpath', action='store', type=str, help="path to vmlinux")
  parser.add_argument('-m', dest='srcmap', action='store', type=str, help="path to kernel src2binary mapping, i.e., pickle file")
  args = parser.parse_args()

  if args.action == 'old':
    src2addr_old(args.srclines, args.linuxpath)
  elif args.action == 'new':
    src2addr_new(args.srclines, args.linuxpath, args.srcmap)