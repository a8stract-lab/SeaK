#!/bin/bash

cd ..

if [ -d "EF_lmbench" ]; then
	:
else
	mkdir EF_lmbench
fi

if [ -d "Results" ]; then
	:
else
	mkdir Results
fi

if [ -d "EF_memory_overhead" ]; then
	:
else
	mkdir EF_memory_overhead
fi

if [ -d "SeaK_memory_overhead" ]; then
	:
else
	mkdir SeaK_memory_overhead
fi

cd EF_lmbench
if [ -d "vanilla" ]; then
	:
else
	mkdir vanilla
fi
if [ -d "C1" ]; then
	:
else
	mkdir C1
fi
if [ -d "C2" ]; then
	:
else
	mkdir C2
fi
if [ -d "C3" ]; then
	:
else
	mkdir C3
fi
cd ../scripts


cd ..

if [ -d "EF_phoronix" ]; then
	:
else
	mkdir EF_phoronix
fi

cd EF_phoronix
if [ -d "vanilla" ]; then
	:
else
	mkdir vanilla
fi
if [ -d "C1" ]; then
	:
else
	mkdir C1
fi
if [ -d "C2" ]; then
	:
else
	mkdir C2
fi
if [ -d "C3" ]; then
	:
else
	mkdir C3
fi
cd ../scripts

cd ..

if [ -d "SeaK_phoronix" ]; then
	:
else
	mkdir SeaK_phoronix
fi

cd SeaK_phoronix
if [ -d "vanilla" ]; then
	:
else
	mkdir vanilla
fi
if [ -d "l2cap" ]; then
	:
else
	mkdir l2cap
fi
if [ -d "seq" ]; then
	:
else
	mkdir seq
fi
if [ -d "cred" ]; then
	:
else
	mkdir cred
fi
if [ -d "sk_filter" ]; then
	:
else
	mkdir sk_filter
fi
if [ -d "fdtable" ]; then
	:
else
	mkdir fdtable
fi
if [ -d "file" ]; then
	:
else
	mkdir file
fi
cd ../scripts

cd ..

if [ -d "SeaK_lmbench" ]; then
	:
else
	mkdir SeaK_lmbench
fi

cd SeaK_lmbench
if [ -d "vanilla" ]; then
	:
else
	mkdir vanilla
fi
if [ -d "l2cap" ]; then
	:
else
	mkdir l2cap
fi
if [ -d "seq" ]; then
	:
else
	mkdir seq
fi
if [ -d "cred" ]; then
	:
else
	mkdir cred
fi
if [ -d "sk_filter" ]; then
	:
else
	mkdir sk_filter
fi
if [ -d "fdtable" ]; then
	:
else
	mkdir fdtable
fi
if [ -d "file" ]; then
	:
else
	mkdir file
fi
cd ../scripts
