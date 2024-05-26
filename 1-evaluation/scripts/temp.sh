#!/bin/bash
cd ..
python3 scripts/phoronix_parse.py /var/lib/phoronix-test-suite/test-results/efc1/composite.xml EF_phoronix/C1/result.txt
python3 scripts/phoronix_parse.py /var/lib/phoronix-test-suite/test-results/efc2/composite.xml EF_phoronix/C2/result.txt
python3 scripts/phoronix_parse.py /var/lib/phoronix-test-suite/test-results/efc3/composite.xml EF_phoronix/C3/result.txt
python3 scripts/phoronix_parse.py /var/lib/phoronix-test-suite/test-results/efvanilla/composite.xml EF_phoronix/vanilla/result.txt
python3 scripts/phoronix_parse.py /var/lib/phoronix-test-suite/test-results/seakl2cap/composite.xml Seak_phoronix/l2cap/result.txt
python3 scripts/phoronix_parse.py /var/lib/phoronix-test-suite/test-results/seakseq/composite.xml Seak_phoronix/seq/result.txt
python3 scripts/phoronix_parse.py /var/lib/phoronix-test-suite/test-results/seakfdtable/composite.xml Seak_phoronix/fdtable/result.txt
python3 scripts/phoronix_parse.py /var/lib/phoronix-test-suite/test-results/seakcred/composite.xml Seak_phoronix/cred/result.txt
python3 scripts/phoronix_parse.py /var/lib/phoronix-test-suite/test-results/seakfile/composite.xml Seak_phoronix/file/result.txt
python3 scripts/phoronix_parse.py /var/lib/phoronix-test-suite/test-results/seakvanilla/composite.xml Seak_phoronix/vanilla/result.txt
python3 scripts/phoronix_parse.py /var/lib/phoronix-test-suite/test-results/seakskfilter/composite.xml Seak_phoronix/sk_filter/result.txt
