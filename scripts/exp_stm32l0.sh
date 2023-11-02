#!/bin/bash

# .text:08000448 BE E7                       B       loc_80003C8
python patch.py -p "../binaries/exp_NUCLEO_L073RZ.bin"  -b 0x08000000 -t 0x08000448 -a cortex-m0

openocd -f  interface/stlink.cfg -f target/stm32l0.cfg -c "program /home/itemqq/fault/fast_fault//binaries/exp_NUCLEO_L073RZ.patched.bin exit 0x8000000"