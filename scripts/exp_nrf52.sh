#!/bin/bash

# Flash:

nrfjprog --program ../binaries/zephyr.patched.bin --chiperase --verify

# Tested
# text:00000402 98 47                       BLX     R3              ; gpio_nrfx_port_toggle_bits
python pifer.py -p "../binaries/zephyr.bin" -b 0x0 -t 0x00000402 -a cortex-m4

# Tested:
# text:00000412 F2 E7                       B       loc_3FA
python patch.py -p "../binaries/zephyr.bin" -b 0x0 -t 0x00000412 -a cortex-m4 
nrfjprog --program ../binaries/zephyr.patched.bin --chiperase --verify

# Tested:
# text:0000040E 03 F0 61 FD                 BL      z_impl_k_sleep
python patch.py -p "../binaries/zephyr.bin" -b 0x0 -t 0x0000040E -a cortex-m4 
nrfjprog --program ../binaries/zephyr.patched.bin --chiperase --verify

# Tested:
# text:000003EE 0B 4A                       LDR     R2, =0x60001    ; flags
python patch.py -p "../binaries/zephyr.bin" -b 0x0 -t 0x000003EE -a cortex-m4 
nrfjprog --program ../binaries/zephyr.patched.bin --chiperase --verify

# Tested:
# text:000003F0 0D 21                       MOVS    R1, #0xD        ; pin
python patch.py -p "../binaries/zephyr.bin" -b 0x0 -t 0x000003F0 -a cortex-m4 
nrfjprog --program ../binaries/zephyr.patched.bin --chiperase --verify

# Tested:
# text:000003FA 4F F4 00 51                 MOV.W   R1, #0x2000     ; mask
python patch.py -p "../binaries/zephyr.bin" -b 0x0 -t 0x000003FA -a cortex-m4 
nrfjprog --program ../binaries/zephyr.patched.bin --chiperase --verify

# text:000003F8 0C DB                       BLT     locret_414
python pifer.py -p "../binaries/zephyr.bin" -b 0x0 -t 0x000003F8 -a cortex-m4
nrfjprog --program ../binaries/zephyr.patched.bin --chiperase --verify

# text:000003DE C8 B1                       CBZ     R0, locret_414
python pifer.py -p "../binaries/zephyr.bin" -b 0x0 -t 0x000003DE -a cortex-m4
nrfjprog --program ../binaries/zephyr.patched.bin --chiperase --verify

# text:0000047C DF E8 00 F0                 TBB.W   [PC,R0]         ; switch jump
python pifer.py -p "../binaries/zephyr.bin" -b 0x0 -t 0x0000047C -a cortex-m4
nrfjprog --program ../binaries/zephyr.patched.bin --chiperase --verify

# Latency:
## all
python exp_switch_only.py -p "../binaries/nrf52_latency.bin" -b 0x0 -t 0x00000696 -a cortex-m4
## measure UDF: 237.1ns
## measue LR:
python exp_switch_only.py -p "../binaries/nrf52_latency.bin" -b 0x0 -t 0x0000068E -a cortex-m4

# Airtag
#ROM:000138B0 07 F0 5E FA                 BL      sub_1AD70
# ROM:000138B4 40 BF                       SEV
# ROM:000138B6 20 BF                       WFE
# python exp_switch_only.py -p "../binaries/airtag.0x80000.bin" -b 0x0 -t 0x00138B6 -a cortex-m4

python exp_airtag_hook.py -p "../binaries/airtag.0x80000.bin" -b 0x0 -t 0x00138B6 -a cortex-m4

python exp_airtag_hook.py -p "../binaries/airtag.0x80000.bin" -b 0x0 -t 0x0304a6 -a cortex-m4

nrfjprog --program ../binaries/airtag.0x80000.patched.bin --chiperase --verify
nrfjprog --memwr 0x10001014 --val 0x00078000
nrfjprog --memwr 0x10001018 --val 0x0007e000


# zephyr

# text:00010484 ED 1A                       SUBS    R5, R5, R3 ; R2=j
# change to 
# SUBS    R5, R5, R2
python exp_zephyr_vul.py -p "../binaries/zephyr.shell.vul.bin" -b 0x0 -t 0x010484 -a cortex-m4