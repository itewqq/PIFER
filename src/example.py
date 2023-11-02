from pifer import *

# Configurations
bin_path = "../binaries/lpcxpresso55s69_led_blinky.bin"
img_base = 0
mcpu = "cortex-m33"
compile_options = "-mfpu=fpv5-sp-d16 -mfloat-abi=hard"
p = PIFER(bin_path=bin_path, img_base=img_base, arch=mcpu, compile_options=compile_options)

# Set the target
'''
.text:000007D4 80 B5                       PUSH            {R7,LR}

.text:00000806 0C 4B                       LDR             R3, =_data

.text:00000832 F5 E7                       B               loc_820
'''
target_list = [0x07D4, 0x0806, 0x0832] 

for addr in target_list:
    payload = f"MOV R1, R1\n"
    p.add_addr_and_payload(addr, payload)

p.patch()

print(f"Done")