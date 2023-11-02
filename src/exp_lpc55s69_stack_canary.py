import random

from pifer import *

# change this in production!
random.seed(0)

if __name__ == "__main__":
    bin_path = "../binaries/lpcxpresso55s69_CoreMark_Print.bin"
    img_base = 0
    mcpu = "cortex-m33"
    compile_options = "-mfpu=fpv5-sp-d16 -mfloat-abi=hard"
    p = PIFER(bin_path=bin_path, img_base=img_base, arch=mcpu, compile_options=compile_options)

    canary_value = random.randint(0,0xffffffff)

    print(f"Canary value random generated: {canary_value}")

    call_list = []
    ret_list = []

    asm_enter = f'''
    LDR, R2, ={hex(canary_value)}
'''
    asm_leave = '''
'''

    

    enter_id = p.add_payload(asm_enter)
    leave_id = p.add_payload(asm_leave)

    for addr in call_list:
        p.add_addr_target(addr, enter_id)

    for addr in ret_list:
        p.add_addr_target(addr, leave_id)
    


    p.patch()