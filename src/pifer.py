import os
import shutil
from typing import List

from template_target import params_asm, template_string, template_string_M0, template_string_Exp_Switch_Only
from utils import *
from translator import TRANS


class PIFER:
    __slots__ = "bin_path", "img_base", "arch", "compile_options", \
        "patched_path", "params_asm", "asm_template", "params_asm", "payload", "addr_target", "stack_free_base"

    def __init__(self, bin_path: str, img_base: int, arch: str, compile_options="", stack_free_base=0x20000000, vtable_offset=0):
        assert bin_path[-4:] == ".bin"
        self.patched_path = bin_path[:-4] + ".patched.bin"
        self.bin_path = bin_path
        self.img_base = img_base
        self.arch = arch
        self.compile_options = compile_options
        self.stack_free_base = stack_free_base
        if arch == "cortex-m0":
            self.asm_template = template_string_M0
        else:
            self.asm_template = template_string
        self.params_asm = params_asm
        # retrieve info from binary
        self.get_binary_params(vtable_offset)
        self.payload = []
        self.addr_target = {}

    def dup_firm(self):
        shutil.copy(self.bin_path, self.patched_path)

    def get_new_seg_offset(self):
        size_ori = os.path.getsize(self.bin_path)
        size_padded = ((size_ori + CODE_ALIGN - 1) // CODE_ALIGN) * CODE_ALIGN
        return size_ori, size_padded


    def ext_firm(self, bin_bytes: bytes) -> int:
        size_ori, new_seg_offset = self.get_new_seg_offset()
        bin_bytes = bin_bytes.rjust(
            len(bin_bytes) + new_seg_offset - size_ori, b'\x00')
        with open(self.patched_path, "ab") as f:  # append to original file
            f.write(bin_bytes)
        return new_seg_offset

    def get_binary_params(self, vtable_img_offset=0x0, skip_reset_header=0):
        with open(self.bin_path, "rb") as f:
            f.seek(vtable_img_offset, 0)
            stack_base = self.stack_free_base
            f.seek(vtable_img_offset + 0x4, 0)
            reset_handler_ori = int.from_bytes(f.read(4), "little")
            f.seek(vtable_img_offset + 0xC, 0)
            hardfault_handler_ori = int.from_bytes(f.read(4), "little")
        # using the unused memory to store the global context
        self.params_asm["stack_bottom"] = stack_base # + 0x10
        print("[d] global context is at:", hex(stack_base + 0x10))

        # Note: if the original reset handler auto reset Sp, we need to bypass that
        # reset_handler_ori += skip_reset_header
        # self.params_asm["stack_bottom_ori"] = hex(stack_base)
        # self.params_asm["stack_bottom"] = hex(stack_base - 0x50)

        self.params_asm["hardfault_handler_ori"] = hex(hardfault_handler_ori)
        # self.params_asm["reset_handler_ori"] = hex(reset_handler_ori)
        return self.params_asm
    
    def get_target_params(self, target_pc_list, img_base=0x0, instlen=0x0):
        for target_pc in target_pc_list:
            target_pc_offset = target_pc - img_base
            code_bytes = b""
            with open(self.bin_path, "rb") as f:
                f.seek(target_pc_offset, 0)
                code_bytes = f.read(4)

            inst, inst_len = disasm_helper(code_bytes, target_pc, inst_len=instlen)
            print("[d] ", inst)
            print("[d] ", inst_len)

            next_pc= (target_pc + inst_len) | 1 # | 1 for thumb, real next pc

            self.params_asm['inst_len'] = hex(inst_len)
            self.params_asm["comparator_next_pc"] += f"\n\tLDR R1, ={hex(target_pc)}\n\tCMP R0, R1\n\tBEQ next_pc_label_{hex(target_pc)}\n"
            self.params_asm["next_pc_loader"] += f"\n\tnext_pc_label_{hex(target_pc)}:\n\tLDR IP, ={hex(next_pc)}\n\tBX LR\n\t.LTORG\n\n"

            # print("0x%x:\t%s\t%s" %(inst.address, inst.mnemonic, inst.op_str))

            trans = TRANS(self.params_asm, self.arch.lower() == 'cortex-m0')
            inserted_ins, self.params_asm = trans.translate(inst)

            patch_bytes_img(self.patched_path, target_pc_offset, inserted_ins)

            # inserted_ins = inst_type.to_bytes(1, "little") + b"\xDE"
            # if inst_len > 2:
            #     inserted_ins += b"\x00\xBF"

            # return params_asm, inserted_ins

    def set_newcode(self):
        comp, ncode = payload2asm(self.addr_target ,self.payload)
        self.params_asm["comp_ncode"] = comp
        self.params_asm["newcode"] = ncode

    def add_addr_target(self, addr, target):
        for _ in self.addr_target:
            if _ == addr:
                raise MultiHooksSingleAddrPiferException(
                    "Multiple hooks for same addr is not supported now!")
        self.addr_target[addr] = target

    def add_payload(self, asm):
        cur_id = len(self.payload)
        self.payload.append(AttributeDict({"payload_id":cur_id, "asm": asm}))
        return cur_id
    
    def add_addr_and_payload(self, addr, asm):
        payload_id = self.add_payload(asm)
        self.add_addr_target(addr, payload_id)

    def patch_sp_hardcode(self, img_base, addrs, sp_str):
        assert sp_str[:2] == "0x"
        sp_bytes = int(sp_str, 0x10).to_bytes(4, "little")
        for addr in addrs:
            patch_bytes_img(self.patched_path, addr - img_base, sp_bytes)

    def patch(self):
        img_base = self.img_base
        self.dup_firm()
        self.params_asm = self.get_binary_params()
        
        target_pc_list = [x for x in self.addr_target]
        self.get_target_params(target_pc_list, img_base=img_base)
        self.set_newcode()
        # compile the assembly modules
        _, new_seg_offset = self.get_new_seg_offset()
        make_target_asm(self.asm_template, self.params_asm)
        compile_target(base_addr=new_seg_offset+self.img_base, mcpu=self.arch, add_options=self.compile_options)
        # get the bytes to be appended
        bin_bytes = get_new_bytes_offsets()
        # stretch the original binary
        new_hardfault_offset = self.ext_firm(bin_bytes)
        # patch target bytes
        patch_bytes_img(self.patched_path, new_hardfault_offset, bin_bytes)
        patch_binary_handlers(self.patched_path, img_base, img_base+new_hardfault_offset)

        

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='PIFER.')
    # required path, image base, target pc
    parser.add_argument('-p', '--path', type=str, required=True,
                        metavar="PATH_TO_BIN", help='path to the firmware binary')
    parser.add_argument('-b', '--base', type=auto_int, required=True,
                        metavar="IMG_BASE", help='base address of the binary image')
    parser.add_argument('-t', '--target', type=auto_int, required=True,
                        metavar="TARGET_PC", help='instrument target address')
    parser.add_argument('-a', '--mcpu', type=str, metavar="MCPU",
                        default='cortex-m4', help='architecture of the target chip(lowercase)')
    # optional params: arch, skip reset header
    # parser.add_argument('-l', '--sp-list', type=auto_int, metavar="offset",
    #                     action='append', help='list of hardcoded init-sp addresss')

    args = parser.parse_args()

    bin_path, img_base, target_pc, mcpu = args.path, args.base, args.target, args.mcpu
    # sp_hardcode_addrs = args.sp_list

    p = PIFER(bin_path=bin_path, img_base=img_base, arch=mcpu)

    payload_id = p.add_payload('''NOP
        MOV R0, 0x00
        MOV R1, 0x01
        MOV R2, 0x02
        MOV R3, 0x03
        MOV R4, 0x04
        MOV R5, 0x05
    ''')
    p.add_addr_target(target_pc, payload_id)
    # manully test
    # p.add_addr_and_payload(0x00000818,'''NOP
    #     MOV R0, 0x00
    #     MOV R1, 0x01
    #     MOV R2, 0x02
    #     MOV R3, 0x03
    #     MOV R4, 0x04
    #     MOV R5, 0x05
    #     MOV R6, 0x06
    # ''')


    p.patch()
