import argparse
import subprocess
import os
import shutil
from pwn import ELF
from string import Template
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB, KsError

from utils import *
from template_target import params_asm, template_string, template_string_M0, template_string_Exp_Switch_Only

ARM_REGS = ['r3',
            'r4',
            'r5',
            'r6',
            'r7',
            'r8',
            'r9',
            'r10',
            'r11',
            'r12',
            'ip']

ARM_REGS_M0 = ['r4',
            'r5',
            'r6',
            'r7',
            'r8',
            'r9',
            'r10',
            'r11',
            'r12',
            'ip']

INST_TYPE = {
    'ins_no_pc': 0xAA,
    'ins_pc_relative_in': 0xAB,
    'ins_pc_relative_out': 0xAC,
    'ins_branch_link': 0xAD
}

IS_M0 = False

def compile_helper(code):
    try:
        ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
        encoding, count = ks.asm(code)
        print("%s = %s (number of statements: %u)" % (code, encoding, count))
    except KsError as e:
        print("ERROR: %s" % e)


def patch_bytes_img(file_path: str, img_offset: int, target_bytes: bytes):
    try:
        with open(file_path, "r+b") as f:
            f.seek(img_offset)
            f.write(target_bytes)
        print(f"\t[+] patched {hex(img_offset)}")
    except Exception as e:
        print(e)
        print(f"\t[x] patched {hex(img_offset)} error!")


def patch_single_inst(file_path: str, img_base: int, target_pc: int, inserted_ins: bytes):
    file_path_patched = get_file_path_patched(file_path)
    patch_bytes_img(file_path_patched, target_pc - img_base,
                    inserted_ins)
    return


def patch_binary_handlers(file_path: str, img_base: int, reset_handler_new: int, hf_handler_new: int):
    file_path_patched = get_file_path_patched(file_path)
    reset_handler_vtable_img_offset = 0x4
    hard_fault_vtable_offset = 0xC
    usage_fault_vtable_offset = 0x18
    patch_bytes_img(file_path_patched, reset_handler_vtable_img_offset,
                    (reset_handler_new + 1).to_bytes(4, "little"))
    patch_bytes_img(file_path_patched, hard_fault_vtable_offset,
                    (hf_handler_new + 1).to_bytes(4, "little"))
    patch_bytes_img(file_path_patched, usage_fault_vtable_offset,
                    (hf_handler_new + 1).to_bytes(4, "little"))


def get_new_bytes_offsets(elf_path="a.out"):
    result = b""
    new_hard_fault_handler_offset = 0
    with open(elf_path, "rb") as f:
        all_bytes = f.read()
        elf = ELF(elf_path)
        new_hard_fault_handler_offset = elf.symbols["new_hard_fault_handler"]
        text_start, text_size = elf.get_section_by_name(
            '.text').header.sh_offset, elf.get_section_by_name('.text').header.sh_size
        result = all_bytes[text_start:text_start+text_size]
    return result, new_hard_fault_handler_offset


def compile_target(target="make_target.S", mcpu="cortex-m4"):
    cmd_str = f"arm-none-eabi-as -mthumb  -mcpu={mcpu} {target}"
    subprocess.run(cmd_str, shell=True)


def make_target_asm(params=params_asm):
    if IS_M0:
        t = Template(template_string_M0)
        with open("make_target.S", "w") as f:
            f.write(t.substitute(params))
    else:
        t = Template(template_string)
        with open("make_target.S", "w") as f:
            f.write(t.substitute(params))


def duplicate_firmware(file_path):
    file_path_patched = get_file_path_patched(file_path)
    shutil.copy(file_path, file_path_patched)


def extend_firmware(file_path, bin_bytes: bytes):
    file_path_patched = get_file_path_patched(file_path)
    size_ori = os.path.getsize(file_path)
    size_padded16 = ((size_ori+16-1)//16)*16
    new_seg_offset = size_padded16
    bin_bytes = bin_bytes.rjust(len(bin_bytes)+size_padded16-size_ori, b'\x00')
    with open(file_path_patched, "ab") as f:  # append to original file
        f.write(bin_bytes)
    return new_seg_offset


def get_binary_params(file_path: str, vtable_img_offset=0x0, skip_reset_header=0):
    stack_base, hardfault_handler_ori, reset_handler_ori = 0x0, 0x0, 0x0
    with open(file_path, "rb") as f:
        f.seek(vtable_img_offset, 0)
        stack_base = int.from_bytes(f.read(4), "little")
        f.seek(vtable_img_offset + 0x4, 0)
        reset_handler_ori = int.from_bytes(f.read(4), "little")
        f.seek(vtable_img_offset + 0xC, 0)
        hardfault_handler_ori = int.from_bytes(f.read(4), "little")

    # Note: if the original reset handler auto reset Sp, we need to bypass that
    reset_handler_ori += skip_reset_header

    params_asm["stack_base"] = hex(stack_base)
    params_asm["stack_bottom"] = hex(stack_base - 0x10)
    params_asm["hardfault_handler_ori"] = hex(hardfault_handler_ori)
    params_asm["reset_handler_ori"] = hex(reset_handler_ori)
    return params_asm


def patch_sp_hardcode(file_path, img_base, addrs, sp_str):
    assert sp_str[:2] == "0x"
    sp_bytes = int(sp_str, 0x10).to_bytes(4, "little")
    for addr in addrs:
        patch_bytes_img(file_path, addr - img_base, sp_bytes)


def get_free_register(inst):
    used_regs = inst.op_str
    stacked_regs_offset = {"r0": 0x0, "r1": 0x4,
                           "r2": 0x8, "r3": 0xC, "r12": 0x10, "ip": 0x10}

    if IS_M0:
        regs = ARM_REGS_M0
    else:
        regs = ARM_REGS
    for r in regs:
        if r not in used_regs:
            if r == "ip":
                r = "r12"
            # if in [r0-r3, r12]
            if r in stacked_regs_offset:
                params_asm["set_stacked_regs_code"] = f"ADD R0, R1, #{stacked_regs_offset[r]}\n\tSTR {r}, [R0]"
            return r
    raise NoFreeRegPiferException(f"cannot find free register for {inst}")


def translate_b_bx(inst):
    pc = inst.address
    free_reg = get_free_register(inst)
    if inst.mnemonic.startswith("bx"):
        reg_list = inst.op_str.replace(",", " ").split()
        assert len(reg_list) == 1
        target_reg = reg_list[0]
        code = "MOV " + free_reg + ", " + target_reg
    else:
        target_pc = int(inst.op_str[1:], 0x10)
        # this is for cortex-m0
        code = "PUSH {R0}"
        code += "\n\tLDR R0, =" + hex(target_pc)
        code += "\n\tMOV " + free_reg + ", R0"
        code += "\n\tPOP {R0}"

    params_asm['Rx'] = free_reg
    params_asm['pc_relative_translated_code'] = code


def translate_bl_blx(inst):
    translate_b_bx(inst)


def translate_cbz_cbnz():
    raise NotImplementedError


def translate_tbb_tbh():
    raise NotImplementedError


def translate_pc(inst):
    pc = inst.address
    free_reg = get_free_register(inst)
    # replace the PC with Rx
    code = inst.mnemonic + " " + inst.op_str
    code = code.replace("pc", free_reg)

    params_asm['Rx'] = free_reg
    params_asm['pc_relative_translated_code'] = code


def translate_no_pc(inst):
    # for no pc we just put the exactly same instruction
    code = inst.mnemonic + " " + inst.op_str
    params_asm['no_pc_inst_ori'] = code


def get_inst(code_bytes, target_pc, inst_len=0):
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    if inst_len == 0:
        try:
            res = list(md.disasm(code_bytes[:4], target_pc))
            if len(res) == 0:
                raise InstDisPiferException(
                    "Failed to disasmble the target instruction!")
            inst_len = res[0].size
        except InstDisPiferException as e:
            print(e)
            exit(0)

    code_bytes = code_bytes[:inst_len]
    inst = list(md.disasm(code_bytes, target_pc))[0]
    return inst, inst_len

## img_base = addr of offset 0


def get_target_params(file_path: str, target_pc: int, img_base=0x0, arch=CS_MODE_THUMB, inst_len=0):
    file_path_patched = get_file_path_patched(file_path)
    link_addr, pc_next, branch_label_addr_ori = 0x0, 0x0, 0x0
    target_pc_offset = target_pc - img_base
    code_bytes = b""
    with open(file_path, "rb") as f:
        f.seek(target_pc_offset, 0)
        code_bytes = f.read(4)

    inst, inst_len = get_inst(code_bytes, target_pc, inst_len=inst_len)
    print("[d] ", inst)
    print("[d] ", inst_len)

    params_asm['pc_next'] = hex((target_pc + inst_len) | 1)
    params_asm['inst_len'] = hex(inst_len)

    # print("0x%x:\t%s\t%s" %(inst.address, inst.mnemonic, inst.op_str))

    if inst.mnemonic.startswith("blx") or inst.mnemonic.startswith("bl"):
        translate_bl_blx(inst)
        inserted_ins = INST_TYPE['ins_branch_link'].to_bytes(
            1, "little") + b"\xDE"
        patch_bytes_img(file_path_patched, target_pc_offset, inserted_ins)
    elif inst.mnemonic.startswith("bx") or inst.mnemonic.startswith("b"):
        translate_b_bx(inst)
        inserted_ins = INST_TYPE['ins_pc_relative_in'].to_bytes(
            1, "little") + b"\xDE"
        patch_bytes_img(file_path_patched, target_pc_offset, inserted_ins)
    elif "pc" in inst.op_str:
        # like ldr    r2, [pc, #0x38]
        translate_pc(inst)
        inserted_ins = INST_TYPE['ins_pc_relative_in'].to_bytes(
            1, "little") + b"\xDE"
        patch_bytes_img(file_path_patched, target_pc_offset, inserted_ins)
    else:
        # TODO: test
        inserted_ins = INST_TYPE['ins_no_pc'].to_bytes(1, "little") + b"\xDE"
        patch_bytes_img(file_path_patched, target_pc_offset, inserted_ins)
        translate_no_pc(inst)

    # inserted_ins = inst_type.to_bytes(1, "little") + b"\xDE"
    # if inst_len > 2:
    #     inserted_ins += b"\x00\xBF"

    return params_asm


def main():
    global IS_M0

    parser = argparse.ArgumentParser(description='PIFER Pathcer.')
    # required path, image base, target pc
    parser.add_argument('-p', '--path', type=str, required=True,
                        metavar="PATH_TO_BIN", help='path to the firmware binary')
    parser.add_argument('-b', '--base', type=auto_int, required=True,
                        metavar="IMG_BASE", help='base address of the binary image')
    parser.add_argument('-t', '--target', type=auto_int, required=True,
                        metavar="TARGET_PC", help='instrument target address')
    # optional params: arch, skip reset header
    parser.add_argument('-l', '--list', type=auto_int, metavar="offset",
                        action='append', help='list of hardcoded init-sp addresss')
    parser.add_argument('-a', '--mcpu', type=str, metavar="MCPU",
                        default='cortex-m4', help='architecture of the target chip(lowercase)')
    parser.add_argument('-s', '--skip', type=auto_int, metavar="offset", default=0,
                        help='how many bytes should skipped in the original reset handler')

    args = parser.parse_args()

    file_path, img_base, target_pc, mcpu, skip_reset_header = args.path, args.base, args.target, args.mcpu, args.skip
    sp_hardcode_addrs = args.list

    # file_path = "../binaries/exp_NUCLEO_L073RZ.bin"
    # img_base = 0x08000000
    # target_pc = 0x08000448
    if mcpu == "cortex-m0":
        IS_M0 = True
    assert file_path[-4:] == ".bin"
    file_path_patched = file_path[:-4] + ".patched.bin"

    print(f"[*] copy {file_path} to {file_path_patched}")
    duplicate_firmware(file_path)

    print("[*] set binary params")
    # skip the header of original reset handler
    params_asm = get_binary_params(file_path, 0x0, skip_reset_header)

    if sp_hardcode_addrs != None:
        print("[*] patch hardcoded sp pointer to new sp")
        patch_sp_hardcode(file_path, img_base, sp_hardcode_addrs,
                        params_asm["stack_bottom"])

    # set target params & patch single instructions
    print("[*] set target params & patch single instructions")
    params_asm = get_target_params(file_path, target_pc, img_base=img_base)

    # make payload
    params_asm["payload"] = '''
    MOVS R1, R0
    '''
    print("[*] build assembly modules")
    make_target_asm(params_asm)
    compile_target(mcpu=mcpu)

    bin_bytes, new_hard_fault_handler_offset = get_new_bytes_offsets()
    # stretch the original binary
    print("[*] stretch the original binary")
    new_seg_offset = extend_firmware(file_path, bin_bytes)
    # patch target bytes
    print("[*] patch target bytes")
    patch_bytes_img(file_path_patched, new_seg_offset, bin_bytes)
    patch_binary_handlers(file_path, img_base, img_base+new_seg_offset,
                          img_base+new_seg_offset+new_hard_fault_handler_offset)

    print("[+] done")

    # inserted_ins = b"\xAD\xDE" + b"\x00\xBF"
    # patch_bytes(BIN_PATH+BIN_NAME, reset_handler_vtable,
    #             (RESET_HANDLER_NEW + 1).to_bytes(4, "little"))
    # patch_bytes(BIN_PATH+BIN_NAME, hard_fault_vtable,
    #             (HW_HANDLER_NEW + 1).to_bytes(4, "little"))
    # patch_bytes(BIN_PATH+BIN_NAME, TARGET_PC,
    #             inserted_ins)

    # # fix last patch
    # # patch_bytes(BIN_PATH+BIN_NAME, TARGET_PC+4,
    # #             b"\xae\xe7")

    # bin_bytes = b"\xdf\xf8\x0c\xd0\xbd\xf1\x10\x0d\xdf\xf8\x08\xc0\x60\x47\x00\x00\x00\x50\x00\x20\xf0\x04\x00\x08\x41\x20\x00\x00"
    # # bin_bytes = b"\xbf\xf3\x4f\x8f\xbf\xf3\x6f\x8f\xdf\xf8\xc0\xd0\xbd\xf1\x10\x0d\xdf\xf8\xbc\xc0\x60\x47\xbf\xf3\x4f\x8f\xbf\xf3\x6f\x8f\x1e\xf0\x04\x0f\x0c\xbf\xef\xf3\x08\x81\xef\xf3\x09\x81\x88\x69\x00\x78\xaa\x28\x0a\xd0\xab\x28\x19\xd0\xac\x28\x27\xd0\xad\x28\x0f\xd0\xbb\x28\x2b\xd0\xdf\xf8\x8c\xc0\x60\x47\x01\xf1\x18\x00\x0f\xf2\x6c\x0c\xc0\xf8\x00\xc0\xbf\xf3\x4f\x8f\xbf\xf3\x6f\x8f\x70\x47\xdf\xf8\x74\xc0\x01\xf1\x14\x00\xc0\xf8\x00\xc0\x1b\x48\xc0\xf8\x00\x90\x01\xf1\x18\x00\xd0\xf8\x00\x90\x0f\xf2\x48\x0c\xc0\xf8\x00\xc0\xbf\xf3\x4f\x8f\xbf\xf3\x6f\x8f\x70\x47\x01\xf1\x18\x00\xc0\xf8\x00\x90\x11\x48\xd0\xf8\x00\x90\x05\xe0\xdf\xf8\x40\xc0\x01\xf1\x18\x00\xc0\xf8\x00\xc0\x0e\x48\x4f\xf4\x00\x51\x4f\xf0\x00\x02\xbf\xf3\x4f\x8f\xbf\xf3\x6f\x8f\x70\x47\x00\xbf\x00\xbf\xbb\xde\x00\xbf\xdf\xf8\x20\x90\xac\xde\x00\x00\x00\x28\x00\x20\x0d\x03\x00\x08\xff\x02\x00\x08\xb7\x02\x00\x08\xf0\x27\x00\x20\x19\x02\x00\x08\x00\x10\x01\x40\x9c\x01\x00\x08\x41\x20\x00\x00\x00\x61\x65\x61\x62\x69\x00\x01\x16\x00\x00\x00\x05\x43\x6f\x72\x74\x65\x78\x2d\x4d\x37\x00\x06\x0d\x07\x4d\x09"
    # patch_bytes(BIN_PATH+BIN_NAME, RESET_HANDLER_NEW, bin_bytes)


if __name__ == '__main__':
    main()
