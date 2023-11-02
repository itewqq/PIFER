import subprocess

from enum import Enum, auto
from typing import List, TypedDict
from string import Template
from pwn import ELF
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB, KsError


CODE_ALIGN = 0x10

class AttributeDict(dict):
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

def auto_int(x):
    return int(x, 0)

def get_file_path_patched(file_path):
    assert file_path[-4:] == ".bin"
    file_path_patched = file_path[:-4] + ".patched.bin"
    return file_path_patched

class Cortex(Enum):
    M0 = auto()
    M3 = auto()
    M4 = auto()
    M7 = auto()

class InstDisPiferException(Exception):
    pass

class NoFreeRegPiferException(Exception):
    pass

class MultiHooksSingleAddrPiferException(Exception):
    pass

def get_arm_pc_relative(pc: int) -> int :
    # clear bit 1, pretty weird but they asked
    pc_relative = (pc + 4) & (0xFFFFFFFD)
    return pc_relative - pc

def payload2asm(addr_target, payload: List):
    comp = "//new_code_comp_start:\n"
    ncode = "//new_code_start:\n"
    for addr,target in addr_target.items():
        comp += f"\tLDR R1, ={addr}\n"
        comp += f"\tCMP R0, R1\n"
        comp += f"\tBEQ newcode_{target}\n"
        comp += f"\tB label_selector_newcode_{addr}\n"
        comp += f"\t.LTORG\n"
        comp += f"\tlabel_selector_newcode_{addr}:\n"

    for i,t in enumerate(payload):
        ncode += f"\tnewcode_{t.payload_id}:\n"
        ncode += f"\t{t.asm}\n"
        ncode += f"\tB all_newcode_return\n"
        
    return comp, ncode

def make_target_asm(template_string, params):
    t = Template(template_string)
    with open("make_target.S", "w") as f:
        f.write(t.substitute(params))

def compile_helper(code):
    try:
        ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
        encoding, count = ks.asm(code)
        print("%s = %s (number of statements: %u)" % (code, encoding, count))
    except KsError as e:
        print("ERROR: %s" % e)

def disasm_helper(code_bytes, target_pc, inst_len=0):
    print(code_bytes, inst_len)
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    if inst_len == 0:
        try:
            res = list(md.disasm(code_bytes[:4], target_pc))
            if len(res) == 0:
                raise InstDisPiferException(
                    f"Failed to disasmble the target instruction at {hex(target_pc)}!")
            inst_len = res[0].size
        except InstDisPiferException as e:
            print(e)
            exit(0)

    code_bytes = code_bytes[:inst_len]
    inst = list(md.disasm(code_bytes, target_pc))[0]
    return inst, inst_len

def compile_target(base_addr, target="make_target.S", mcpu="cortex-m4", add_options=""):
    as_cmd = f"arm-none-eabi-as -mthumb  -mcpu={mcpu} {add_options} {target} -o as.out"
    subprocess.run(as_cmd, shell=True)
    ld_cmd = f"arm-none-eabi-ld -Ttext {hex(base_addr)} as.out -o a.out"
    subprocess.run(ld_cmd, shell=True)


def patch_bytes_img(file_path: str, img_offset: int, target_bytes: bytes):
    try:
        with open(file_path, "r+b") as f:
            f.seek(img_offset)
            f.write(target_bytes)
        print(f"\t[+] patched {hex(img_offset)}")
    except Exception as e:
        print(e)
        print(f"\t[x] patched {hex(img_offset)} error!")

def get_new_bytes_offsets(elf_path="a.out"):
    result = b""
    # new_hard_fault_handler_offset = 0
    with open(elf_path, "rb") as f:
        all_bytes = f.read()
        elf = ELF(elf_path)
        # new_hard_fault_handler_offset = elf.symbols["new_hard_fault_handler"]
        text_start, text_size = elf.get_section_by_name(
            '.text').header.sh_offset, elf.get_section_by_name('.text').header.sh_size
        result = all_bytes[text_start:text_start+text_size]
    return result
    # return result, new_hard_fault_handler_offset

def patch_binary_handlers(file_path_patched: str, img_base: int, hf_handler_new: int):
    reset_handler_vtable_img_offset = 0x4
    hard_fault_vtable_offset = 0xC
    usage_fault_vtable_offset = 0x18
    patch_bytes_img(file_path_patched, hard_fault_vtable_offset,
                    (hf_handler_new + 1).to_bytes(4, "little"))
    patch_bytes_img(file_path_patched, usage_fault_vtable_offset,
                    (hf_handler_new + 1).to_bytes(4, "little"))

# mod test
if __name__ == "__main__":
    payload = []
    payload.append(AttributeDict({"addr":0x300, "asm": "NOP"}))
    payload.append(AttributeDict({"addr":0x300, "asm": "ADD R1, R2"}))
    payload.append(AttributeDict({"addr":0x300, "asm": "MOV R0, 0xAA"}))
    comp, ncode = payload2asm(payload)

    print(comp+ncode)