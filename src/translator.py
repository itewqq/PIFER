from utils import *

ARM_REGS = ['r0',
            'r1',
            'r2',
            'r3',
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

# ARM_REGS = [
#             'r8',
#             'r9',
#             'r10',
#             'r11',
#             'r12',
#             'ip']

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

COND = {
    "EQ",
    "NE",
    "CS",
    "HS",
    "CC",
    "LO",
    "MI",
    "PL",
    "VS",
    "VC",
    "HI",
    "LS",
    "GE",
    "LT",
    "GT",
    "LE",
    "AL"
}

INST_TYPE = {
    'ins_no_pc': 0x0,
    'ins_no_pc_out': 0x1,
    'ins_pc_in': 0x2,
    'ins_pc_out': 0x3,
    'ins_bl': 0x4
}

EXC_STACK_OFFSET = {
    'r0': 0x0,
    'r1': 0x4,
    'r2': 0x8,
    'r3': 0xC,
    'r12': 0x10,
    'ip': 0x10
}

UDF_BYTES = {
    2: b"\xDE",
    4: b"\xf7\xf0\xa000"
}

def make_udf(inst, tp):
    if inst.size == 2:
        return tp + b"\xDE"
    else:
        return b"\xF0\xF7" + tp + b"\xA0"

class TRANS:
    __slots__ = "params_asm", "is_m0"

    def __init__(self, params_asm, is_m0=False):
        self.params_asm = params_asm
        self.is_m0 = is_m0

    def get_free_register(self, inst, banned_list = []):
        used_regs = inst.op_str
        stacked_regs_offset = {"r0": 0x0, "r1": 0x4,
                            "r2": 0x8, "r3": 0xC, "r12": 0x10, "ip": 0x10}

        if self.is_m0 is True:
            regs = ARM_REGS_M0
        else:
            regs = ARM_REGS
        if inst.mnemonic.startswith("pop"):
            # ordered
            # pc = r15, the biggest
            used_regs_list = used_regs.replace("{", "").replace("}", "").replace(",", " ").split()
            pre_pc = []
            for r in used_regs_list:
                if r == "pc":
                    break
                pre_pc.append(r)
            if len(pre_pc) == 0:
                lower_bd = 0
            else:
                print(pre_pc[-1])
                lower_bd = int(pre_pc[-1][1:]) + 1
            for r in regs:
                if r in banned_list:
                    continue
                if r == "ip":
                    idx = 12
                else:
                    idx = int(r[1:])
                if idx < lower_bd:
                    continue
                if r in used_regs:
                    continue
                if r == "ip":
                    r = "r12"
                    return r
        else:
            for r in regs:
                if r in banned_list:
                    continue
                if r not in used_regs:
                    if r == "ip":
                        r = "r12"
                    return r
        raise NoFreeRegPiferException(f"cannot find free register for {inst}")


    def translate_b_bx(self, inst):
        inst_len = inst.size
        addr = inst.address
        code = ""
        code_end = ""
        free_reg = self.get_free_register(inst)

        for cond in COND:
            if cond.lower() in inst.mnemonic:
                code += f"\n\t{inst.mnemonic} cond_label_{hex(inst.address)}\n"
                code+= f"\tMOV {free_reg}, #{hex((addr+inst_len) | 1)}\n"
                code += f"\tUDF #{hex(INST_TYPE['ins_pc_out'])}0\n"
                code += f"cond_label_{hex(inst.address)}:\n"
                code_end += f"\tUDF #{hex(INST_TYPE['ins_pc_out'])}0\n"

        if inst.op_str.startswith("#"):
            # label
            target_pc = int(inst.op_str[1:], 0x10)
            # this is for cortex-m0
            tmp_free_reg = self.get_free_register(inst, banned_list=[free_reg])
            code += f"\tPUSH {{ {tmp_free_reg} }}\n"
            code += f"\tLDR {tmp_free_reg}, =" + hex(target_pc | 1) + "\n"
            code += f"\tMOV {free_reg}, {tmp_free_reg}\n"
            code += f"\tPOP {{ {tmp_free_reg} }}\n"
        else:
            # bx Rm
            reg_list = inst.op_str.replace(",", " ").split()
            assert len(reg_list) == 1
            target_reg = reg_list[0]
            code += "\tMOV " + free_reg + ", " + target_reg + "\n"

        code += code_end
        # reuse the pc relative code
        self.translate_pc(inst, code)


    def translate_bl_blx(self, inst):
        self.translate_b_bx(inst)


    def translate_cbz_cbnz(self, inst):
        inst_len = inst.size
        addr = inst.address
        free_reg = self.get_free_register(inst)
        Rn, label_orig = inst.op_str.split(',')
        label_orig = label_orig.strip()
        assert(label_orig.startswith("#")) # only label allowed here
        code = "\n\t" + inst.mnemonic + " " + Rn + f", label_cb_out{hex(addr)}\n"
        code+= f"\tMOV {free_reg}, #{hex(addr+inst_len+1)}\n"
        code+= f"\tUDF #{hex(INST_TYPE['ins_pc_out'])}0\n"
        code+= f"label_cb_out{hex(addr)}:\n"
        code+= f"\tMOV {free_reg}, {label_orig}\n"
        code+= f"\tUDF #{hex(INST_TYPE['ins_pc_out'])}0\n"
        # reuse the pc relative code
        self.translate_pc(inst, code)


    def translate_tbb_tbh(self, inst):
        inst_len = inst.size
        addr = inst.address
        free_reg = self.get_free_register(inst)

        if inst.mnemonic.startswith("tbb"):
            ldr_type = "B"
        elif inst.mnemonic.startswith("tbh"):
            ldr_type = "H"
        else:
            raise("Not tbb or tbh")

        Rn, Rm = inst.op_str.split(',')[:2]
        Rn = Rn.strip().strip('[').strip(']')
        Rm = Rm.strip().strip('[').strip(']')
        if Rn == "pc":
            Rn = free_reg # replace with free register

        code = "\n"
        code+= f"\tPUSH {{{Rm}}}\n"
        code+= f"\tLDR{ldr_type} {Rm}, [{Rn}, {Rm}]\n"
        code+= f"\tLSL {Rm}, {Rm}, #1\n"
        code+= f"\tADD {free_reg}, {Rm}\n"
        code+= f"\tPOP {{{Rm}}}\n"

        # reuse the pc relative code
        self.translate_pc(inst, code, pc_offset=get_arm_pc_relative(inst.address))

    def translate_it(self, inst):
        inst_len = inst.size
        addr = inst.address
        free_reg = self.get_free_register(inst)
        code = "\t" + inst.mnemonic + " " + inst.op_str + "\n"
        # fix the it block
        code+= f"\tUDF #{hex(INST_TYPE['ins_no_pc_out'])}0\n"
        code+= f"\tUDF #{hex(INST_TYPE['ins_no_pc_out'])}0\n"
        code+= f"\tUDF #{hex(INST_TYPE['ins_no_pc_out'])}0\n"
        code+= f"\tUDF #{hex(INST_TYPE['ins_no_pc_out'])}0\n"

        # reuse the no_pc code
        self.translate_no_pc(inst, code)

    def translate_adr(self, inst):
        inst_len = inst.size
        addr = inst.address
        free_reg = self.get_free_register(inst)
        Rd, label_orig = inst.op_str.split(',')
        label_orig = label_orig.strip()
        assert(label_orig.startswith("#")) # only label allowed here
        code = f"\tMOV {Rd}, {free_reg}\n"
        code+= f"\tADD {Rd}, {Rd}, {label_orig}\n"

        # reuse the pc relative code
        self.translate_pc(inst, code, pc_offset=get_arm_pc_relative(inst.address))

    def translate_pc(self, inst, code=None, pc_offset=None):
        inst_len = inst.size
        addr = inst.address
        free_reg = self.get_free_register(inst)
        print(f"[d]  Rx for {hex(addr)} is {free_reg}")

        if code is None:
            code = inst.mnemonic + " " + inst.op_str
            # replace the PC with Rx
            code = code.replace("pc", free_reg)

        self.params_asm['Rx'] = free_reg
        if pc_offset is None:
            self.params_asm['translated_targets'] += f"\ntrans_{hex(addr)}:\n\t{code}\n\tUDF #{hex(INST_TYPE['ins_pc_out'])}0\n"
        else:
            diff = pc_offset - inst_len
            # note that in arm asm the PC point to PC+4
            self.params_asm['translated_targets'] += f"\ntrans_{hex(addr)}:\n\tADD {free_reg}, #{pc_offset}\n\t{code}\n\tSUB {free_reg}, #{diff}\n\tUDF #{hex(INST_TYPE['ins_pc_out'])}0\n"

        self.params_asm['comp_trans_pc'] += f"\n\tLDR IP, =trans_{hex(addr)}\n\tLDR R3, ={hex(addr)}\n\tCMP R0, R3\n\tBEQ save_rx_label_{hex(addr)}\n\tB label_selector_trans_{hex(addr)}\n\t.LTORG\n\tlabel_selector_trans_{hex(addr)}:\n\n"

        self.params_asm['comp_restore_rx'] += f"\n\tLDR R3, ={hex(addr)}\n\tCMP R0, R3\n\tBEQ restore_rx_label_{hex(addr)}\n\n"

        if free_reg in ['r0', 'r1', 'r2', 'r3', 'r12', 'ip']:
            self.params_asm['save_rx'] += f"\n\tsave_rx_label_{hex(addr)}:\n\tLDR R0, [R1, {EXC_STACK_OFFSET[free_reg]}]\n\tSTR R0, [R2, 0x8]\n\tLDR R0, [R2, 0x0]\n\tSTR R0, [R1, {EXC_STACK_OFFSET[free_reg]}]\n\tB pc_in_return\n\t.LTORG\n"
            self.params_asm['restore_rx'] += f"\n\trestore_rx_label_{hex(addr)}:\n\tLDR R0, [R1, {EXC_STACK_OFFSET[free_reg]}]\n\tSTR R0, [R2, 0x4]\n\tLDR R0, [R2, 0x8]\n\tSTR R0, [R1, {EXC_STACK_OFFSET[free_reg]}]\n\tB no_pc_out\n\t.LTORG\n"
        else:
            self.params_asm['save_rx'] += f"\n\tsave_rx_label_{hex(addr)}:\n\tSTR {free_reg}, [R2, 0x8]\n\tLDR {free_reg}, [R2, 0x0]\n\tB pc_in_return\n\t.LTORG\n"
            
            self.params_asm['restore_rx'] += f"\n\trestore_rx_label_{hex(addr)}:\n\tSTR {free_reg}, [R2, 0x4]\n\tLDR {free_reg}, [R2, 0x8]\n\tB no_pc_out\n\t.LTORG\n"


    def translate_no_pc(self, inst, code=None):
        # for no pc we just put the exactly same instruction
        # print(inst)
        addr = inst.address
        if code is None:
            code = inst.mnemonic + " " + inst.op_str
        self.params_asm['translated_targets'] += f"\ntrans_{hex(addr)}:\n\t{code}\n\tUDF #{hex(INST_TYPE['ins_no_pc_out'])}0\n"
        self.params_asm['comp_trans_no_pc'] += f"\n\tLDR IP, =trans_{hex(addr)}\n\tLDR R3, ={hex(addr)}\n\tCMP R0, R3\n\tBEQ no_pc_in_return\n\tB label_selector_trans_{hex(addr)}\n\t.LTORG\n\tlabel_selector_trans_{hex(addr)}:\n\n"


    def translate(self, inst):
        if inst.mnemonic.startswith("blx") or inst.mnemonic == "bl" :
            # note the bls blt ble blo should not go this way
            self.translate_bl_blx(inst)
            inserted_ins = make_udf(inst, (INST_TYPE['ins_bl']<<4).to_bytes(1, "little") )
        elif inst.mnemonic.startswith("bx") or inst.mnemonic.startswith("b") and not inst.mnemonic.startswith("bic"):
            self.translate_b_bx(inst)
            inserted_ins = make_udf(inst, (INST_TYPE['ins_pc_in']<<4).to_bytes(1, "little") )
        elif inst.mnemonic.startswith("cbz") or inst.mnemonic.startswith("cbnz"):
            self.translate_cbz_cbnz(inst)
            inserted_ins = make_udf(inst, (INST_TYPE['ins_pc_in']<<4).to_bytes(1, "little") )
        elif inst.mnemonic.startswith("tbb") or inst.mnemonic.startswith("tbh"):
            self.translate_tbb_tbh(inst)
            inserted_ins = make_udf(inst, (INST_TYPE['ins_pc_in']<<4).to_bytes(1, "little") )
        elif inst.mnemonic.startswith("adr"):
            self.translate_adr(inst)
            inserted_ins = make_udf(inst, (INST_TYPE['ins_pc_in']<<4).to_bytes(1, "little") )
        elif inst.mnemonic.startswith("it"):
            # it only set the flag, we just need to go back to next pc
            inserted_ins = make_udf(inst, (INST_TYPE['ins_no_pc']<<4).to_bytes(1, "little") )
            self.translate_it(inst)
        elif "pc" in inst.op_str and (inst.mnemonic.startswith("pop") or inst.op_str.startswith("pc")):
            # do not use pc offset since we are writing to PC
            self.translate_pc(inst)
            inserted_ins = make_udf(inst, (INST_TYPE['ins_pc_in']<<4).to_bytes(1, "little") )
        elif "pc" in inst.op_str:
            # like ldr    r2, [pc, #0x38]
            self.translate_pc(inst, code=None, pc_offset=get_arm_pc_relative(inst.address))
            inserted_ins = make_udf(inst, (INST_TYPE['ins_pc_in']<<4).to_bytes(1, "little") )
        else:
            # no_pc don't need Rx
            inserted_ins = make_udf(inst, (INST_TYPE['ins_no_pc']<<4).to_bytes(1, "little") )
            self.translate_no_pc(inst)

        return inserted_ins, self.params_asm
