import idc
import idaapi
import idautils
from idautils import ida_bytes


branch_dict = {}
branch_link_dict = {}
pc_rel_dict = {}
no_pc_dict = {}

def get_xrefs_frm(ea):
    xref_set = set()
    for xref in idautils.XrefsFrom(ea, 1):
        xref_set.add(xref.to)
    return xref_set


def add2dict(mnem, head, dc):
    if mnem in dc.keys():
        dc[mnem].append(head)
    else:
        dc[mnem] = [head]

def count_ins(dc):
    return sum([len(dc[x]) for x in dc])

def get_all_ins(dc):
    return [addr for d in dc for addr in dc[d]]

# coremark_functions = {
#     "core_main":0x0A94,
#     "get_seed_32":0x1B20,
#     "portable_init":0x042B6,
#     "get_time":0x178C,
#     "portable_fini":0x42D4,
#     "core_init_state":0x017B4,
#     "core_init_matrix":0x3D70,
#     "__aeabi_dcmplt":0x4D04,
#     "__fixunsdfsi":0x2EE0,
#     "check_data_types":0x1B9C,
#     "core_list_init":0x0868,
#     "stop_time":0x15CC,
#     "start_time":0x15B4,
#     "time_in_secs":0x412E,
#     "__aeabi_cdrcmple":0x2E5C,
#     "__aeabi_cdcmple":0x2E6C,
#     "ee_printf":0x419E,
#     "iterate":0x3A2E,
#     "core_bench_list":0x6A4,
#     "core_list_insert_new":0x3782,
#     "__divdf3":0x2C00,
#     "barebones_clock":0x411E,
#     "__floatunsidf":0x28B8,
#     "__nedf2":0x2DE0,
#     "core_list_remove":0x37F8,
#     "core_list_find":0x3872,
#     "core_list_reverse":0x38DA,
#     "core_list_undo_remove":0x3838,
#     "core_list_mergesort":0x3910,
#     "copy_info":0x3758,
#     "crc16":0x4486,
#     "crcu16":0x4408,
#     "crcu8":0x4374,
# }

coremark_functions = {
    "core_main":0x0AA4,
    "get_seed_32":0x1B30,
    "portable_init":0x497A,
    "get_time":0x179C,
    "portable_fini":0x4998,
    "core_init_state":0x017C4,
    "core_init_matrix":0x4434,
    "check_data_types":0x1BAC,
    "core_list_init":0x092C,
    "stop_time":0x1784,
    "start_time":0x176C,
    "time_in_secs":0x4942,
    "ee_printf":0x49B2,
    "iterate":0x41FE,
    "core_bench_list":0x0768,
    "core_list_insert_new":0x3F52,
    "barebones_clock":0x4932,
    "core_list_remove":0x3FC8,
    "core_list_find":0x4042,
    "core_list_reverse":0x40AA,
    "core_list_undo_remove":0x4008,
    "core_list_mergesort":0x40E0,
    "copy_info":0x3F28,
    "crc16":0x4C9A,
    "crcu16":0x4C1C,
    "crcu8":0x4B88,
    "__aeabi_dcmplt":0x39C0,
    "__aeabi_dcmpgt":0x39FC,
    "__aeabi_dcmplt":0x39C0,
    "__fixunsdfsi":0x3A10,
    "__aeabi_cdrcmple":0x398C,
    "__aeabi_cdcmple":0x399C,
    "__divdf3":0x3730,
    "__floatunsidf":0x33E8,
    "__nedf2":0x3910,
}

fail = 0
total = 0
total_cando = 0
# for funcea in idautils.Functions():
    # if funcea > 0x80000:
        # break
for _,funcea in coremark_functions.items():
    for (startea, endea) in idautils.Chunks(funcea):
        for head in idautils.Heads(startea, endea):
            total += 1
            inst = idc.GetDisasm(head)
            if inst.startswith("BKPT") or inst.startswith("CPS") or inst.startswith("MRS")  or inst.startswith("MSR") or inst.startswith("SEV") or inst.startswith("SVC") or inst.startswith("WFE") or inst.startswith("WFI") :
                fail += 1
                continue
            if inst.startswith("DC"):
                # the disassembler seems to be stupid = =
                continue
            total_cando += 1
            mnem = inst.split()[0]
            mnem = mnem.split('.')[0] # remove the width description
            # brach and control
            if (mnem.startswith("B") and not mnem.startswith("BIC") and not mnem.startswith("BL")) or mnem.startswith("CBZ") or mnem.startswith("CBNZ") or mnem.startswith("TBB") or mnem.startswith("TBH") or mnem.startswith("BLT") or mnem.startswith("BLO") or mnem.startswith("BLS") or mnem.startswith("BLE"):
                add2dict(mnem, head, branch_dict)
            elif mnem.startswith("BL"):
                add2dict(mnem, head, branch_link_dict)
            elif "PC".lower() in inst.lower() or "ADR".lower() in inst.lower() or ("LDR".lower() in inst.lower() and len(inst.split())>=2 and inst.split()[2].startswith("=") ):
                add2dict(mnem, head, pc_rel_dict)
            else:
                add2dict(mnem, head, no_pc_dict)
            
            

print(f"Cannot instrument: {fail} {total} {fail/total} {1-fail/total}")

branch_num = count_ins(branch_dict)
branch_link_num = count_ins(branch_link_dict)
pc_rel_num = count_ins(pc_rel_dict)
no_pc_num = count_ins(no_pc_dict)

print(f"branch_num: {branch_num}\nbranch_link_num: {branch_link_num}\npc_rel_num: {pc_rel_num}\nno_pc_num: {no_pc_num}")

print(f"branch_num: {branch_num/total_cando}\nbranch_link_num: {branch_link_num/total_cando}\npc_rel_num: {pc_rel_num/total_cando}\nno_pc_num: {no_pc_num/total_cando}")



no_pc_all_ins = get_all_ins(no_pc_dict)
pc_rel_all_ins = get_all_ins(pc_rel_dict)
branch_link_all_ins = get_all_ins(branch_link_dict)
branch_all_ins = get_all_ins(branch_dict)