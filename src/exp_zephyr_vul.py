from patch import *

payload = '''
    BX  LR
'''

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
    params_asm["payload"] = payload

    print("[*] build assembly modules")
    # change logic of relocated
    params_asm["no_pc_inst_ori"] = "SUBS    R5, R5, R2"
    make_target_asm(params_asm)
    compile_target(mcpu=mcpu)

    bin_bytes, new_hard_fault_handler_offset = get_new_bytes_offsets()
    # stretch the original binary
    print("[*] find space to patch")
    new_seg_offset = extend_firmware(file_path, bin_bytes)
    # patch target bytes
    print("[*] patch target bytes")
    patch_bytes_img(file_path_patched, new_seg_offset, bin_bytes)
    patch_binary_handlers(file_path, img_base, img_base+new_seg_offset,
                          img_base+new_seg_offset+new_hard_fault_handler_offset)

    print("[+] done")


if __name__ == '__main__':
    main()
