from pykd import *
import argparse

global addr_flash_base
global len_flash_range
global addr_parse
global addr_getmethodname
global addr_setjit
global addr_unused_memory
global is_modified_setjit
# save JIT method map <address, method name>
global map_jit_bp

if not 'is_modified_setjit' in vars():
    # dprintln("is_modified_setjit is undefined, set it as False")
    global is_modified_setjit
    is_modified_setjit = False

def get_flash_module_base_address():
    base_addr = 0
    msg = dbgCommand("lm vm flash*")
    lines = msg.split('\n')
    if len(lines) > 3:
        for line in lines:
            line = line.lower()
            if 'flash' in line:
                # 67e70000 68901000   Flash11e   (deferred)
                keys = line.split(' ')
                global addr_flash_base
                global len_flash_range
                addr_flash_base = int(keys[0],16)
                len_flash_range = int(keys[1],16) - addr_flash_base
                return
    raise Exception('Cannot get flash module base address from Debugger CMD')

def search_base_address():
    if 'addr_flash_base' in globals():
        dprintln("Find addr_flash_base in globals: " + hex(addr_flash_base))
        dprintln("Find len_flash_range in globals: " + hex(len_flash_range))
    else:
        dprintln("Cannot find addr_flash_base in globals, try to analyze flash module info...")
        get_flash_module_base_address()

def parse_search_result(result_msg, min_addr = 0):
    if None == result_msg:
        return 0
    addr = 0
    matched_list = result_msg.split('\n')
    matched_count = len(matched_list) - 1
    for line in matched_list[0:-1]:
        # matched result looks like:
        # 6f2e6870  8b 41 10 a8 01 74 13 83-e0 fe 74 0c 8b 40 0c 52  .A...t....t..@.R
        matched_addr = line.split(' ')[0]
        #dprintln("first matched address in search result: 0x" + matched_addr)
        addr = int(matched_addr, 16)
        if addr > min_addr:
            return addr
    return addr

def search_sig_parse():
    # .text:106B5670                               AbcParser__parse proc near              ; CODE XREF: AbcParser__decodeAbc+8Dp
    # .text:106B5670
    # .text:106B5670                               arg_0           = dword ptr  4
    # .text:106B5670
    # .text:106B5670 56                                            push    esi
    # .text:106B5671 8B F1                                         mov     esi, ecx
    # .text:106B5673 8B 46 10                                      mov     eax, [esi+10h]
    # .text:106B5676 8B 88 D0 00 00 00                             mov     ecx, [eax+0D0h]
    # .text:106B567C E8 9F D3 FF FF                                call    sub_106B2A20
    # .text:106B5681 8B 4E 10                                      mov     ecx, [esi+10h]
    # .text:106B5684 8B 89 D4 00 00 00                             mov     ecx, [ecx+0D4h]
    # .text:106B568A E8 91 D3 FF FF                                call    sub_106B2A20
    #
    # s 0x10000000 L111e000 56 8B F1 8B 46 10 8B 88 D0 00 00 00
    dprintln("search signature of parse ...")
    msg = dbgCommand("s %s L%s 56 8B F1 8B 46 10 8B 88 D0 00 00 00" % (hex(addr_flash_base), hex(len_flash_range)))
    global addr_parse
    addr_parse = parse_search_result(msg)
    dprintln("Address of AbcParser__parse is: 0x" + hex(addr_parse))
    if addr_parse == 0:
        raise Exception('Cannot get address of hook point: AbcParser::parse')

def search_sig_getmethodname():
    #.text:106C4750                               MethodInfo__getMethodName proc near     ; CODE XREF: sub_1064BE80+6p
    #.text:106C4750                                                                       ; sub_106C4780+2p
    #.text:106C4750 8B 41 10                                      mov     eax, [ecx+10h]
    #.text:106C4753 A8 01                                         test    al, 1
    #.text:106C4755 74 13                                         jz      short loc_106C476A
    #.text:106C4757 83 E0 FE                                      and     eax, 0FFFFFFFEh
    #.text:106C475A 74 0C                                         jz      short loc_106C4768
    #.text:106C475C 8B 40 0C                                      mov     eax, [eax+0Ch]
    #.text:106C475F 52                                            push    edx
    #.text:106C4760 8B D0                                         mov     edx, eax
    #.text:106C4762 E8 B9 F7 FF FF                                call    MethodInfo__getMethodNameWithTraits
    #.text:106C4767 C3                                            retn
    #
    # s 0x10000000 L111e000 8B 41 10 A8 01 74 13 83 E0 FE 74 0C
    dprintln("search signature of getmethodname ...")
    msg = dbgCommand("s %s L%s 8B 41 10 A8 01 74 13 83 E0 FE 74 0C" % (hex(addr_flash_base), hex(len_flash_range)))
    global addr_getmethodname
    addr_getmethodname = parse_search_result(msg)
    dprintln("Address of MethodInfo__getMethodName is: " + hex(addr_getmethodname))
    if addr_getmethodname == 0:
        raise Exception('Cannot get address of hook point: MethodInfo::getMethodName')

def search_sig_setjit():
    #.text:106D7E80 8B 4C 24 08                                   mov     ecx, [esp+code]
    #.text:106D7E84 56                                            push    esi
    #.text:106D7E85 8B 74 24 08                                   mov     esi, [esp+4+mi]
    #.text:106D7E89 8B 46 30                                      mov     eax, [esi+30h]
    #.text:106D7E8C 25 FF FF 7F FF                                and     eax, 0FF7FFFFFh
    #.text:106D7E91 0D 00 00 20 80                                or      eax, 80200000h
    #.text:106D7E96 56                                            push    esi
    #
    # s 0x10000000 L111e000 8B 4C 24 08 56 8B 74 24 08 8B 46 30 25 FF FF 7F FF
    dprintln("search signature of setjit ...")
    msg = dbgCommand("s %s L%s 8B 4C 24 08 56 8B 74 24 08 8B 46 30 25 FF FF 7F FF" % (hex(addr_flash_base), hex(len_flash_range)))
    global addr_setjit
    addr_setjit = parse_search_result(msg)
    dprintln("Address of SetJIT is: " + hex(addr_setjit))
    if addr_setjit == 0:
        raise Exception('Cannot get address of hook point: SetJIT')

def search_unused_memory():
    #mov ecx,esi // 0x89,0xf1
    #// offset = 106C4750 - 1000ee4a - 5 = 6B5901
    #call 0x******** // 0xE8,0x01,0x59,0x6b,0x00
    #pop  esi // 0x5E
    #pop ecx // 0x59
    #mov eax,[esi+30h] // 0x8B,0x46,0x30
    #add eax,0xFF7FFFFF // 0x25,0xFF,0xFF,0x7F,0xFF
    #// offset = 106d7e91 - 1000ee59 - 5 = 6C9033
    #jmp 0x******** // 0xE9,0x33,0x90,0x6C,0x00
    #
    # at least 22 bytes
    # s 0x10000000 L111e000 CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC 
    dprintln("search signature of unused memory ...")
    msg = dbgCommand("s %s L%s CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC" % (hex(addr_flash_base), hex(len_flash_range)))
    if addr_getmethodname > addr_setjit:
        addr_high = addr_getmethodname
    else:
        addr_high = addr_setjit
    global addr_unused_memory
    addr_unused_memory = parse_search_result(msg, addr_high)
    dprintln("Address of Unused Memory is: " + hex(addr_unused_memory))
    if addr_unused_memory == 0:
        raise Exception('Cannot get address of hook point: Unused Memory')

def search_hook_points():
    # search_sig_parse()
    search_sig_getmethodname()
    search_sig_setjit()
    search_unused_memory()

def calc_offset(cur_addr, target_addr):
    if abs(target_addr-cur_addr) <= 5:
        return 0
    return target_addr-cur_addr-5

def build_instruction(offset, instructions, i_offset, size):
    print 'offset hex format is: ' + hex(offset)
    for i in range(0, size):
        instructions[i_offset + i] = offset & 0xFF
        offset >>= 8
    return instructions

def modify_setjit():
    dprintln("Try to modify SetJIT function to call getMethodName")
    # modify setjit
    #.text:106D7E80 8B 4C 24 08                                   mov     ecx, [esp+code]
    #.text:106D7E84 56                                            push    esi
    #.text:106D7E85 8B 74 24 08                                   mov     esi, [esp+4+mi]
    #.text:106D7E89 8B 46 30                                      mov     eax, [esi+30h]       --> 0x51,0x56,0x90
    #.text:106D7E8C 25 FF FF 7F FF                                and     eax, 0FF7FFFFFh      --> 0xE9,OFFSET
    #.text:106D7E91 0D 00 00 20 80                                or      eax, 80200000h
    #.text:106D7E96 56                                            push    esi
    
    #push ecx // 0x51
    #push esi // 0x56
    #0x90
    #jmp 0x******** //0xE9

    offset = calc_offset(addr_setjit+0x0C, addr_unused_memory)
    if offset == 0:
        raise Exception("Failed to calculate offset for unused memory");
    instructions = [0x51, 0x56, 0x90, 0xE9, 0x00, 0x00, 0x00, 0x00]
    instructions = build_instruction(offset, instructions, 4, 4)
    print '[{}]'.format(', '.join(hex(x) for x in instructions))
    writeBytes(addr_setjit+0x09, instructions)

    # modify unused memory
    #mov ecx,esi // 0x89,0xf1
    #// offset = 106C4750 - 1000ee4a - 5 = 6B5901
    #call 0x******** // 0xE8,0x01,0x59,0x6b,0x00
    #pop  esi // 0x5E
    #pop ecx // 0x59
    #mov eax,[esi+30h] // 0x8B,0x46,0x30
    #add eax,0xFF7FFFFF // 0x25,0xFF,0xFF,0x7F,0xFF
    #// offset = 106d7e91 - 1000ee59 - 5 = 6C9033
    #jmp 0x******** // 0xE9,0x33,0x90,0x6C,0x00
    
    instructions_in_unused_memory = [0x89,0xF1,0xE8,0x00,0x00,0x00,0x00,0x5E,0x59,0x8B,0x46,0x30,0x25,0xFF,0xFF,0x7F,0xFF,0xE9,0x00,0x00,0x00,0x00];
    offset = calc_offset(addr_unused_memory+0x02, addr_getmethodname)
    # 
    if offset == 0:
        raise Exception("Failed to calculate offset for getmemthodname");
    instructions_in_unused_memory = build_instruction(offset, instructions_in_unused_memory, 3, 4)
    print '[{}]'.format(', '.join(hex(x) for x in instructions_in_unused_memory))
    # 
    offset = calc_offset(addr_unused_memory+0x11, addr_setjit+0x11)
    if offset == 0:
        raise Exception("Failed to calculate offset for setjit");
    instructions_in_unused_memory = build_instruction(offset, instructions_in_unused_memory, 0x12, 4)
    print '[{}]'.format(', '.join(hex(x) for x in instructions_in_unused_memory))
    # 
    writeBytes(addr_unused_memory, instructions_in_unused_memory)

    global is_modified_setjit
    is_modified_setjit = True


# JIT method name list
list_jit_bp = []

def monitor_jit_funtion(func_name):
    list_jit_bp.append(func_name)

def is_monitoring_jit_function(func_name):
    if func_name in list_jit_bp:
        return True
    return False

# <address, method name>
if not 'map_jit_bp' in vars():
    map_jit_bp = {}

def find_near_jit_symbol(checked_addr):
    pre_less_addr = 0
    for addr in sorted(map_jit_bp):
        # print "%s: %s" % (hex(addr), map_jit_bp[addr])
        if checked_addr > addr:
            pre_less_addr = addr
        elif checked_addr < addr:
            print "Find near symbol:"
            print map_jit_bp[pre_less_addr] + " (" + hex(pre_less_addr) + ") | " + map_jit_bp[addr] + " (" + hex(addr) + ")"
            return
        else: # checked_addr == addr
            print "Find exact matched symbol: " + map_jit_bp[addr]
            return

class HookPointHandler(pykd.eventHandler):
    """
    """
    def __init__(self):
        #self.bp_parse = setBp(addr_parse, self.callback_parse)
        self.bp_getmethodname = setBp(addr_getmethodname, self.callback_getmethodname)
        self.bp_setjit = setBp(addr_setjit, self.callback_setjit)

    def set_bp_after_getmethodname(self):
        if not is_modified_setjit:
            dprintln("SetJIT function hasn't been modified, don't need to set bp after getMethodName")
            return
        # set breakpoint at 
        # 0:011> u 0x6d7d308c
        # Flash32_22_0_0_192!IAEModule_IAEKernel_UnloadModule+0x2c693c:
        # 6d7d308c 89f1            mov     ecx,esi
        # 6d7d308e e8dd37f8ff      call    Flash32_22_0_0_192!IAEModule_IAEKernel_UnloadModule+0x24a120 (6d756870) ;getMethodName
        # 6d7d3093 5e              pop     esi
        # 6d7d3094 59              pop     ecx
        # 6d7d3095 8b4630          mov     eax,dword ptr [esi+30h] <--- bp here
        # 6d7d3098 25ffff7fff      and     eax,0FF7FFFFFh
        # 6d7d309d e9df6cfaff      jmp     Flash32_22_0_0_192!IAEModule_IAEKernel_UnloadModule+0x26d631 (6d779d81)
        dprintln("set breakpoint at addr_unused_memory+0x09 for getting method name")
        self.bp_after_call_getmethodname = setBp(addr_unused_memory+0x09, self.callback_after_call_getmethodname)

    def callback_parse(self):
        dprintln("Enter into callback_parse")
    
    def callback_getmethodname(self):
        # dprintln("Enter into callback_getmethodname")
        pass

    def callback_after_call_getmethodname(self):
        # dprintln("Enter into callback_after_call_getmethodname")   
        reg_eax = reg("eax")   
        # dprintln("EAX = " + hex(reg_eax))
        addr_name = ptrPtr(reg_eax+0x08)
        if 0 != addr_name:
            jit_method_addr = reg("ecx")
            jit_method_name = loadCStr(addr_name)
            dprintln("Method Address: " + hex(jit_method_addr) + ", Method Name: " + jit_method_name)
            global map_jit_bp
            map_jit_bp[jit_method_addr] = jit_method_name
            if is_monitoring_jit_function(jit_method_name):
                dbgCommand('bp ' + hex(jit_method_addr) + '".echo >>> ' + jit_method_name + '"')

    def callback_setjit(self):
        # dprintln("Enter into callback_setjit")
        if not is_modified_setjit:
            modify_setjit()
            if is_modified_setjit:
                self.set_bp_after_getmethodname()


parser = argparse.ArgumentParser("WinDBG PYKD Python Extension - FlashExt")
parser.add_argument("--tjit", action="store_true", help="trace JIT functions")
parser.add_argument("--bpjit", type=str, help="set breakpoint on JIT functions by name")
parser.add_argument("--lnjit", type=lambda x: hex(int(x,0)), help="displays JIT symbols at or near given address")
parser.add_argument("--export_embedded", action="store_true", help="export embedded content")
args = parser.parse_args()
if args.tjit:
    dprintln("Trace JIT Functions ...")
    search_base_address()
    search_hook_points()
    HookPointHandler()
    go()
elif args.bpjit:
    dprintln("set breakpoint at \"" + args.bpjit + "\"")
    search_base_address()
    search_hook_points()
    HookPointHandler()
    monitor_jit_funtion(args.bpjit)
    go()
elif args.lnjit:
    dprintln("list near symbol at: " + args.lnjit)
    find_near_jit_symbol(int(args.lnjit, 16))
elif args.export_embedded:
    pass
else:
    parser.print_help()