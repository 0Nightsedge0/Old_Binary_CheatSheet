# Fuzz
# packet fuzzing

## Spike
- s_binary = static input
- s_string_variable = fuzzing point

### TFTP fuzzing
```
s_binary("0002");
s_string_variable("netascii")
s_binary("00");
s_string_variable("netascii")
s_binary("00");
sleep(1);
```

### bigger jmp back (512 bytes)
```
fldz
fnstenv
pop ecx
add c1, 10
nop

dec ch        ; ecx=-256
dec ch        ; ecx=-256
jmp ecx       ; jmp ecx -512
```
