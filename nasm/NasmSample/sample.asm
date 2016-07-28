extern ExitProcess
import ExitProcess  kernel32.dll
extern MessageBoxA
import MessageBoxA  user32.dll

[section .rdata   rdata align=8]
[section .bss     bss   align=4]
[section .data align=4 use32]
hoyo	   dd "hoyo",0
ncha	   dd "n'cha",0

;[section code class=code align=16 use32]
;le class= code sert quand meme a donner le entry point
[section .text    code  align=16 use32]

..start:

push dword 0
push dword hoyo
push dword ncha
push dword 0
call [MessageBoxA]

push dword 0
call [ExitProcess]

