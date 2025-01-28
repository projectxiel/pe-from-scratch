format PE                           ; Win32 portable executable 
entry _start                                 ; _start is the program's entry point

include '%FASMINC%/win32a.inc'  

section '.data' data readable
        hello db "Hello World!", 0
        stringformat db "%s", 0ah, 0

section '.text' code readable executable     ; code
_start:
        invoke printf, stringformat, hello   ; call printf, defined in msvcrt.dll                      
        invoke ExitProcess, 0                ; exit the process

section '.idata' import data readable      ; data imports

library kernel, 'kernel32.dll',\             ; link to kernel32.dll, msvcrt.dll
        msvcrt, 'msvcrt.dll'

import kernel, \                             ; import ExitProcess from kernel32.dll
       ExitProcess, 'ExitProcess'

import msvcrt, \                             ; import printf from msvcrt.dll
       printf, 'printf'