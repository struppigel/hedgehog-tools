; zerobytes.asm
; Compile: yasm -f win32 zerobytes.asm -o zerobytes.obj
; Link:    link.exe /subsystem:windows /entry:main zerobytes.obj user32.lib kernel32.lib /out:zerobytes.exe

extern _MessageBoxA@16
extern _ExitProcess@4

section .data
    msg_title db "Hello", 0
    msg_text  db "Hello World!", 0
    times 4096 db 0               ; 4 KB of zero padding in .data

section .text
global main
main:
    push 0                        ; MB_OK
    push msg_title                ; lpCaption
    push msg_text                 ; lpText
    push 0                        ; hWnd = NULL
    call _MessageBoxA@16

    push 0
    call _ExitProcess@4

    times 4096 db 0               ; 64 KB zero padding in .text

section '.rsrc' data align=4
    times 65536 db 0              ; 4 KB zero-filled .rsrc section
