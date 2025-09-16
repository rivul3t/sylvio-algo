BITS 64
; c4 7f
section .data
        woody_msg: db "....WOODY....",10
        woody_msg_len : equ $-woody_msg
        key: times 16 db "H"
        key_len : dw 16

section .text

_start_payload:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r11

    call _print_woody
    call _mprotect
    call _getvar
    jmp _xor_cipher

_end_payload:
    pop r11
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax

    call _ret2oep
    push rax
    ret

_print_woody:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel $+woody_msg-$]
    mov rdx, woody_msg_len
    syscall
    ret

_get_base_addr:
    call _get_rip
    sub eax, 0x31313131 ; offset to _get_base addr (len from begin vx to this instruction)
    sub eax, 0x99999999 ; new entry point
    ret 

_get_rip:
    mov rax, qword [rsp]
    ret

_ret2oep:
    call _get_rip
    sub rax, 0x71717171 ; virus size
    sub rax, 0x72727272 ; new entry_point
    add rax, 0x73737373 ; old entry_point
    ret

_getvar:
    call _get_base_addr
    mov rsi, 0x22222222 ; filesz
    mov rdi, 0x33333333 ; file offset
    add rdi, rax ; file offset + base addr
    call _ret2oep
    mov rdi, rax
    mov ecx, 0x44444444 ; key_len
    mov rdx, 0x55555555 ; key offset
    call _get_base_addr
    add rdx, rax ; key offset + base addr
    ret

_mprotect:
    mov edx, 0x7
    mov esi, 0x14141414 ; text_seg_size
    call _ret2oep
    mov rdi, rax
    and rdi, -0x1000
    mov rax, 0xa
    syscall
    ret

_xor_cipher:
    mov r9, 00 
    mov r15, 16

_reset_key:
;    cmp r9, rsi ; check i < text_len
;    je _end_payload
    lea r10, [rel $+key-$]
    mov r8, 00

_xor_loop:
    cmp r9, rsi ; check i < text_len
    je _end_payload

    mov rax, rdi
    mov r12b, byte[r10]
    xor byte[rax], r12b

    add rdi, 1
    add r10, 1
    add r9, 1
    add r8, 1
    cmp r8, r15
    je _reset_key
    cmp r9, rsi
    jle _xor_loop
