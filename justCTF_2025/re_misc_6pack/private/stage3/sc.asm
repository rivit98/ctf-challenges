bits 64

stage1_len equ 0x100
stage2_len equ 0x800

; rcx is a pointer to the flag string
; unpack self, run validator
mov r15, rcx

; figure out legth of the string
call strlen
mov r14, rax

; flag length check
cmp r14, FLAG_LENGTH
je .continue

mov rax, 1
ret


.continue:
; reverse string in place
call rev_string

; self decrypt
call smc

; call validator
mov rcx, r15 ; flag ptr
mov rdx, r14 ; flag length
call newcode

ret


; FUNCTIONS
strlen:
    mov rdi, rcx
    xor rax, rax
    mov rcx, 0x100
    repne scasb
    mov rax, 0x100
    sub rax, rcx
    dec rax
    ret


rev_string:
    lea rdi, [r15]
    lea rsi, [r15+r14-1]
    mov rcx, r14
    shr rcx, 1

    _rev:
        movzx rax, byte [rdi]
        movzx rbx, byte [rsi]
        mov [rsi], al
        mov [rdi], bl

        inc rdi
        dec rsi
    loop _rev

    xor rax, rax
    ret

smc:
    mov rcx, stage2_len-stage1_len
    lea rdi, [rel newcode]
    decode:
        xor byte [rdi + rcx - 1], 0x17
        loop decode

    ret


; Align to 512 bytes using NOPs
times (stage1_len - ($ - $$)) db 0x90


newcode:

    ; Reference: https://github.com/edxsh/MyWarez/blob/c0c3bcbd1d206ff6fff7efb2c798538d79fbe87f/MyWarez/Resources/Static/Yasm/MessageBox_x64.yasm

    push rbp
    mov rbp, rsp
    sub rsp, 0x70 ; shadow space + 4 locals + 0x20 byte array for sha256 hash

    mov [rbp-0x8], rcx  ; flag ptr
    mov [rbp-0x10], rdx ; flag length
    mov qword [rbp-0x18], 0 ; hash idx
    mov qword [rbp-0x20], 0 ; loop counter

    mov qword [rbp-0x28], 0 ; hash data
    mov qword [rbp-0x30], 0 ; hash data
    mov qword [rbp-0x38], 0 ; hash data
    mov qword [rbp-0x40], 0 ; hash data

    mov qword [rbp-0x48], 0 ; ok counter


    mov r12, [gs:60h]       ; peb
    mov r12, [r12 + 0x18]   ; Peb --> LDR
    mov r12, [r12 + 0x20]   ; Peb.Ldr.InMemoryOrderModuleList
    mov r12, [r12]          ; 2st entry
    mov r15, [r12 + 0x20]   ; ntdll.dll base address!
    mov r12, [r12]          ; 3nd entry
    mov r12, [r12 + 0x20]   ; kernel32.dll base address! We go 20 bytes in here as we are already 10 bytes into the _LDR_DATA_TABLE_ENTRY from the InMemoryOrderModuleList


    ; find address of loadLibraryA from kernel32.dll which was found above. 
    mov edx, dword [rel hash_LoadLibraryA]
    mov rcx, r12
    call GetProcessAddress
    mov r12, rax

    lea rcx, [rel bcrypt_str]
    call r12
    mov r12, rax ; store bcrypt base addr


    mov rax, [rbp-0x10]
    xor rdx, rdx
    mov rcx, 3
    div rcx
    mov [rbp-0x20], rax
    .hash_loop:
        mov rcx, [rbp-0x8]
        mov rdx, rcx
        add rdx, 3
        mov qword [rbp-0x8], rdx

        lea rdx, [rbp-0x40]
        call Hash3ByteBlock

        ; compare hashes
        lea rdi, [rbp-0x40]
        lea rsi, [rel EXPECTED_HASHES]
        mov rax, [rbp-0x18]
        lea rsi, [rsi + rax*8]
        mov rcx, 32
        cld
        repe cmpsb
        setz al

        add qword [rbp-0x48], rax

        add qword [rbp-0x18], 4
        dec qword [rbp-0x20]
        jnz .hash_loop


    ; 6 chunks have to match
    cmp qword [rbp-0x48], FLAG_CHUNKS
    jnz .error


    mov rax, 0
    leave
    ret

.error:
    mov rax, 1
    leave
    ret


;Hashing section to resolve a function address
GetProcessAddress:    
        mov r13, rcx                     ;r13 = absolute base address of image/dll loaded 
        mov eax, [r13 + 0x3c]           ;eax = offset of the PE header (relative to the image base)
        mov r14d, [r13 + rax + 0x88]    ;r14d = offset of the PE export table (relative to the image base)

        add r14, r13                  ;r14 = absolute address of the export table
        mov r10d, [r14 + 0x18]         ;r10d = export table->numberOfNames 
        mov ebx, [r14 + 0x20]          ;ebx = offset of the export name pointer table (relative to the image base)
        add rbx, r13                   ;rbx = absolute address of the export name pointer table
        
    find_function_loop:  
        jecxz find_function_finished   ;if ecx is zero, quit :( nothing found. 
        dec r10d                       ;dec ECX by one for the loop until a match/none are found
        mov esi, [rbx + r10 * 4]      ;get a name to play with from the export table. 
        add rsi, r13                  ;rsi = absolute address of the current name to search on. 
        
    find_hashes:
        xor edi, edi
        xor eax, eax
        cld      
        
    continue_hashing:  
        lodsb                         ;get into al from esi
        test al, al                   ;is the end of string reached?
        jz compute_hash_finished
        ror dword edi, 0xd            ;ROR13 for hash calculation
        add edi, eax    
        jmp continue_hashing
        
    compute_hash_finished:
        cmp edi, edx                  ;edx has the function hash
        jnz find_function_loop        ;didn't match, keep trying!
        mov ebx, [r14 + 0x24]        ;ebx = the ordinal table offset
        add rbx, r13                 ;rbx = absolute address of ordinal table
        xor ecx, ecx                  ;ensure ecx is 0'd. 
        mov cx, [rbx + 2 * r10]      ;ordinal = 2 bytes. Get the current ordinal and put it in cx. ECX was our counter for which # we were in. 
        mov ebx, [r14 + 0x1c]        ;ebx = the address table offset
        add rbx, r13                 ;rbx = absolute address of address table
        mov eax, [rbx + 4 * rcx]      ;eax = relative address of the target function
        add rax, r13         ;rax = absolute address of the target function
        
    find_function_finished:
        ret 


hash_LoadLibraryA:
    dd 0xec0e4e8e
hash_BCryptOpenAlgorithmProvider:
    dd 0xad3b3e2c
hash_BCryptCreateHash:
    dd 0x8105a138
hash_BCryptHashData:
    dd 0xe3122629
hash_BCryptFinishHash:
    dd 0xf825ea57
hash_BCryptDestroyHash:
    dd 0x2616ae7a
hash_BCryptCloseAlgorithmProvider:
    dd 0xf783037b


Hash3ByteBlock:
    push rbp
    mov rbp, rsp
    sub rsp, 0x50 ; shadow space + 3 locals + 3 stack args

    mov [rbp-0x8], rcx
    mov [rbp-0x10], rdx

    ; BCryptOpenAlgorithmProvider(&g_hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    mov edx, dword [rel hash_BCryptOpenAlgorithmProvider]
    mov rcx, r12
    call GetProcessAddress
    mov r13, rax

    lea rcx, [rel g_hAlg]                   ; *phAlgorithm
    lea rdx, [rel BCRYPT_SHA256_ALGORITHM]  ; pszAlgId
    xor r8, r8                              ; pszImplementation
    xor r9, r9                              ; dwFlags
    call r13

    test rax, rax
    jnz .error


    ; BCryptCreateHash(g_hAlg, &g_hHash, NULL, 0, NULL, 0, 0);
    mov edx, dword [rel hash_BCryptCreateHash]
    mov rcx, r12
    call GetProcessAddress
    mov r13, rax

    mov rcx, [rel g_hAlg]   ; hAlgorithm
    lea rdx, [rel g_hHash] ; *phHash
    xor r8, r8              ; pbHashObject
    xor r9, r9              ; cbHashObject
    mov qword [rsp+0x20], 0 ; pbSecret
    mov qword [rsp+0x28], 0 ; cbSecret
    mov qword [rsp+0x30], 0 ; dwFlags
    call r13

    test rax, rax
    jnz .error


    ; BCryptHashData(g_hHash, (PBYTE)str1, (ULONG)strlen(str1), 0);
    mov edx, dword [rel hash_BCryptHashData]
    mov rcx, r12
    call GetProcessAddress
    mov r13, rax

    mov rcx, [rel g_hHash]
    mov rdx, [rbp-0x8]
    mov r8, 3
    xor r9, r9
    call r13

    test rax, rax
    jnz .error


    ; BCryptFinishHash(g_hHash, g_hashOutput, SHA1_HASH_SIZE, 0);
    mov edx, dword [rel hash_BCryptFinishHash]
    mov rcx, r12
    call GetProcessAddress
    mov r13, rax

    mov rcx, [rel g_hHash]
    mov rdx, [rbp-0x10]
    mov r8, 32
    xor r9, r9
    call r13

    test rax, rax
    jnz .error


    ; BCryptDestroyHash(g_hHash);
    mov edx, dword [rel hash_BCryptDestroyHash]
    mov rcx, r12
    call GetProcessAddress
    mov r13, rax

    mov rcx, [rel g_hHash]
    call r13

    test rax, rax
    jnz .error


    ; BCryptCloseAlgorithmProvider(g_hAlg, 0);
    mov edx, dword [rel hash_BCryptCloseAlgorithmProvider]
    mov rcx, r12
    call GetProcessAddress
    mov r13, rax

    mov rcx, [rel g_hAlg]
    xor rdx, rdx
    call r13

    test rax, rax
    jnz .error


    mov rax, 0
    leave
    ret

.error:
    mov rax, 1
    leave
    ret


bcrypt_str:
    db  'bcrypt.dll'
    db 0

g_hAlg:
    dq 0

g_hHash:
    dq 0

BCRYPT_SHA256_ALGORITHM:
    db __utf16__ `SHA256\0`


%include 'hashed_data.asm'


times (stage2_len - ($ - $$)) db 0x90