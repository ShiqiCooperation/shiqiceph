;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;  Copyright(c) 2011-2014 Intel Corporation All rights reserved.
;
;  Redistribution and use in source and binary forms, with or without
;  modification, are permitted provided that the following conditions
;  are met:
;    * Redistributions of source code must retain the above copyright
;      notice, this list of conditions and the following disclaimer.
;    * Redistributions in binary form must reproduce the above copyright
;      notice, this list of conditions and the following disclaimer in
;      the documentation and/or other materials provided with the
;      distribution.
;    * Neither the name of Intel Corporation nor the names of its
;      contributors may be used to endorse or promote products derived
;      from this software without specific prior written permission.
;
;  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
;  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
;  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
;  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
;  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
;  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%ifidn __OUTPUT_FORMAT__, elf64
%define WRT_OPT		wrt ..plt
%else
%define WRT_OPT
%endif

%ifidn __OUTPUT_FORMAT__, elf32

[bits 32]

%define def_wrd		dd
%define wrd_sz  	dword
%define arg1		esi

%else

%include "reg_sizes.asm"
default rel
[bits 64]

%define def_wrd 	dq
%define wrd_sz  	qword
%define arg1		rsi

extern ec_encode_data_sse
extern ec_encode_data_avx
extern ec_encode_data_avx2
extern gf_vect_mul_sse
extern gf_vect_mul_avx
extern gf_vect_dot_prod_sse
extern gf_vect_dot_prod_avx
extern gf_vect_dot_prod_avx2
%endif

extern gf_vect_mul_base
extern ec_encode_data_base
extern gf_vect_dot_prod_base

section .data
;;; *_mbinit are initial values for *_dispatched; is updated on first call.
;;; Therefore, *_dispatch_init is only executed on first call.

ec_encode_data_dispatched:
	def_wrd      ec_encode_data_mbinit

gf_vect_mul_dispatched:
	def_wrd      gf_vect_mul_mbinit

gf_vect_dot_prod_dispatched:
	def_wrd      gf_vect_dot_prod_mbinit

section .text
;;;;
; ec_encode_data multibinary function
;;;;
global ec_encode_data:function
ec_encode_data_mbinit:
	call	ec_encode_data_dispatch_init

ec_encode_data:
	jmp	wrd_sz [ec_encode_data_dispatched]

ec_encode_data_dispatch_init:
	push    arg1
%ifidn __OUTPUT_FORMAT__, elf32		;; 32-bit check
	lea     arg1, [ec_encode_data_base]
%else
	push    rax
	push    rbx
	push    rcx
	push    rdx
	lea     arg1, [ec_encode_data_base WRT_OPT] ; Default

	mov     eax, 1
	cpuid
	lea     rbx, [ec_encode_data_sse WRT_OPT]
	test    ecx, FLAG_CPUID1_ECX_SSE4_1
	cmovne  arg1, rbx

	and	ecx, (FLAG_CPUID1_ECX_AVX | FLAG_CPUID1_ECX_OSXSAVE)
	cmp	ecx, (FLAG_CPUID1_ECX_AVX | FLAG_CPUID1_ECX_OSXSAVE)
	lea	rbx, [ec_encode_data_avx WRT_OPT]

	jne	_done_ec_encode_data_init
	mov	rsi, rbx

	;; Try for AVX2
	xor	ecx, ecx
	mov	eax, 7
	cpuid
	test	ebx, FLAG_CPUID1_EBX_AVX2
	lea     rbx, [ec_encode_data_avx2 WRT_OPT]
	cmovne	rsi, rbx

	;; Does it have xmm and ymm support
	xor	ecx, ecx
	xgetbv
	and	eax, FLAG_XGETBV_EAX_XMM_YMM
	cmp	eax, FLAG_XGETBV_EAX_XMM_YMM
	je	_done_ec_encode_data_init
	lea     rsi, [ec_encode_data_sse WRT_OPT]

_done_ec_encode_data_init:
	pop     rdx
	pop     rcx
	pop     rbx
	pop     rax
%endif			;; END 32-bit check
	mov     [ec_encode_data_dispatched], arg1
	pop     arg1
	ret

;;;;
; gf_vect_mul multibinary function
;;;;
global gf_vect_mul:function
gf_vect_mul_mbinit:
	call    gf_vect_mul_dispatch_init

gf_vect_mul:
	jmp	wrd_sz [gf_vect_mul_dispatched]

gf_vect_mul_dispatch_init:
	push    arg1
%ifidn __OUTPUT_FORMAT__, elf32		;; 32-bit check
	lea     arg1, [gf_vect_mul_base]
%else
	push    rax
	push    rbx
	push    rcx
	push    rdx
	lea     arg1, [gf_vect_mul_base WRT_OPT] ; Default

	mov     eax, 1
	cpuid
	test    ecx, FLAG_CPUID1_ECX_SSE4_2
	lea     rbx, [gf_vect_mul_sse WRT_OPT]
	je	_done_gf_vect_mul_dispatch_init
	mov  	arg1, rbx

	;; Try for AVX
	and     ecx, (FLAG_CPUID1_ECX_OSXSAVE | FLAG_CPUID1_ECX_AVX)
	cmp     ecx, (FLAG_CPUID1_ECX_OSXSAVE | FLAG_CPUID1_ECX_AVX)
	jne     _done_gf_vect_mul_dispatch_init

	;; Does it have xmm and ymm support
	xor     ecx, ecx
	xgetbv
	and     eax, FLAG_XGETBV_EAX_XMM_YMM
	cmp     eax, FLAG_XGETBV_EAX_XMM_YMM
	jne     _done_gf_vect_mul_dispatch_init
	lea     arg1, [gf_vect_mul_avx WRT_OPT]

_done_gf_vect_mul_dispatch_init:
	pop     rdx
	pop     rcx
	pop     rbx
	pop     rax
%endif			;; END 32-bit check
	mov     [gf_vect_mul_dispatched], arg1
	pop     arg1
	ret


;;;;
; gf_vect_dot_prod multibinary function
;;;;
global gf_vect_dot_prod:function
gf_vect_dot_prod_mbinit:
	call    gf_vect_dot_prod_dispatch_init

gf_vect_dot_prod:
	jmp     wrd_sz [gf_vect_dot_prod_dispatched]

gf_vect_dot_prod_dispatch_init:
	push    arg1
%ifidn __OUTPUT_FORMAT__, elf32         ;; 32-bit check
	lea     arg1, [gf_vect_dot_prod_base]
%else
	push	rax
	push	rbx
	push	rcx
	push	rdx
	lea     arg1, [gf_vect_dot_prod_base WRT_OPT] ; Default

	mov     eax, 1
	cpuid
	lea     rbx, [gf_vect_dot_prod_sse WRT_OPT]
	test    ecx, FLAG_CPUID1_ECX_SSE4_1
	cmovne  arg1, rbx

	and	ecx, (FLAG_CPUID1_ECX_AVX | FLAG_CPUID1_ECX_OSXSAVE)
	cmp	ecx, (FLAG_CPUID1_ECX_AVX | FLAG_CPUID1_ECX_OSXSAVE)
	lea     rbx, [gf_vect_dot_prod_avx WRT_OPT]

	jne     _done_gf_vect_dot_prod_init
	mov	rsi, rbx

	;; Try for AVX2
	xor	ecx, ecx
	mov	eax, 7
	cpuid
	test	ebx, FLAG_CPUID1_EBX_AVX2
	lea     rbx, [gf_vect_dot_prod_avx2 WRT_OPT]
	cmovne	rsi, rbx

	;; Does it have xmm and ymm support
	xor	ecx, ecx
	xgetbv
	and	eax, FLAG_XGETBV_EAX_XMM_YMM
	cmp	eax, FLAG_XGETBV_EAX_XMM_YMM
	je	_done_gf_vect_dot_prod_init
	lea     rsi, [gf_vect_dot_prod_sse WRT_OPT]

_done_gf_vect_dot_prod_init:
	pop     rdx
	pop     rcx
	pop     rbx
	pop     rax
%endif			;; END 32-bit check
	mov     [gf_vect_dot_prod_dispatched], arg1
	pop	arg1
	ret

%macro slversion 4
global %1_slver_%2%3%4
global %1_slver
%1_slver:
%1_slver_%2%3%4:
	dw 0x%4
	db 0x%3, 0x%2
%endmacro

;;;       func                  core, ver, snum
slversion ec_encode_data,	00,   02,  0133
slversion gf_vect_mul,		00,   02,  0134
slversion gf_vect_dot_prod,	00,   01,  0138
; inform linker that this doesn't require executable stack
section .note.GNU-stack noalloc noexec nowrite progbits
