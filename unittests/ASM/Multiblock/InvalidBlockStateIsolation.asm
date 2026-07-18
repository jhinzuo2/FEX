%ifdef CONFIG
{
  "Match": "All",
  "RegData": {
    "RAX": "0x20"
  }
}
%endif

; A decoded block containing an invalid LOCK/register combination must not
; poison later, independently reachable blocks in the same multiblock unit.
; The conditional branch is always taken, so the invalid block is compiled
; but never executed.
xor eax, eax
test eax, eax
jz valid_block

invalid_block:
db 0xf0, 0x80, 0xc7, 0xd4 ; LOCK ADD BH, 0xd4: invalid LOCK on a register.

valid_block:
jmp success

wrong_fallthrough:
mov rax, 0x10
hlt

success:
mov rax, 0x20
hlt
