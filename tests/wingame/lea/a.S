.text
.globl getptr
getptr:
  lea leaf(%rip), %rax
  ret
  .byte 0x48, 0xB8, 1, 2, 3      /* data in the code section (like a jump table): decodes as the
                                    start of a 10-byte instruction that swallows leaf's first bytes */
leaf:
  mov $42, %eax
  add %ecx, %eax
  ret
