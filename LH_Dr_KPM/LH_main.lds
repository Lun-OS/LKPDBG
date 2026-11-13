SECTIONS {
	.plt (NOLOAD) : { BYTE(0) }
	.init.plt (NOLOAD) : { BYTE(0) }
	.text.ftrace_trampoline (NOLOAD) : { BYTE(0) }
	/* 归拢全部字符串字面量到专用节区：供构建期整节区加密 + 运行时一次性解密 */
	.kpm.str : { *(.rodata.str1.1) *(.rodata.str1.2) *(.rodata.str1.4) *(.rodata.str2.*) *(.rodata.str4.*) *(.rodata.str8.*) *(.rodata.str*) }
	/* 归拢一次性初始化代码（如符号解析）到专用节区：init 末尾整段抹零 */
	.kpm.once : { *(.kpm.once .kpm.once.*) }
}