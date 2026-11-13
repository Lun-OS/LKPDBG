/*
 * LH_armor.lds — 仅在最终 `ld -r` 阶段使用。
 * 目的：把各对象的字符串节(.rodata.str*)与一次性代码节(.kpm.once)归拢成
 * 专用输出节，并在其中注入"节内定义符号"作为边界。
 *
 * loader 会把节内符号按 st_value += 节运行基址 重定位（module.c simplify_symbols），
 * 因此 __kenc_region_begin 等在运行时拿到的是模块内存里的真实地址。
 *
 * 注意：每对象编译阶段的 -T 对汇编器无效，对象里字符串节名仍是 GCC 原生
 * .rodata.str1.*；因此这里匹配 .rodata.str*，而不是 .kpm.str。
 */
SECTIONS {
	.kpm.str : {
		__kenc_region_begin = .;
		*(.rodata.str1.1) *(.rodata.str1.2) *(.rodata.str1.4) *(.rodata.str1.8)
		*(.rodata.str2.*) *(.rodata.str4.*) *(.rodata.str8.*)
		*(.rodata.str*) *(.kpm.str .kpm.str.*)
		__kenc_region_end = .;
	}
	.kpm.once : {
		__konce_region_begin = .;
		*(.kpm.once .kpm.once.*)
		__konce_region_end = .;
	}
}