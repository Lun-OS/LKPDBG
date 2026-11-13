# Makefile for KPM hidden driver module
# 基于 KernelPatch KPM 构建系统
# 工具链：aarch64-none-elf- (ARM 裸机交叉编译器)
# 不要使用 aarch64-linux-gnu- (会生成动态链接，.kpm 无法加载)

# clean 目标不需要工具链
ifneq ($(MAKECMDGOALS),clean)
ifndef TARGET_COMPILE
    $(error TARGET_COMPILE not set. Example: make TARGET_COMPILE=aarch64-none-elf-)
endif
endif

ifndef KP_DIR
    # KernelPatch 源码目录（包含 kernel/include/ 等头文件）
    KP_DIR = ../KernelPatch_temp
endif

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

# 编译模式：
#   make DEBUG=1 ...    (debug 模式，默认：-O0 -g，LH_printk 输出到 dmesg)
#   make RELEASE=1 ...  (release 模式：-O2，LH_printk 空操作，零 dmesg 痕迹)
# 默认为 debug 模式（便于开发调试）
ifndef RELEASE
DEBUG ?= 1
endif

ifdef DEBUG
OPT_LEVEL  = -O0 -g
DBG_DEFS   = -DKPM_DEBUG=1
else
OPT_LEVEL  = -O2
DBG_DEFS   =
endif

# 特性选择（构建时覆盖）：
#   make FEATURE_MEM=1 FEATURE_GYRO=0 FEATURE_TOUCH=0 ...  (仅内存)
#   make FEATURE_MEM=0 FEATURE_GYRO=1 FEATURE_TOUCH=0 ...  (仅陀螺仪)
#   make FEATURE_MEM=0 FEATURE_GYRO=0 FEATURE_TOUCH=1 ...  (仅触摸)
# 默认三者全开（向后兼容）；未定义按 1 处理。
ifndef FEATURE_MEM
    FEATURE_MEM = 1
endif
ifndef FEATURE_GYRO
    FEATURE_GYRO = 1
endif
ifndef FEATURE_TOUCH
    FEATURE_TOUCH = 1
endif

FEATURE_DEFS =
ifeq ($(FEATURE_MEM),1)
    FEATURE_DEFS += -DKPM_FEATURE_MEM
endif
ifeq ($(FEATURE_GYRO),1)
    FEATURE_DEFS += -DKPM_FEATURE_GYRO
endif
ifeq ($(FEATURE_TOUCH),1)
    FEATURE_DEFS += -DKPM_FEATURE_TOUCH
endif

# 包含路径：KPM 框架头文件
INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

# 编译选项
CFLAGS = -Wall -Wextra $(OPT_LEVEL) -nostdlib -ffreestanding -fno-builtin \
         -mgeneral-regs-only -fno-stack-protector -fno-omit-frame-pointer \
         -fvisibility=hidden -fmerge-constants $(DBG_DEFS) $(FEATURE_DEFS) -Wall

TARGET = LH_main

# 源文件列表
SRCS = LH_main.c LH_syms.c LH_hooks.c LH_touch.c LH_utils.c LH_log.c LH_intercept.c touch_manager.c LH_mem_rw.c LH_mem_scan.c LH_mem_freeze.c LH_ptr_scan.c LH_debug.c LH_hook_enhanced.c LH_lib.c LH_proc.c LH_udp.c LH_stealth.c LH_state_info.c LH_dump.c LH_cmd.c LH_gyro.c LH_hide.c LH_armor.c LH_feat.c LH_suspend.c LH_filter.c LH_netctl.c LH_sysmon.c LH_resctl.c LH_hook2.c LH_force.c LH_trace.c LH_memwatch.c LH_wxshadow.c
OBJS = $(SRCS:.c=.o)

# ============================================================
# 加固(构建期后处理) —— 与 KernelPatch_temp 编译框架一致的保护
#   make PROTECT=1            : 链接后对 *.kpm 做符号随机化 + 元数据清除
#   make PROTECT_PLAIN="a,b"  : 泄漏门禁, 产物残留任一明文串则构建失败
# 安全原理: 已定义符号的名字对加载/重定位无影响(重定位按 symtab 索引,
#   加载器仅按名字解析 SHN_UNDEF 内核符号), 因此等长随机化保证加载兼容。
#   兼容优先级恒定: 内核 UNDEF 符号名 / .kpm.* 关键节名 一律不动。
# ============================================================
PYTHON ?= python
KP_PROTECT := $(KP_DIR)/tools/kpm_protect.py
comma := ,

# ---- 可选字符串加密 / 函数虚拟化 接入钩子 ----
# 存在对应 manifest/asm 时才自动生成; 源码经 #include 引用生成头后生效。
KP_ENCSTR := $(KP_DIR)/tools/encstr.py
KP_KMVM   := $(KP_DIR)/tools/kmvm_asm.py
ENC_MANIFEST := LH_main.enc
ENC_GEN      := encstr_autogen.h
VM_SRC       := LH_vm.vm
VM_GEN       := LH_vm_prog.h
ENC_DEPS := $(if $(wildcard $(ENC_MANIFEST)),$(ENC_GEN))
VM_DEPS  := $(if $(wildcard $(VM_SRC)),$(VM_GEN))

# ---- 反静态分析迷雾区：独立可执行节区 .kpm.fog ----
# 由 kpm_fog.py 确定性生成；运行时惰性（无真实代码引用/执行），仅用于让
# IDA 等静态分析工具打开即陷入大片回跳分支网。不引用任何内核符号/无 libgcc。
KP_FOG  := $(KP_DIR)/tools/kpm_fog.py
FOG_S   := LH_fog.S
FOG_OBJ := LH_fog.o

# 泄漏门禁参数: 把逗号列表展开给 kpm_protect --check-plain
ifneq ($(strip $(PROTECT_PLAIN)),)
PROTECT_EXTRA := --check-plain $(subst $(comma), ,$(PROTECT_PLAIN))
endif

# ---- 深度加固: 字符串整节区密文化 + 一次性代码抹零 ----
# kpm_armor.py 对最终 .kpm 的 .kpm.str 整节加密(与 LH_armor.c 互逆, 种子一致)。
# LH_armor.lds 仅在最终 ld -r 注入节内边界符号, 供运行时解密/抹零定位。
# make NOARMOR=1 可整体关闭(回退到未加密产物)。
KP_ARMOR  := $(KP_DIR)/tools/kpm_armor.py
ARMOR_LDS := LH_armor.lds
# 构建期随机密钥: keygen 每次(加密)构建覆盖生成混淆碎片头 LH_armor_keys.h 与
# 原始密钥旁证 .armor_keys。全部 .o 依赖碎片头 => 密钥轮换自动触发整模块重编;
# 整节区加密阶段读取旁证 str_key, 与编译期同源。
# make NOARMOR=1 时跳过 keygen, 使用仓库提交的默认头(仅够 NOARMOR 回退编译)。
# make ARMOR_SEED=0x.. 可用确定性种子(复现/自测); 省略即系统熵随机。
KEYS_HEADER := LH_armor_keys.h
KEYS_SIDE   := .armor_keys
ifeq ($(filter 1,$(NOARMOR)),1)
KEYGEN :=
else
KEYGEN := $(KEYS_HEADER) $(KEYS_SIDE)
endif
ARMOR_DEPS := $(if $(filter 1,$(NOARMOR)),,LH_armor.o $(ARMOR_LDS))

all: $(TARGET).kpm check-syms

# 生成头(仅当对应源存在时被触发)
$(ENC_GEN): $(ENC_MANIFEST)
	$(PYTHON) $(KP_ENCSTR) --in $< --out $@
$(VM_GEN): $(VM_SRC)
	$(PYTHON) $(KP_KMVM) --in $< --out $@ --seed 0x9d3f02a71c8b4e65

# 迷雾节区源/对象(工具变更时自动重新生成; 对象无 UNDEF/重定位负担)
$(FOG_S): $(KP_FOG)
	$(PYTHON) $(KP_FOG) --size 65536 --out $@
$(FOG_OBJ): $(FOG_S) $(KP_FOG)
	$(CC) $(INCLUDE_FLAGS) -c -o $@ $(FOG_S)

# 深度加固密钥生成(仅加密构建): FORCE 保证每次构建重生成随机 STR/PTR 密钥,
# 写混淆碎片头 + 原始密钥旁证。碎片头被所有 .o 依赖 => 同批新密钥整模块重编。
ifneq ($(filter 1,$(NOARMOR)),1)
$(KEYS_HEADER) $(KEYS_SIDE): FORCE
	$(PYTHON) $(KP_ARMOR) --gen-keys . $(if $(ARMOR_SEED),--seed $(ARMOR_SEED),)
endif
.PHONY: FORCE
FORCE:

# 链接为可重定位 ELF; 之后: (1) 整节区字符串加密 (2) libgcc 门禁
# (3) 可选符号混淆/元数据清除/泄漏门禁
$(TARGET).kpm: $(OBJS) $(FOG_OBJ) $(ENC_DEPS) $(VM_DEPS) $(ARMOR_LDS)
	@if [ "$(NOARMOR)" = "1" ]; then \
		$(CC) -r -o $@ $(filter-out $(ARMOR_LDS),$^) ; \
	else \
		$(CC) -r -o $@ $(filter-out $(ARMOR_LDS),$^) -T$(ARMOR_LDS) ; \
	fi
	@if [ "$(NOARMOR)" != "1" ]; then \
		$(PYTHON) $(KP_ARMOR) -f $@ -o $@ --keys-dir . ; \
	fi
	@echo "[make] checking forbidden libgcc symbols..."
	@if $(TARGET_COMPILE)nm -u $@ | grep -E '(__aarch64_|__atomic_|__sync_)' ; then \
		echo "ERROR: libgcc dependency found in $@" ; exit 1 ; \
	else \
		echo "OK: no libgcc symbols in $@" ; \
	fi
	$(if $(filter 1,$(PROTECT)),$(PYTHON) $(KP_PROTECT) --syms --zero-comment -f $@ -o $@ $(PROTECT_EXTRA))

# 编译单个源文件
# 全部源文件统一在 -mgeneral-regs-only 下编译，从构建层面杜绝 FPSIMD 指令。
%.o: %.c $(KEYS_HEADER) LH_version.h
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -T$(TARGET).lds -c -o $@ $<

.PHONY: clean
clean:
	rm -f *.o *.kpm $(ENC_GEN) $(VM_GEN) $(FOG_S) $(KEYS_SIDE)

# 编译后检查：确保无 libgcc 辅助函数残留
# KPM 运行时无 libgcc 链接，__aarch64_* / __atomic_* / __sync_* 符号会导致加载失败
.PHONY: check-syms
check-syms: $(TARGET).kpm
	@echo "Checking for forbidden libgcc symbols..."
	@if $(TARGET_COMPILE)nm -u $< | grep -E '(__aarch64_|__atomic_|__sync_)' ; then \
		echo "ERROR: Found libgcc dependency! Use inline assembly instead." ; \
		exit 1 ; \
	else \
		echo "OK: No libgcc symbols found." ; \
	fi
