/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LH_version.h - 单一版本源
 *
 * 所有版本展示必须从这里读取，禁止在其他 .c/.h/build 脚本里再写死：
 *   - KPM 元数据            LH_main.c: LH_KPM_INFO(version, LH_VERSION_STR, ...)
 *   - state_info 结构体     LH_state_info.c: kpm_build_version = LH_VERSION_CODE
 *   - info 文件 / 诊断输出  LH_main.c: INFO_APPEND("LH %s ...", LH_VERSION_STR)
 *   - 构建脚本产物命名      build.ps1: 解析本文件的 MAJOR/MINOR/PATCH
 *
 * 发布新版本只改下面三行；字符串与数值编码自动同步，避免版本不一致。
 */
#ifndef _LH_VERSION_H_
#define _LH_VERSION_H_

#include <stdint.h>

#define LH_VERSION_MAJOR 1
#define LH_VERSION_MINOR 6
#define LH_VERSION_PATCH 1

/* 两级字符串化：LH_VERSION_STR 展开为三段版本号字面量，
 * 可直接参与相邻字符串拼接（LH_KPM_INFO / INFO_APPEND）。 */
#define LH_VER_STR_(x) #x
#define LH_VER_STR(x)  LH_VER_STR_(x)
#define LH_VERSION_STR \
    LH_VER_STR(LH_VERSION_MAJOR) "." \
    LH_VER_STR(LH_VERSION_MINOR) "." \
    LH_VER_STR(LH_VERSION_PATCH)

/* 数值编码（与既有 state_info.module_version 解码一致）：
 *   major=(v>>24)&0xFF, minor=(v>>16)&0xFF, patch=(v>>8)&0xFF */
#define LH_VERSION_CODE \
    ((uint32_t)((LH_VERSION_MAJOR << 24) | (LH_VERSION_MINOR << 16) | \
                (LH_VERSION_PATCH << 8)))

#endif /* _LH_VERSION_H_ */
