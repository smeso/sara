/* SPDX-License-Identifier: GPL-2.0 */

/*
 * S.A.R.A. Linux Security Module
 *
 * Copyright (C) 2017 Salvatore Mesoraca <s.mesoraca16@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

#ifndef __SARA_H
#define __SARA_H

#include <linux/types.h>
#include <uapi/linux/limits.h>

#define SARA_VERSION 0
#define SARA_PATH_MAX PATH_MAX

#undef pr_fmt
#define pr_fmt(fmt) "SARA: " fmt

extern bool sara_config_locked __read_mostly;
extern bool sara_enabled __read_mostly;

void sara_init(void) __init;

#endif /* __SARA_H */
