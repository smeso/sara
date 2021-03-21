/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __SARA_H
#define __SARA_H

#include <linux/types.h>
#include <uapi/linux/limits.h>

#define SARA_VERSION 0
#define SARA_PATH_MAX PATH_MAX

#undef pr_fmt
#define pr_fmt(fmt) "SARA: " fmt

extern int sara_config_locked __read_mostly;
extern int sara_enabled __read_mostly;

#endif /* __SARA_H */
