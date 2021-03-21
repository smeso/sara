/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __SARA_DFA_H
#define __SARA_DFA_H

#include "securityfs.h"

#ifdef CONFIG_SARA_DFA_32BIT
typedef uint32_t sara_dfa_state;
typedef uint32_t sara_dfa_output;
#define SARA_INVALID_DFA_VALUE 0xffffffffu
#else
typedef uint16_t sara_dfa_state;
typedef uint16_t sara_dfa_output;
#define SARA_INVALID_DFA_VALUE 0xffffu
#endif

#define SARA_DFA_VERSION 2

struct sara_dfa_tables {
	sara_dfa_state states;
	sara_dfa_state cmp_states;
	sara_dfa_output *output;
	sara_dfa_state *def;
	sara_dfa_state *base;
	sara_dfa_state *next;
	sara_dfa_state *check;
	char hash[SARA_CONFIG_HASH_LEN];
};

int sara_dfa_match(struct sara_dfa_tables *dfa,
		   const unsigned char *s,
		   sara_dfa_output *output);
struct sara_dfa_tables *sara_dfa_make_null(void);
struct sara_dfa_tables *sara_dfa_load(const char *buf,
				      size_t buf_len,
				      bool (*is_valid)(sara_dfa_output));
ssize_t sara_dfa_dump(const struct sara_dfa_tables *dfa, char **buffer);
void sara_dfa_free_tables(struct sara_dfa_tables *dfa);

#endif /* __SARA_DFA_H */
