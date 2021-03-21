// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/slab.h>

#include "include/sara.h"
#include "include/dfa.h"
#include "include/securityfs.h"

#define DFA_MAGIC_SIZE 8
#define DFA_MAGIC "SARADFAT"

#define DFA_INPUTS 255

#ifndef CONFIG_SECURITY_SARA_DFA_32BIT
#define pr_err_dfa_size() \
	pr_err_ratelimited("DFA: too many states. Recompile kernel with CONFIG_SARA_DFA_32BIT.\n")
#else
#define pr_err_dfa_size() pr_err_ratelimited("DFA: too many states.\n")
#endif

void sara_dfa_free_tables(struct sara_dfa_tables *dfa)
{
	if (dfa) {
		kvfree(dfa->output);
		kvfree(dfa->def);
		kvfree(dfa->base);
		kvfree(dfa->next);
		kvfree(dfa->check);
		kvfree(dfa);
	}
}

static struct sara_dfa_tables *sara_dfa_alloc_tables(sara_dfa_state states,
						     sara_dfa_state cmp_states)
{
	struct sara_dfa_tables *tmp = NULL;

	tmp = kvzalloc(sizeof(*tmp), GFP_KERNEL_ACCOUNT);
	if (!tmp)
		goto err;
	tmp->output = kvcalloc(states,
			       sizeof(*tmp->output),
			       GFP_KERNEL_ACCOUNT);
	if (!tmp->output)
		goto err;
	tmp->def = kvcalloc(states,
			    sizeof(*tmp->def),
			    GFP_KERNEL_ACCOUNT);
	if (!tmp->def)
		goto err;
	tmp->base = kvcalloc(states,
			     sizeof(*tmp->base),
			     GFP_KERNEL_ACCOUNT);
	if (!tmp->base)
		goto err;
	tmp->next = kvcalloc(cmp_states,
			     sizeof(*tmp->next) * DFA_INPUTS,
			     GFP_KERNEL_ACCOUNT);
	if (!tmp->next)
		goto err;
	tmp->check = kvcalloc(cmp_states,
			      sizeof(*tmp->check) * DFA_INPUTS,
			      GFP_KERNEL_ACCOUNT);
	if (!tmp->check)
		goto err;
	tmp->states = states;
	tmp->cmp_states = cmp_states;
	return tmp;

err:
	sara_dfa_free_tables(tmp);
	return ERR_PTR(-ENOMEM);
}

int sara_dfa_match(struct sara_dfa_tables *dfa,
		   const unsigned char *s,
		   sara_dfa_output *output)
{
	sara_dfa_state i, j;
	sara_dfa_state c_state = 0;

	/* Max s[x] value must be == DFA_INPUTS */
	BUILD_BUG_ON((((1ULL << (sizeof(*s) * 8)) - 1) != DFA_INPUTS));

	/*
	 * The DFA transition table is compressed using 5 linear arrays
	 * as shown in the Dragon Book.
	 * These arrays are: default, base, next, check and output.
	 * default, base and output have the same size and are indexed by
	 * state number.
	 * next and check tables have the same size and are indexed by
	 * the value from base for a given state and the input symbol.
	 * To match a string against this set of arrays we need to:
	 * - Use the base arrays to recover the index to use
	 *   with check and next arrays for the current state and symbol.
	 * - If the value in the check array matches the current state
	 *   number the next state should be retrieved from the next array,
	 *   otherwise we take it from the default array.
	 * - If the next state is not valid we should return immediately
	 * - If the input sequence is over and the value in the output array
	 *   is valid, the string matches, and we should return the output
	 *   value.
	 */

	for (i = 0; s[i]; i++) {
		j = (dfa->base[c_state] * DFA_INPUTS) + s[i] - 1;
		if (dfa->check[j] != c_state)
			c_state = dfa->def[c_state];
		else
			c_state = dfa->next[j];
		if (c_state == SARA_INVALID_DFA_VALUE)
			return 0;
	}

	if (dfa->output[c_state] != SARA_INVALID_DFA_VALUE) {
		*output = dfa->output[c_state];
		return 1;
	}
	return 0;
}

struct sara_dfa_tables *sara_dfa_make_null(void)
{
	int i;
	struct sara_dfa_tables *dfa = NULL;

	dfa = sara_dfa_alloc_tables(1, 1);
	if (IS_ERR_OR_NULL(dfa))
		return NULL;
	dfa->output[0] = SARA_INVALID_DFA_VALUE;
	dfa->def[0] = SARA_INVALID_DFA_VALUE;
	dfa->base[0] = 0;
	for (i = 0; i < DFA_INPUTS; ++i)
		dfa->next[i] = SARA_INVALID_DFA_VALUE;
	for (i = 0; i < DFA_INPUTS; ++i)
		dfa->check[i] = 0;
	memset(dfa->hash, 0, SARA_CONFIG_HASH_LEN);
	return dfa;
}

struct binary_dfa_header {
	char magic[DFA_MAGIC_SIZE];
	__le32 version;
	__le32 states;
	__le32 cmp_states;
	char hash[SARA_CONFIG_HASH_LEN];
} __packed;

#define SARA_INVALID_DFA_VALUE_LOAD 0xffffffffu

struct sara_dfa_tables *sara_dfa_load(const char *buf,
				      size_t buf_len,
				      bool (*is_valid)(sara_dfa_output))
{
	int ret;
	struct sara_dfa_tables *dfa = NULL;
	struct binary_dfa_header *h = (struct binary_dfa_header *) buf;
	__le32 *p;
	uint64_t i;
	u32 version, states, cmp_states, tmp;

	ret = -EINVAL;
	if (unlikely(buf_len < sizeof(*h)))
		goto out;

	ret = -EINVAL;
	if (unlikely(memcmp(h->magic, DFA_MAGIC, DFA_MAGIC_SIZE) != 0))
		goto out;
	version = le32_to_cpu(h->version);
	states = le32_to_cpu(h->states);
	cmp_states = le32_to_cpu(h->cmp_states);
	if (unlikely(version != SARA_DFA_VERSION)) {
		pr_err_ratelimited("DFA: unsupported version\n");
		goto out;
	}
	if (unlikely(states >= SARA_INVALID_DFA_VALUE ||
		     cmp_states >= SARA_INVALID_DFA_VALUE)) {
		pr_err_dfa_size();
		goto out;
	}
	if (unlikely(states == 0 ||
		     cmp_states == 0))
		goto out;
	if (unlikely(((states * sizeof(u32) * 3) +
		      (cmp_states * sizeof(u32) * 2 * DFA_INPUTS) +
		      sizeof(*h)) != buf_len))
		goto out;

	ret = -ENOMEM;
	dfa = sara_dfa_alloc_tables(h->states, h->cmp_states);
	if (IS_ERR_OR_NULL(dfa))
		goto out;

	dfa->states = states;
	dfa->cmp_states = cmp_states;

	ret = -EINVAL;
	p = (__le32 *) (buf + sizeof(*h));
	for (i = 0; i < dfa->states; i++) {
		tmp = le32_to_cpu(*p);
		if (unlikely(tmp != SARA_INVALID_DFA_VALUE_LOAD &&
			     tmp >= dfa->states))
			goto out_alloc;
		dfa->def[i] = (sara_dfa_state) tmp;
		++p;
	}
	for (i = 0; i < dfa->states; i++) {
		tmp = le32_to_cpu(*p);
		if (unlikely(tmp >= dfa->cmp_states))
			goto out_alloc;
		dfa->base[i] = (sara_dfa_state) tmp;
		++p;
	}
	for (i = 0; i < (dfa->cmp_states * DFA_INPUTS); i++) {
		tmp = le32_to_cpu(*p);
		if (unlikely(tmp != SARA_INVALID_DFA_VALUE_LOAD &&
			     tmp >= dfa->states))
			goto out_alloc;
		dfa->next[i] = (sara_dfa_state) tmp;
		++p;
	}
	for (i = 0; i < (dfa->cmp_states * DFA_INPUTS); i++) {
		tmp = le32_to_cpu(*p);
		if (unlikely(tmp != SARA_INVALID_DFA_VALUE_LOAD &&
			     tmp >= dfa->states))
			goto out_alloc;
		dfa->check[i] = (sara_dfa_state) tmp;
		++p;
	}
	for (i = 0; i < dfa->states; i++) {
		tmp = le32_to_cpu(*p);
		if (unlikely(tmp != SARA_INVALID_DFA_VALUE_LOAD &&
			     !is_valid(tmp)))
			goto out_alloc;
		dfa->output[i] = (sara_dfa_state) tmp;
		++p;
	}
	if (unlikely((void *) p != (void *) (buf + buf_len)))
		goto out_alloc;

	BUILD_BUG_ON(sizeof(dfa->hash) != sizeof(h->hash));
	memcpy(dfa->hash, h->hash, sizeof(dfa->hash));

	return dfa;
out_alloc:
	sara_dfa_free_tables(dfa);
out:
	pr_err_ratelimited("DFA: invalid load\n");
	return ERR_PTR(ret);
}

ssize_t sara_dfa_dump(const struct sara_dfa_tables *dfa, char **buffer)
{
	char *buf;
	size_t buf_len = 0;
	struct binary_dfa_header *h;
	__le32 *p;
	int i;

	buf_len = sizeof(*h) +
		  dfa->states * sizeof(__le32) * 3 +
		  dfa->cmp_states * sizeof(__le32) * DFA_INPUTS * 2;
	buf = kvmalloc(buf_len, GFP_KERNEL_ACCOUNT);
	if (unlikely(!buf))
		return -ENOMEM;

	h = (struct binary_dfa_header *) buf;
	memcpy(h->magic, DFA_MAGIC, DFA_MAGIC_SIZE);
	h->version = cpu_to_le32(SARA_DFA_VERSION);
	h->states = cpu_to_le32(dfa->states);
	h->cmp_states = cpu_to_le32(dfa->cmp_states);
	BUILD_BUG_ON(sizeof(dfa->hash) != sizeof(h->hash));
	memcpy(h->hash, dfa->hash, sizeof(dfa->hash));

	p = (__le32 *) (buf + sizeof(*h));
	for (i = 0; i < dfa->states; i++) {
		if (dfa->def[i] == SARA_INVALID_DFA_VALUE)
			*p++ = cpu_to_le32(SARA_INVALID_DFA_VALUE_LOAD);
		else
			*p++ = cpu_to_le32(dfa->def[i]);
	}
	for (i = 0; i < dfa->states; i++) {
		if (dfa->base[i] == SARA_INVALID_DFA_VALUE)
			*p++ = cpu_to_le32(SARA_INVALID_DFA_VALUE_LOAD);
		else
			*p++ = cpu_to_le32(dfa->base[i]);
	}
	for (i = 0; i < (dfa->cmp_states * DFA_INPUTS); i++) {
		if (dfa->next[i] == SARA_INVALID_DFA_VALUE)
			*p++ = cpu_to_le32(SARA_INVALID_DFA_VALUE_LOAD);
		else
			*p++ = cpu_to_le32(dfa->next[i]);
	}
	for (i = 0; i < (dfa->cmp_states * DFA_INPUTS); i++) {
		if (dfa->check[i] == SARA_INVALID_DFA_VALUE)
			*p++ = cpu_to_le32(SARA_INVALID_DFA_VALUE_LOAD);
		else
			*p++ = cpu_to_le32(dfa->check[i]);
	}
	for (i = 0; i < dfa->states; i++) {
		if (dfa->output[i] == SARA_INVALID_DFA_VALUE)
			*p++ = cpu_to_le32(SARA_INVALID_DFA_VALUE_LOAD);
		else
			*p++ = cpu_to_le32(dfa->output[i]);
	}

	if (unlikely((void *) p != (void *) (buf + buf_len))) {
		/*
		 * We can calculate the correct buffer size upfront.
		 * This should never happen.
		 */
		kvfree(buf);
		pr_crit("memory corruption in %s\n", __func__);
		return 0;
	}

	*buffer = buf;
	return buf_len;
}

#undef SARA_INVALID_DFA_VALUE_LOAD
