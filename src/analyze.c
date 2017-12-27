/*
 * The dhcpd-pools has BSD 2-clause license which also known as "Simplified
 * BSD License" or "FreeBSD License".
 *
 * Copyright 2006- Sami Kerola. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the
 *       distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR AND CONTRIBUTORS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are
 * those of the authors and should not be interpreted as representing
 * official policies, either expressed or implied, of Sami Kerola.
 */

/*! \file analyze.c
 * \brief Data analysis functions.
 */

#include <config.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "dhcpd-pools.h"

/*! \brief Prepare data for analysis. The function will sort leases and
 * ranges. */
void prepare_data(struct conf_t *state)
{
	/* Sort leases */
	HASH_SORT(state->leases, leasecomp);
	/* Sort ranges */
	qsort(state->ranges, state->num_ranges, sizeof(struct range_t), &rangecomp);
}

/*!\brief Perform counting.  Join leases with ranges, and update range and
 * shared network counters.  */
void do_counting(struct conf_t *state)
{
	struct range_t *restrict range_p = state->ranges;
	const struct leases_t *restrict l = state->leases;
	unsigned long i;
	double block_size;

	/* Walk through ranges */
	for (i = 0; i < state->num_ranges; i++, range_p++) {
		while (l != NULL && ipcomp(&range_p->first_ip, &l->ip) < 0)
			l = l->hh.prev;	/* rewind */
		if (l == NULL)
			l = state->leases;
		for (; l != NULL && ipcomp(&l->ip, &range_p->last_ip) <= 0; l = l->hh.next) {
			if (unlikely(ipcomp(&l->ip, &range_p->first_ip) < 0))
				continue;	/* cannot happen? */
			/* IP in range */
			switch (l->type) {
			case FREE:
				range_p->touched++;
				break;
			case ACTIVE:
				range_p->count++;
				break;
			case BACKUP:
				range_p->backups++;
				break;
			}
		}
		/* Size of range size. */
		block_size = get_range_size(range_p);
		/* Count together ranges within shared network block. */
		range_p->shared_net->available += block_size;
		range_p->shared_net->used += range_p->count;
		range_p->shared_net->touched += range_p->touched;
		range_p->shared_net->backups += range_p->backups;
		/* When shared network is not 'all networks' add it as well. */
		if (range_p->shared_net != state->shared_net_root) {
			state->shared_net_root->available += block_size;
			state->shared_net_root->used += range_p->count;
			state->shared_net_root->touched += range_p->touched;
			state->shared_net_root->backups += range_p->backups;
		}
	}
}
