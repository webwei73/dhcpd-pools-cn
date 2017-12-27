/*
 * The dhcpd-pools has BSD 2-clause license which also known as "Simplified
 * BSD License" or "FreeBSD License".
 *
 * Copyright 2006- Sami Kerola. All rights reserved.
 * Copyright 2012 Cheer Xiao.
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

/*! \file sort.c
 * \brief Functions to sort output.
 */

#include <config.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "error.h"
#include "progname.h"
#include "quote.h"
#include "xalloc.h"

#include "dhcpd-pools.h"

/*! \brief Compare IP address, with IPv4/v6 determination.
 * \param a Binary IP address.
 * \param b Binary IP address.
 * \return If a < b return -1, if a < b return 1, when they are equal return 0.
 */
int ipcomp_init(const union ipaddr_t *restrict a __attribute__ ((unused)),
		const union ipaddr_t *restrict b __attribute__ ((unused)))
{
	return 0;
}

int ipcomp_v4(const union ipaddr_t *restrict a, const union ipaddr_t *restrict b)
{
	if (a->v4 < b->v4)
		return -1;
	if (a->v4 > b->v4)
		return 1;
	return 0;
}

int ipcomp_v6(const union ipaddr_t *restrict a, const union ipaddr_t *restrict b)
{
	return memcmp(&a->v6, &b->v6, sizeof(a->v6));
}

/*! \brief Compare IP address in leases_t structure, with IPv4/v6 determination.
 * \param a Binary IP address.
 * \param b Binary IP address.
 * \return If a < b return -1, if a < b return 1, when they are equal return 0.
 */
int leasecomp_init(const struct leases_t *restrict a __attribute__ ((unused)),
		   const struct leases_t *restrict b __attribute__ ((unused)))
{
	return 0;
}

int leasecomp_v4(const struct leases_t *restrict a, const struct leases_t *restrict b)
{
	if (a->ip.v4 < b->ip.v4)
		return -1;
	if (a->ip.v4 > b->ip.v4)
		return 1;
	return 0;
}

int leasecomp_v6(const struct leases_t *restrict a, const struct leases_t *restrict b)
{
	return memcmp(&a->ip.v6, &b->ip.v6, sizeof(a->ip.v6));
}

/*! \brief Compare IP address in leases. Suitable for sorting range table.
 * \param r1 A range structure.
 * \param r2 A range structure.
 * \return Return pas through from ipcomp.
 */
int rangecomp(const void *restrict r1, const void *restrict r2)
{
	return ipcomp(&((const struct range_t *)r1)->first_ip,
		      &((const struct range_t *)r2)->first_ip);
}

/*! \brief Compare two doubles.
 * \param f1,f2 Data to compare.
 * \return Like strcmp.
 */
int comp_double(double f1, double f2)
{
	return f1 < f2 ? -1 : f1 > f2 ? 1 : 0;
}

/*! \brief Compare two range_t by their first_ip.
 * \param r1,r2 Pointers to data to compare.
 * \return Like strcmp.
 */
int comp_ip(struct range_t *r1, struct range_t *r2)
{
	return ipcomp(&r1->first_ip, &r2->first_ip);
}

/*! \brief Compare two range_t by their capacity.
 * \param r1,r2 Pointers to data to compare.
 * \return Like strcmp.
 */
int comp_max(struct range_t *r1, struct range_t *r2)
{
	return comp_double(get_range_size(r1), get_range_size(r2));
}

/*! \brief Compare two range_t by their current usage.
 * \param r1,r2 Pointers to data to compare.
 * \return Like strcmp.
 */
int comp_cur(struct range_t *r1, struct range_t *r2)
{
	return comp_double(r1->count, r2->count);
}

/*! \brief Compare two range_t by their current usage percentage.
 * \param r1,r2 Pointers to data to compare.
 * \return Like strcmp.
 */
int comp_percent(struct range_t *r1, struct range_t *r2)
{
	return comp_double(ret_percent(*r1), ret_percent(*r2));
}

/*! \brief Compare two range_t by their touched addresses.
 * \param r1,r2 Pointers to data to compare.
 * \return Like strcmp.
 */
int comp_touched(struct range_t *r1, struct range_t *r2)
{
	return comp_double(r1->touched, r2->touched);
}

/*! \brief Compare two range_t by their touched and in use addresses.
 * \param r1,r2 Pointers to data to compare.
 * \return Like strcmp.
 */
int comp_tc(struct range_t *r1, struct range_t *r2)
{
	return comp_double(ret_tc(*r1), ret_tc(*r2));
}

/*! \brief Compare two range_t by their touched and in use percentage.
 * \param r1,r2 Pointers to data to compare.
 * \return Like strcmp.
 */
int comp_tcperc(struct range_t *r1, struct range_t *r2)
{
	return comp_double(ret_tcperc(*r1), ret_tcperc(*r2));
}

/*! \brief Percentage in use in range.
 * \param r A range structure.
 * \return Usage percentage of the given range.
 */
double ret_percent(struct range_t r)
{
	return r.count / get_range_size(&r);
}

/*! \brief Touched and in use in range
 * \param r A range structure.
 * \return Number of touched or in use addresses in the given range.
 */
double ret_tc(struct range_t r)
{
	return (r.count + r.touched);
}

/*! \brief Return percentage of addresses touched and in use in range.
 * \param r A range structure.
 * \return Percentage of touched or in use addresses in the given range.
 */
double ret_tcperc(struct range_t r)
{
	return ret_tc(r) / get_range_size(&r);
}

/*! \brief Sort field selector.
 * \param c Symbolic name of a sort by character.
 * The sort algorithms are stabile, which means multiple sorts can be
 * specified and they do not mess the result of previous sort.  The sort
 * algorithms are used via function pointer, that gets to be reassigned.
 * \return Return the selected compare function.
 */
comparer_t field_selector(char c)
{
	switch (c) {
	case 'n':
		return NULL;
	case 'i':
		return comp_ip;
	case 'm':
		return comp_max;
	case 'c':
		return comp_cur;
	case 'p':
		return comp_percent;
	case 't':
		return comp_touched;
	case 'T':
		return comp_tc;
	case 'e':
		return comp_tcperc;
	default:
		{
			char str[2] = { c, '\0' };
			error(EXIT_FAILURE, 0, "field_selector: unknown sort order: %s",
			      quote(str));
		}
	}
	return NULL;
}

/*! \brief Perform requested sorting.
 * \param left The left side of the merge sort.
 * \param right The right side of the merge sort.
 * \return Relevant for merge sort decision.
 */
static int merge(struct conf_t *state, struct range_t *restrict left, struct range_t *restrict right)
{
	struct output_sort *p;
	int ret;

	for (p = state->sorts; p; p = p->next) {
		if (p->func == NULL) {
			/* String sorting is special. */
			ret = strcmp(left->shared_net->name, right->shared_net->name);
		} else {
			/* Range sorts are common. */
			ret = p->func(left, right);
		}
		if (0 < ret)
			return (0);
		if (ret < 0)
			return (1);
	}
	/* this is reached if nothing was sorted */
	return (0);
}

/*! \brief Mergesort for range table.
 */
void mergesort_ranges(struct conf_t *state, struct range_t *restrict orig, unsigned int size,
		      struct range_t *restrict temp, const int root_call)
{
	unsigned int left, i, u_right;
	int s_right;
	struct range_t hold;
	/* Merge sort split size */
	static const unsigned int MIN_MERGE_SIZE = 8;

	if (temp == NULL)
		temp = xmalloc(sizeof(struct range_t) * size);

	if (size < MIN_MERGE_SIZE) {
		for (left = 0; left < size; left++) {
			hold = *(orig + left);
			for (s_right = left - 1; 0 <= s_right; s_right--) {
				if (merge(state, (orig + s_right), &hold))
					break;
				*(orig + s_right + 1) = *(orig + s_right);
			}
			*(orig + s_right + 1) = hold;
		}
		if (root_call)
			free(temp);
		return;
	}
	mergesort_ranges(state, orig, size / 2, temp, 0);
	mergesort_ranges(state, orig + size / 2, size - size / 2, temp, 0);
	left = 0;
	u_right = size / 2;
	i = 0;
	while (left < size / 2 && u_right < size) {
		if (merge(state, (orig + left), (orig + u_right))) {
			*(temp + i) = *(orig + left);
			left++;
		} else {
			*(temp + i) = *(orig + u_right);
			u_right++;
		}
		i++;
	}
	while (left < size / 2) {
		*(temp + i) = *(orig + left);
		left++;
		i++;
	}
	while (u_right < size) {
		*(temp + i) = *(orig + u_right);
		u_right++;
		i++;
	}
	memcpy(orig, temp, size * sizeof(struct range_t));

	if (root_call)
		free(temp);
}
