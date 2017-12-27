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

/*! \file other.c
 * \brief Collection of various functions.
 */

#include <config.h>

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "error.h"
#include "progname.h"
#include "quote.h"
#include "xalloc.h"

#include "dhcpd-pools.h"

char *(*cidr_last) (union ipaddr_t *restrict addr, const int mask);
static char *cidr_last_v4(union ipaddr_t *restrict addr, const int mask);
static char *cidr_last_v6(union ipaddr_t *restrict addr, const int mask);

/*! \brief Set function pointers depending on IP version.
 * \param ip IP version.
 */
void set_ipv_functions(struct conf_t *state, int version)
{
	switch (version) {

	case IPv4:
		state->ip_version = version;
		add_lease = add_lease_v4;
		copy_ipaddr = copy_ipaddr_v4;
		find_lease = find_lease_v4;
		get_range_size = get_range_size_v4;
		ipcomp = ipcomp_v4;
		leasecomp = leasecomp_v4;
		ntop_ipaddr = ntop_ipaddr_v4;
		parse_ipaddr = parse_ipaddr_v4;
		cidr_last = cidr_last_v4;
		xstrstr = xstrstr_v4;
		break;

	case IPv6:
		state->ip_version = version;
		add_lease = add_lease_v6;
		copy_ipaddr = copy_ipaddr_v6;
		find_lease = find_lease_v6;
		get_range_size = get_range_size_v6;
		ipcomp = ipcomp_v6;
		leasecomp = leasecomp_v6;
		ntop_ipaddr = ntop_ipaddr_v6;
		parse_ipaddr = parse_ipaddr_v6;
		cidr_last = cidr_last_v6;
		xstrstr = xstrstr_v6;
		break;

	case IPvUNKNOWN:
		state->ip_version = version;
		add_lease = add_lease_init;
		copy_ipaddr = copy_ipaddr_init;
		find_lease = find_lease_init;
		get_range_size = get_range_size_init;
		ipcomp = ipcomp_init;
		leasecomp = leasecomp_init;
		ntop_ipaddr = ntop_ipaddr_init;
		parse_ipaddr = parse_ipaddr_init;
		cidr_last = NULL;
		xstrstr = xstrstr_init;
		break;

	default:
		abort();

	}
	return;
}

/*! \brief Convert text string IP address from either IPv4 or IPv6 to an integer.
 * \param src An IP string in either format.
 * \param dst An union which will hold conversion result.
 * \return Was parsing successful.
 */
int parse_ipaddr_init(struct conf_t *state, const char *restrict src, union ipaddr_t *restrict dst)
{
	struct in_addr addr;
	struct in6_addr addr6;

	if (inet_aton(src, &addr) == 1)
		set_ipv_functions(state, IPv4);
	else if (inet_pton(AF_INET6, src, &addr6) == 1)
		set_ipv_functions(state, IPv6);
	else
		return 0;
	return parse_ipaddr(state, src, dst);
}

int parse_ipaddr_v4(struct conf_t *state
		    __attribute__ ((unused)), const char *restrict src,
		    union ipaddr_t *restrict dst)
{
	int rv;
	struct in_addr addr;

	rv = inet_aton(src, &addr);
	dst->v4 = ntohl(addr.s_addr);
	return rv == 1;
}

int parse_ipaddr_v6(struct conf_t *state
		    __attribute__ ((unused)), const char *restrict src,
		    union ipaddr_t *restrict dst)
{
	int rv;
	struct in6_addr addr;

	rv = inet_pton(AF_INET6, src, &addr);
	memcpy(&dst->v6, addr.s6_addr, sizeof(addr.s6_addr));
	return rv == 1;
}

/*! \brief Convert string to a desimal format network marks.
 * \param src Digit that should be a network mask.
 * \return Network mask, or -1 when failing.
 */
static int strtol_mask(const char *str)
{
	long num;
	char *end = NULL;

	errno = 0;
	if (str == NULL || *str == '\0')
		goto err;
	num = strtol(str, &end, 10);

	if (errno || str == end || (end && *end))
		goto err;
	if (num < 0 || 128 < num)
		goto err;
	return (int)num;
 err:
	return -1;
}

/*! \brief Find last address in IPv4 range by using cidr format.
 * \param addr Pointer to memory where address needs to be stored.
 * \return Allocated string format of the address.
 */
static char *cidr_last_v4(union ipaddr_t *restrict addr, const int mask)
{
	union ipaddr_t last_ip;
	uint32_t netmask;
	const char *ip;

	if (mask)
		netmask = (1U << (32 - mask)) - 1;
	else
		netmask = 0;
	last_ip.v4 = addr->v4 | netmask;

	ip = ntop_ipaddr(&last_ip);
	return xstrdup(ip);
}

/*! \brief Find last address in IPv6 range by using cidr format.
 * \param addr Pointer to memory where address needs to be stored.
 * \return Allocated string format of the address.
 */
static char *cidr_last_v6(union ipaddr_t *restrict addr, const int mask)
{
	union ipaddr_t bitmask;
	int i, j;
	char ip[128];

	memset(&bitmask, 0x0, sizeof(bitmask));
	for (i = mask, j = 0; i > 0; i -= 8, j++) {
		if (i >= 8)
			bitmask.v6[j] = 0xff;
		else
			bitmask.v6[j] = (unsigned char)(0xffU << (8 - i));
	}
	for (i = 0; i < (int)sizeof(bitmask); i++)
		addr->v6[i] |= ~bitmask.v6[i];
	inet_ntop(AF_INET6, addr, ip, sizeof(ip));
	return xstrdup(ip);
}

/*! \brief Convert a cidr notated address to a range.
 * \param range_p Pointer to memory where addresses need to be stored.
 * \param word A range as a cidr string.
 */
void parse_cidr(struct conf_t *state, struct range_t *range_p, const char *word)
{
	char *divider;
	int mask;
	union ipaddr_t addr;
	char *last;

	/* determine cidr */
	divider = strchr(word, '/');
	*divider++ = '\0';
	mask = strtol_mask(divider);
	if (mask < 0)
		error(EXIT_FAILURE, 0, "cidr %s invalid mask %s", word, divider);
	if (state->ip_version == IPvUNKNOWN) {
		if (!strchr(word, ':'))
			set_ipv_functions(state, IPv4);
		else
			set_ipv_functions(state, IPv6);
	}

	/* start of the range is easy */
	parse_ipaddr(state, word, &addr);
	copy_ipaddr(&range_p->first_ip, &addr);

	/* end of the range depends cidr size */
	last = cidr_last(&addr, mask);
	parse_ipaddr(state, last, &addr);
	copy_ipaddr(&range_p->last_ip, &addr);
	free(last);
}

/*! \brief Copy IP address to union.
 *
 * \param dst Destination for a binary IP address.
 * \param src Sourse of an IP address. */
void copy_ipaddr_init(union ipaddr_t *restrict dst __attribute__ ((unused)),
		      const union ipaddr_t *restrict src __attribute__ ((unused)))
{
}

void copy_ipaddr_v4(union ipaddr_t *restrict dst, const union ipaddr_t *restrict src)
{
	dst->v4 = src->v4;
}

void copy_ipaddr_v6(union ipaddr_t *restrict dst, const union ipaddr_t *restrict src)
{
	memcpy(&dst->v6, &src->v6, sizeof(src->v6));
}

/*! \brief Convert an address to string. This function will convert the
 * IPv4 addresses to 123.45.65.78 format, and the IPv6 addresses to it's
 * native format depending on which version of the addressing is found to
 * be in use.
 *
 * \param ip Binary IP address.
 * \return Printable address.
 */
const char *ntop_ipaddr_init(const union ipaddr_t *ip __attribute__ ((unused)))
{
	static char buffer = '\0';

	return &buffer;
}

const char *ntop_ipaddr_v4(const union ipaddr_t *ip)
{
	static char buffer[sizeof("255.255.255.255")];
	struct in_addr addr;

	addr.s_addr = htonl(ip->v4);
	return inet_ntop(AF_INET, &addr, buffer, sizeof(buffer));
}

const char *ntop_ipaddr_v6(const union ipaddr_t *ip)
{
	static char buffer[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")];
	struct in6_addr addr;

	memcpy(addr.s6_addr, ip->v6, sizeof(addr.s6_addr));
	return inet_ntop(AF_INET6, &addr, buffer, sizeof(buffer));
}

/*! \brief Calculate how many addresses there are in a range.
 *
 * \param r Pointer to range structure, which has information about first
 * and last IP in the range.
 * \return Size of a range.
 */
double get_range_size_init(const struct range_t *r __attribute__ ((unused)))
{
	return 0;
}

double get_range_size_v4(const struct range_t *r)
{
	return r->last_ip.v4 - r->first_ip.v4 + 1;
}

double get_range_size_v6(const struct range_t *r)
{
	double size = 0;
	int i;

	/* When calculating the size of an IPv6 range overflow may occur.
	 * In that case only the last LONG_BIT bits are preserved, thus
	 * we just skip the first (16 - LONG_BIT) bits...  */
	for (i = 0; i < 16; i++) {
		size *= 256;
		size += (int)r->last_ip.v6[i] - (int)r->first_ip.v6[i];
	}
	return size + 1;
}

/*! \fn xstrstr_init(const char *restrict str)
 * \brief Determine if the dhcpd is in IPv4 or IPv6 mode. This function
 * may be needed when dhcpd.conf file has zero IP version hints.
 *
 * \param str A line from dhcpd.conf
 * \return prefix_t enum value
 */
int xstrstr_init(struct conf_t *state, const char *restrict str)
{
	if (!memcmp("lease ", str, 6)) {
		set_ipv_functions(state, IPv4);
		return PREFIX_LEASE;
	}
	if (!memcmp("  iaaddr ", str, 9)) {
		set_ipv_functions(state, IPv6);
		return PREFIX_LEASE;
	}
	return NUM_OF_PREFIX;
}

/*! \fn xstrstr_v4(const char *restrict str)
 * \brief parse lease file in IPv4 mode
 *
 * \param str A line from dhcpd.conf
 * \return prefix_t enum value
 */
int
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
    __attribute__ ((hot))
#endif
    xstrstr_v4(struct conf_t *state __attribute__ ((unused)), const char *restrict str)
{
	size_t len;

	if (str[2] == 'b' || str[2] == 'h')
		len = strlen(str);
	else
		len = 0;
	if (15 < len) {
		switch (str[16]) {
		case 'f':
			if (!memcmp("  binding state free;", str, 21))
				return PREFIX_BINDING_STATE_FREE;
			break;
		case 'a':
			if (!memcmp("  binding state active;", str, 23))
				return PREFIX_BINDING_STATE_ACTIVE;
			if (!memcmp("  binding state abandoned;", str, 25))
				return PREFIX_BINDING_STATE_ABANDONED;
			break;
		case 'e':
			if (!memcmp("  binding state expired;", str, 24))
				return PREFIX_BINDING_STATE_EXPIRED;
			break;
		case 'r':
			if (!memcmp("  binding state released;", str, 25))
				return PREFIX_BINDING_STATE_RELEASED;
			break;
		case 'b':
			if (!memcmp("  binding state backup;", str, 23))
				return PREFIX_BINDING_STATE_BACKUP;
			break;
		case 'n':
			if (!memcmp("  hardware ethernet", str, 19))
				return PREFIX_HARDWARE_ETHERNET;
			break;
		}
	}
	if (!memcmp("lease ", str, 6))
		return PREFIX_LEASE;
	return NUM_OF_PREFIX;
}

/*! \fn xstrstr_v4(const char *restrict str)
 * \brief parse lease file in IPv6 mode
 *
 * \param str A line from dhcpd.conf
 * \return prefix_t enum value
 */
int
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
    __attribute__ ((hot))
#endif
    xstrstr_v6(struct conf_t *state __attribute__ ((unused)), const char *restrict str)
{
	size_t len;

	if (str[4] == 'b' || str[2] == 'h')
		len = strlen(str);
	else
		len = 0;
	if (17 < len) {
		switch (str[18]) {
		case 'f':
			if (!memcmp("    binding state free;", str, 23))
				return PREFIX_BINDING_STATE_FREE;
			break;
		case 'a':
			if (!memcmp("    binding state active;", str, 25))
				return PREFIX_BINDING_STATE_ACTIVE;
			if (!memcmp("    binding state abandoned;", str, 27))
				return PREFIX_BINDING_STATE_ABANDONED;
			break;
		case 'e':
			if (!memcmp("    binding state expired;", str, 26))
				return PREFIX_BINDING_STATE_EXPIRED;
			break;
		case 'r':
			if (!memcmp("    binding state released;", str, 27))
				return PREFIX_BINDING_STATE_RELEASED;
			break;
		case 'b':
			if (!memcmp("    binding state backup;", str, 25))
				return PREFIX_BINDING_STATE_BACKUP;
			break;
		case 'n':
			if (!memcmp("  hardware ethernet", str, 19))
				return PREFIX_HARDWARE_ETHERNET;
			break;
		}
	}
	if (!memcmp("  iaaddr ", str, 9))
		return PREFIX_LEASE;
	return NUM_OF_PREFIX;
}

/*! \brief Parse option argument color mode.
 *
 * \param Color mode string.
 * \return color mode enum.
 */
int parse_color_mode(const char *restrict optarg)
{
	if (!strcmp(optarg, "always"))
		return color_on;
	if (!strcmp(optarg, "auto"))
		return color_auto;
	if (!strcmp(optarg, "never"))
		return color_off;
	return color_unknown;
}

/*! \brief Return a double floating point value.
 *
 * \param str String to be converted to a double.
 * \param errmesg Exit error message if conversion fails.
 * \return Binary result of string to double conversion.
 */
double strtod_or_err(const char *restrict str, const char *restrict errmesg)
{
	double num;
	char *end = NULL;

	if (str == NULL || *str == '\0')
		goto err;
	errno = 0;
	num = strtod(str, &end);
	if (errno || str == end || (end && *end))
		goto err;
	return num;
 err:
	error(EXIT_FAILURE, errno, "%s: %s", errmesg, quote(str));
	return 0;
}

/*! \brief Reverse range.
 * Used before output, if a caller has requested reverse sorting. */
void flip_ranges(struct conf_t *state)
{
	unsigned int i = state->num_ranges - 1, j;
	struct range_t *tmp_ranges;

	tmp_ranges = xmalloc(sizeof(struct range_t) * state->num_ranges);
	for (j = 0; j < state->num_ranges; j++, i--)
		*(tmp_ranges + j) = *(state->ranges + i);
	memcpy(state->ranges, tmp_ranges, state->num_ranges * sizeof(struct range_t));
	free(tmp_ranges);
}

/*! \brief Free memory, flush buffers etc. */
void clean_up(struct conf_t *state)
{
	struct output_sort *cur, *next;
	struct shared_network_t *c, *n;

	/* Just in case there something in buffers */
	if (fflush(NULL))
		error(EXIT_FAILURE, errno, "clean_up: fflush");
	free(state->ranges);
	delete_all_leases(state);
	for (cur = state->sorts; cur; cur = next) {
		next = cur->next;
		free(cur);
	}
	for (c = state->shared_net_root; c; c = n) {
		n = c->next;
		free(c->name);
		free(c);
	}
}

/*! \brief Print a time stamp of a path or now to output file. */
void dp_time_tool(FILE *file, const char *path, int epoch)
{
	time_t t;

	/* a file or now */
	if (path) {
		struct stat st;

		stat(path, &st);
		t = st.st_mtime;
	} else
		t = time(NULL);
	/* epoc or iso time stamp */
	if (epoch)
		fprintf(file, "%ld", t);
	else {
		char time_stamp[64];
		struct tm tm;
		int len;

		localtime_r(&t, &tm);
		len = snprintf(time_stamp, sizeof(time_stamp), "%4d-%.2d-%.2dT%02d:%02d:%02d",
			       tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			       tm.tm_hour, tm.tm_min, tm.tm_sec);
		strftime(time_stamp + len, sizeof(time_stamp) - len, "%z", &tm);
		fprintf(file, "%s", time_stamp);
	}
}

/*! \brief A version printing. */
void __attribute__ ((__noreturn__)) print_version(void)
{
#define stringify(s) #s
#define stringify_value(s) stringify(s)
	fprintf(stdout, "%s\n"
		"Original design and maintainer Sami Kerola.\n"
		"uthash %s by Troy D. Hanson.\n"
		"XML support by Dominic Germain, Sogetel inc.\n"
		"IPv6 support by Cheer Xiao.\n"
		"Mustach templating support by Jose Bollo.\n"
		"  The dhcpd-pools is FreeBSD Licensed,\n"
		"  uthash uses BSD license,\n"
		"  gnulib parts are mostly GPL,\n"
		"  and mustache uses Apache License.\n", PACKAGE_STRING,
		stringify_value(UTHASH_VERSION));
	exit(EXIT_SUCCESS);
}

/*! \brief Command line help screen. */
void __attribute__ ((__noreturn__)) usage(int status)
{
	FILE *out = status == EXIT_SUCCESS ? stdout : stderr;

	fprintf(out,	"Usage: %s [OPTIONS]\n", program_name);
	fputs(		"\n", out);
	fputs(		"This is ISC dhcpd pools usage analyzer.\n", out);
	fputs(		"\n", out);
	fputs(		"  -c, --config=FILE      path to the dhcpd.conf file\n", out);
	fputs(		"  -l, --leases=FILE      path to the dhcpd.leases file\n", out);
	fputs(		"  -f, --format=[thHcxXjJ] output format\n", out);
	fputs(		"                           t for text\n", out);
	fputs(		"                           H for full html page\n", out);
	fputs(		"                           x for xml\n", out);
	fputs(		"                           X for xml with active lease details\n", out);
	fputs(		"                           j for json\n", out);
	fputs(		"                           J for json with active lease details\n", out);
	fputs(		"                           c for comma separated values\n", out);
#ifdef BUILD_MUSTACH
	fputs(		"      --mustach=FILE     output using mustach template file\n", out);
#endif
	fputs(		"  -s, --sort=[nimcptTe]  sort ranges by\n", out);
	fputs(		"                           n name\n", out);
	fputs(		"                           i IP\n", out);
	fputs(		"                           m maximum\n", out);
	fputs(		"                           c current\n", out);
	fputs(		"                           p percent\n", out);
	fputs(		"                           t touched\n", out);
	fputs(		"                           T t+c\n", out);
	fputs(		"                           e t+c perc\n", out);
	fputs(		"  -r, --reverse          reverse order sort\n", out);
	fputs(		"  -o, --output=FILE      output into a file\n", out);
	fputs(		"  -L, --limit=NR         output limit mask 77 - 00\n", out);
	fputs(		"      --color=WHEN       use colors 'always', 'never', or 'auto'\n", out);
	fputs(		"      --warning=PERC     set warning alarming threshold\n", out);
	fputs(		"      --critical=PERC    set critical alarming threshold\n", out);
	fputs(		"      --skip=WHAT        do not print threshold 'ok', 'warning', 'critical',\n", out);
	fputs(		"                           'minsize', or 'suppressed'\n", out);
	fputs(		"      --warn-count=NR    a number of free leases before warning raised\n", out);
	fputs(		"      --crit-count=NR    a number of free leases before critical raised\n", out);
	fputs(		"      --minsize=size     disable alarms for small ranges and shared-nets\n", out);
	fputs(		"      --snet-alarms      suppress range alarms that are part of a shared-net\n", out);
	fputs(		"  -p, --perfdata         print additional perfdata in alarming mode\n", out);
	fputs(		"  -A, --all-as-shared    treat single subnets as shared-network with CIDR as their name\n", out);
	fputs(          "      --ip-version=4|6   force analysis to use either IPv4 or IPv6 functions\n", out);
	fputs(		"  -v, --version          output version information and exit\n", out);
	fputs(		"  -h, --help             display this help and exit\n", out);
	fputs(		"\n", out);
	fprintf(out,	"Report bugs to <%s>\n", PACKAGE_BUGREPORT);
	fprintf(out,	"Homepage: %s\n", PACKAGE_URL);

	exit(status);
}
