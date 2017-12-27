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

/*! \file dhcpd-pools.h
 * \brief Global definitions of structures, enums, and function prototypes.
 */

#ifndef DHCPD_POOLS_H
# define DHCPD_POOLS_H 1

# include <config.h>
# include <arpa/inet.h>
# include <stddef.h>
# include <stdio.h>
# include <string.h>
# include <uthash.h>

/*! \def likely(x)
 * \brief Symbolic call to __builtin_expect'ed branch.
 */
/*! \def unlikely(x)
 * \brief Symbolic call to not-__builtin_expect'ed branch.
 */
# ifdef HAVE_BUILTIN_EXPECT
#  define likely(x)	__builtin_expect(!!(x), 1)
#  define unlikely(x)	__builtin_expect(!!(x), 0)
# else
#  define likely(x)	(x)
#  define unlikely(x)	(x)
# endif

/*! \def _DP_ATTRIBUTE_HOT
 * \brief The function attribute __hot__ was added in gcc 4.3.  See gnu
 * documentation for further information.
 * https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-hot-function-attribute
 */
# if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
#  define _DP_ATTRIBUTE_HOT __attribute__ ((__hot__))
# else
#  define _DP_ATTRIBUTE_HOT	/* empty */
# endif

/*! \union ipaddr_t
 * \brief Memory space for a binary IP address saving. */
union ipaddr_t {
	uint32_t v4;
	unsigned char v6[16];
};

/*! \enum dhcp_version
 * \brief The IP version, IPv4 or IPv6, served by the dhcpd.
 */
enum dhcp_version {
	IPvUNKNOWN,
	IPv4,
	IPv6
};

/*! \enum prefix_t
 * \brief Enumeration of interesting data in dhcpd.leases file, that has to
 * be further examined, and saved.  Functions xstrstr_v4() and xstrstr_v6()
 * return one of these values to parse_leases().
 */
enum prefix_t {
	PREFIX_LEASE,
	PREFIX_BINDING_STATE_FREE,
	PREFIX_BINDING_STATE_ABANDONED,
	PREFIX_BINDING_STATE_EXPIRED,
	PREFIX_BINDING_STATE_RELEASED,
	PREFIX_BINDING_STATE_ACTIVE,
	PREFIX_BINDING_STATE_BACKUP,
	PREFIX_HARDWARE_ETHERNET,
	NUM_OF_PREFIX
};

/*! \enum color_mode
 * \brief Enumeration whether to use or not color output.
 */
enum color_mode {
	color_unknown,
	color_off,
	color_on,
	color_auto		/*!< Default, use colors when output terminal is interactive. */
};

/*! \struct shared_network_t
 * \brief Counters for an individual shared network.  This data entry is
 * also used for 'all networks' counting.
 */
struct shared_network_t {
	char *name;
	double available;
	double used;
	double touched;
	double backups;
	int netmask;
	struct shared_network_t *next;
};

/*! \struct range_t
 * \brief Counters for an individual range.
 */
struct range_t {
	struct shared_network_t *shared_net;
	union ipaddr_t first_ip;
	union ipaddr_t last_ip;
	double count;
	double touched;
	double backups;
};

/*! \struct output_helper_t
 * \brief Various per range and shared net temporary calculation results.
 */
struct output_helper_t {
	int status;
	double range_size;
	double percent;
	double tc;
	double tcp;
	double bup;
};

/*! \enum ltype
 * \brief Lease state types.  These are the possible values in struct leases_t.
 */
enum ltype {
	ACTIVE,
	FREE,
	BACKUP
};

/*! \struct leases_t
 * \brief An individual lease. These leaases are hashed.
 */
struct leases_t {
	union ipaddr_t ip;	/* ip as key */
	enum ltype type;
	char *ethernet;
	UT_hash_handle hh;
};

/*! \enum limbits
 * \brief Output limit bits.
 */
enum limbits {
	R_BIT = (1 << 0),	/*!< Range limit. */
	S_BIT = (1 << 1),	/*!< Shared networks limit. */
	A_BIT = (1 << 2)	/*!< All networks summary limit. */
};

/*! \def STATE_OK
 * \brief Nagios alarm exit value.
 */
# define STATE_OK 0
# define STATE_WARNING 1
# define STATE_CRITICAL 2

/*! \var comparer_t
 * \brief Function pointer holding sort algorithm.
 */
typedef int (*comparer_t) (struct range_t *r1, struct range_t *r2);

/*! \struct output_sort
 * \brief Linked list of sort functions.
 */
struct output_sort {
	comparer_t func;
	struct output_sort *next;
};

/*! \struct conf_t
 * \brief Runtime configuration state.
 */
struct conf_t {
	struct shared_network_t *shared_net_root;	/*!< First entry in shared network linked list, that is the 'all networks', */
	struct shared_network_t *shared_net_head;	/*!< Last entry in shared network linked list.  */
	struct range_t *ranges;				/*!< Array of ranges. */
	unsigned int num_ranges;			/*!< Number of ranges in the ranges array. */
	size_t ranges_size;				/*!< Size of the ranges array. */
	struct leases_t *leases;			/*!< An array of individual leases from dhcpd.leases file. */
	enum dhcp_version ip_version;			/*!< Designator if the dhcpd is running in IPv4 or IPv6 mode. */
	const char *dhcpdconf_file;			/*!< Path to dhcpd.conf file. */
	const char *dhcpdlease_file;			/*!< Path to dhcpd.leases file. */
	int output_format;				/*!< Column to use in color_tags array. */
	struct output_sort *sorts;			/*!< Linked list how to sort ranges. */
	const char *output_file;			/*!< Output file path. */
	const char *mustach_template;			/*!< Mustach template file path. */
	double warning;					/*!< Warning percent threshold. */
	double critical;				/*!< Critical percent threshold. */
	double warn_count;				/*!< Maximum number of free IP's before warning. */
	double crit_count;				/*!< Maximum number of free IP's before critical. */
	double minsize;					/*!< Minimum size of range or shared network to be considered exceeding threshold. */
	unsigned int
		reverse_order:1,			/*!< Reverse sort order. */
		backups_found:1,			/*!< Indicator if dhcpd.leases file has leases in backup state. */
		snet_alarms:1,				/*!< Suppress alarming thresholds for ranges that are part of a shared network. */
		perfdata:1,				/*!< Include performance statistics when using Nagios alarm output format. */
		all_as_shared:1,			/*!< Treat stand-alone subnets as a shared network. */
		header_limit:4,				/*!< Bits to suppress header output. */
		number_limit:3,				/*!< Bits to suppress value output. */
		skip_ok:1,				/*!< Skip none-alarming values from output. */
		skip_warning:1,				/*!< Skip warning values from output. */
		skip_critical:1,			/*!< Skip critical values from output. */
		skip_minsize:1,				/*!< Skip alarming values that are below minsize from output. */
		skip_suppressed:1,			/*!< Skip alarming values that are suppressed with --snet-alarms option, or they are shared networks without IP availability. */
		color_mode:2;				/*!< Indicator if colors should be used in output. */
};

/* Function prototypes */

/* analyze.c */
extern void prepare_data(struct conf_t *state);
extern void do_counting(struct conf_t *state);

/* getdata.c */
extern int parse_leases(struct conf_t *state, const int print_mac_addreses);
extern void parse_config(struct conf_t *state, const int is_include,
			 const char *restrict config_file,
			 struct shared_network_t *restrict shared_p);

/* hash.c */
extern void (*add_lease) (struct conf_t *state, union ipaddr_t *addr, enum ltype type);
extern void add_lease_init(struct conf_t *state, union ipaddr_t *addr, enum ltype type);
extern void add_lease_v4(struct conf_t *state, union ipaddr_t *addr, enum ltype type);
extern void add_lease_v6(struct conf_t *state, union ipaddr_t *addr, enum ltype type);

extern struct leases_t *(*find_lease) (struct conf_t *state, union ipaddr_t *addr);
extern struct leases_t *find_lease_init(struct conf_t *state, union ipaddr_t *addr);
extern struct leases_t *find_lease_v4(struct conf_t *state, union ipaddr_t *addr);
extern struct leases_t *find_lease_v6(struct conf_t *state, union ipaddr_t *addr);

extern void delete_lease(struct conf_t *state, struct leases_t *lease);
extern void delete_all_leases(struct conf_t *state);

/* mustach-dhcpd-pools.c */
extern int mustach_dhcpd_pools(struct conf_t *state);

/* other.c */
extern void set_ipv_functions(struct conf_t *state, int version);
extern void flip_ranges(struct conf_t *state);
extern void clean_up(struct conf_t *state);
extern void parse_cidr(struct conf_t *state, struct range_t *range_p, const char *word);
extern int parse_color_mode(const char *restrict optarg);
extern double strtod_or_err(const char *restrict str, const char *restrict errmesg);
extern void __attribute__ ((noreturn)) print_version(void);
extern void __attribute__ ((noreturn)) usage(int status);
extern void dp_time_tool(FILE *file, const char *path, int epoch);

extern int (*parse_ipaddr) (struct conf_t *state, const char *restrict src,
			    union ipaddr_t *restrict dst);
extern int parse_ipaddr_init(struct conf_t *state, const char *restrict src,
			     union ipaddr_t *restrict dst);
extern int parse_ipaddr_v4(struct conf_t *state, const char *restrict src,
			   union ipaddr_t *restrict dst);
extern int parse_ipaddr_v6(struct conf_t *state, const char *restrict src,
			   union ipaddr_t *restrict dst);

extern int (*xstrstr) (struct conf_t *state, const char *restrict str);
extern int xstrstr_init(struct conf_t *state, const char *restrict str);
extern int xstrstr_v4(struct conf_t *state, const char *restrict str);
extern int xstrstr_v6(struct conf_t *state, const char *restrict str);

extern void (*copy_ipaddr) (union ipaddr_t *restrict dst, const union ipaddr_t *restrict src);
extern void copy_ipaddr_init(union ipaddr_t *restrict dst, const union ipaddr_t *restrict src);
extern void copy_ipaddr_v4(union ipaddr_t *restrict dst, const union ipaddr_t *restrict src);
extern void copy_ipaddr_v6(union ipaddr_t *restrict dst, const union ipaddr_t *restrict src);

extern const char *(*ntop_ipaddr) (const union ipaddr_t *ip);
extern const char *ntop_ipaddr_init(const union ipaddr_t *ip);
extern const char *ntop_ipaddr_v4(const union ipaddr_t *ip);
extern const char *ntop_ipaddr_v6(const union ipaddr_t *ip);

extern double (*get_range_size) (const struct range_t *r);
extern double get_range_size_init(const struct range_t *r);
extern double get_range_size_v4(const struct range_t *r);
extern double get_range_size_v6(const struct range_t *r);

/* output.c */
extern int range_output_helper(struct conf_t *state, struct output_helper_t *oh,
			       struct range_t *range_p);
extern int shnet_output_helper(struct conf_t *state, struct output_helper_t *oh,
			       struct shared_network_t *shared_p);
extern int output_analysis(struct conf_t *state, const char output_format);

/* sort.c */
extern void mergesort_ranges(struct conf_t *state,
			     struct range_t *restrict orig, unsigned int size,
			     struct range_t *restrict temp, const int root_call);

extern int (*leasecomp) (const struct leases_t *restrict a, const struct leases_t *restrict b);
extern int leasecomp_init(const struct leases_t *restrict a
			  __attribute__ ((unused)),
			  const struct leases_t *restrict b __attribute__ ((unused)));
extern int leasecomp_v4(const struct leases_t *restrict a, const struct leases_t *restrict b);
extern int leasecomp_v6(const struct leases_t *restrict a, const struct leases_t *restrict b);

extern int (*ipcomp) (const union ipaddr_t *restrict a, const union ipaddr_t *restrict b);
extern int ipcomp_init(const union ipaddr_t *restrict a, const union ipaddr_t *restrict b);
extern int ipcomp_v4(const union ipaddr_t *restrict a, const union ipaddr_t *restrict b);
extern int ipcomp_v6(const union ipaddr_t *restrict a, const union ipaddr_t *restrict b);

extern int rangecomp(const void *restrict r1, const void *restrict r2)
    __attribute__ ((nonnull(1, 2)));

extern int comp_cur(struct range_t *r1, struct range_t *r2);
extern int comp_double(double f1, double f2);
extern int comp_ip(struct range_t *r1, struct range_t *r2);
extern int comp_max(struct range_t *r1, struct range_t *r2);
extern int comp_percent(struct range_t *r1, struct range_t *r2);
extern int comp_tc(struct range_t *r1, struct range_t *r2);
extern int comp_tcperc(struct range_t *r1, struct range_t *r2);
extern int comp_touched(struct range_t *r1, struct range_t *r2);

extern comparer_t field_selector(char c);
extern double ret_percent(struct range_t r);
extern double ret_tc(struct range_t r);
extern double ret_tcperc(struct range_t r);

#endif /* DHCPD_POOLS_H */
