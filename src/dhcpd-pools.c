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

/*! \file dhcpd-pools.c
 * \brief The main(), and core initialization.
 */

#include <config.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdio.h>
#include <limits.h>

#include "close-stream.h"
#include "closeout.h"
#include "error.h"
#include "progname.h"
#include "quote.h"
#include "xalloc.h"

#include "dhcpd-pools.h"

/* Function pointers */
int (*parse_ipaddr) (struct conf_t *state, const char *restrict src, union ipaddr_t *restrict dst);
void (*copy_ipaddr) (union ipaddr_t *restrict dst, const union ipaddr_t *restrict src);
const char *(*ntop_ipaddr) (const union ipaddr_t *ip);
double (*get_range_size) (const struct range_t *r);
int (*xstrstr) (struct conf_t *state, const char *restrict str);
int (*ipcomp) (const union ipaddr_t *restrict a, const union ipaddr_t *restrict b);
int (*leasecomp) (const struct leases_t *restrict a, const struct leases_t *restrict b);
void (*add_lease) (struct conf_t *state, union ipaddr_t *ip, enum ltype type);
struct leases_t *(*find_lease) (struct conf_t *state, union ipaddr_t *ip);

/*! \brief An option argument parser to populate state header_limit and
 * number_limit values.
 */
static int return_limit(const char c)
{
	if ('0' <= c && c < '8')
		return c - '0';
	error(EXIT_FAILURE, 0, "return_limit: output mask %s is illegal", quote(optarg));
	return 0;
}

/*! \brief Run time initialization. Global allocations, counter
 * initializations, etc are here. */
static void prepare_memory(struct conf_t *state)
{
	state->ranges = xmalloc(sizeof(struct range_t) * state->ranges_size);
	/* First shared network entry is all networks */
	state->shared_net_root = xcalloc(sizeof(struct shared_network_t), 1);
	state->shared_net_root->name = xstrdup("All networks");
	state->shared_net_head = state->shared_net_root;
}

/*! \brief The --skip option argument parser. */
static void skip_arg_parse(struct conf_t *state, char *optarg)
{
	enum {
		OPT_ARG_OK = 0,
		OPT_ARG_WARNING,
		OPT_ARG_CRITICAL,
		OPT_ARG_MINSIZE,
		OPT_ARG_SUPRESSED
	};

	char *const tokens[] = {
		[OPT_ARG_OK] = "ok",
		[OPT_ARG_WARNING] = "warning",
		[OPT_ARG_CRITICAL] = "critical",
		[OPT_ARG_MINSIZE] = "minsize",
		[OPT_ARG_SUPRESSED] = "suppressed",
		NULL
	};
	char *value;

	while (*optarg != '\0') {
		switch (getsubopt(&optarg, tokens, &value)) {
		case OPT_ARG_OK:
			state->skip_ok = 1;
			break;
		case OPT_ARG_WARNING:
			state->skip_warning = 1;
			break;
		case OPT_ARG_CRITICAL:
			state->skip_critical = 1;
			break;
		case OPT_ARG_MINSIZE:
			state->skip_minsize = 1;
			break;
		case OPT_ARG_SUPRESSED:
			state->skip_suppressed = 1;
			break;
		default:
			error(EXIT_FAILURE, 0, "unknown --skip specifier: %s", value);
		}
	}
}

/*! \brief Command line options parser. */
static char parse_command_line_opts(struct conf_t *state, int argc, char **argv)
{
	enum {
		OPT_SNET_ALARMS = CHAR_MAX + 1,
		OPT_WARN,
		OPT_CRIT,
		OPT_MINSIZE,
		OPT_WARN_COUNT,
		OPT_CRIT_COUNT,
		OPT_COLOR,
		OPT_SKIP,
		OPT_SET_IPV,
		OPT_MUSTACH
	};

	static struct option const long_options[] = {
		{"config", required_argument, NULL, 'c'},
		{"leases", required_argument, NULL, 'l'},
		{"color", required_argument, NULL, OPT_COLOR},
		{"skip", required_argument, NULL, OPT_SKIP},
		{"format", required_argument, NULL, 'f'},
		{"sort", required_argument, NULL, 's'},
		{"reverse", no_argument, NULL, 'r'},
		{"output", required_argument, NULL, 'o'},
		{"limit", required_argument, NULL, 'L'},
		{"mustach", required_argument, NULL, OPT_MUSTACH},
		{"version", no_argument, NULL, 'v'},
		{"help", no_argument, NULL, 'h'},
		{"snet-alarms", no_argument, NULL, OPT_SNET_ALARMS},
		{"warning", required_argument, NULL, OPT_WARN},
		{"critical", required_argument, NULL, OPT_CRIT},
		{"warn-count", required_argument, NULL, OPT_WARN_COUNT},
		{"crit-count", required_argument, NULL, OPT_CRIT_COUNT},
		{"minsize", required_argument, NULL, OPT_MINSIZE},
		{"perfdata", no_argument, NULL, 'p'},
		{"all-as-shared", no_argument, NULL, 'A'},
		{"ip-version", required_argument, NULL, OPT_SET_IPV},
		{NULL, 0, NULL, 0}
	};
	char output_format = '\0';
	int alarming = 0;

	while (1) {
		int c;

		c = getopt_long(argc, argv, "c:l:f:o:s:rL:pAvh", long_options, NULL);
		if (c == EOF)
			break;
		switch (c) {
		case 'c':
			/* config file */
			state->dhcpdconf_file = optarg;
			break;
		case 'l':
			/* lease file */
			state->dhcpdlease_file = optarg;
			break;
		case 'f':
			/* Output format */
			output_format = optarg[0];
			break;
		case 's':
			{
				/* Output sorting option */
				struct output_sort *p = state->sorts;
				size_t len;

				while (p && p->next)
					p = p->next;
				for (len = 0; len < strlen(optarg); len++) {
					if (state->sorts == NULL) {
						state->sorts =
						    xcalloc(1, sizeof(struct output_sort));
						p = state->sorts;
					} else {
						p->next = xcalloc(1, sizeof(struct output_sort));
						p = p->next;
					}
					p->func = field_selector(optarg[len]);
				}
			}
			break;
		case 'r':
			/* What ever sort in reverse order */
			state->reverse_order = 1;
			break;
		case 'o':
			/* Output file */
			state->output_file = optarg;
			break;
		case 'L':
			/* Specification what will be printed */
			state->header_limit = return_limit(optarg[0]);
			state->number_limit = return_limit(optarg[1]);
			break;
		case OPT_MUSTACH:
#ifdef BUILD_MUSTACH
			state->mustach_template = optarg;
			output_format = 'm';
#else
			error(EXIT_FAILURE, 0, "compiled without mustach support");
#endif
			break;
		case OPT_COLOR:
			state->color_mode = parse_color_mode(optarg);
			if (state->color_mode == color_unknown)
				error(EXIT_FAILURE, errno, "unknown color mode: %s", quote(optarg));
			break;
		case OPT_SKIP:
			skip_arg_parse(state, optarg);
			break;
		case OPT_SNET_ALARMS:
			state->snet_alarms = 1;
			break;
		case OPT_WARN:
			alarming = 1;
			state->warning = strtod_or_err(optarg, "illegal argument");
			break;
		case OPT_CRIT:
			alarming = 1;
			state->critical = strtod_or_err(optarg, "illegal argument");
			break;
		case OPT_WARN_COUNT:
			alarming = 1;
			state->warn_count = strtod_or_err(optarg, "illegal argument");
			break;
		case OPT_CRIT_COUNT:
			alarming = 1;
			state->crit_count = strtod_or_err(optarg, "illegal argument");
			break;
		case OPT_MINSIZE:
			state->minsize = strtod_or_err(optarg, "illegal argument");
			break;
		case OPT_SET_IPV:
			switch (optarg[0]) {
			case '4':
				set_ipv_functions(state, IPv4);
				break;
			case '6':
				set_ipv_functions(state, IPv6);
				break;
			default:
				error(EXIT_FAILURE, 0, "unknown --ip-version argument: %s", optarg);
			}
			break;
		case 'p':
			/* Print additional performance data in alarming mode */
			state->perfdata = 1;
			break;
		case 'A':
			/* Treat single networks as shared with network CIDR as name */
			state->all_as_shared = 1;
			break;
		case 'v':
			/* Print version */
			print_version();
		case 'h':
			/* Print help */
			usage(EXIT_SUCCESS);
		default:
			error(EXIT_FAILURE, 0, "Try %s --help for more information.", program_name);
		}
	}

	/* Use default dhcpd.conf when user did not define anything. */
	if (state->dhcpdconf_file == NULL)
		state->dhcpdconf_file = DHCPDCONF_FILE;
	/* Use default dhcpd.leases when user did not define anything. */
	if (state->dhcpdlease_file == NULL)
		state->dhcpdlease_file = DHCPDLEASE_FILE;
	/* Use default limits when user did not define anything. */
	if (state->header_limit == 8) {
		char const *default_limit = OUTPUT_LIMIT;

		state->header_limit = return_limit(default_limit[0]);
		state->number_limit = return_limit(default_limit[1]);
	}
	/* Output format is not defined, if alarm thresholds are then it's alarming, else use the
	 * default.  */
	if (output_format == '\0') {
		if (alarming == 1)
			output_format = 'a';
		else {
			const char *const default_format = OUTPUT_FORMAT;

			output_format = default_format[0];
		}
	}
	return output_format;
}

/*!\brief Start of execution.  This will mostly call other functions one
 * after another.
 *
 * \return Return value indicates success or fail or analysis, unless
 * either --warning or --critical options are in use, which makes the
 * return value in some cases to match with Nagios expectations about
 * alarming. */
int main(int argc, char **argv)
{
	struct conf_t state = {
		.warning = ALARM_WARN,
		.critical = ALARM_CRIT,
		.warn_count = 0x100000000,	/* == 2^32 that is the entire IPv4 space */
		.crit_count = 0x100000000,	/* basically turns off the count criteria */
		.header_limit = 8,
		.color_mode = color_auto,
		.ranges_size = 64,
		.ip_version = IPvUNKNOWN,
		0
	};
	char output_format;
	int ret_val;

	atexit(close_stdout);
	set_program_name(argv[0]);
	prepare_memory(&state);
	set_ipv_functions(&state, IPvUNKNOWN);
	output_format = parse_command_line_opts(&state, argc, argv);

	/* Do the job */
	parse_config(&state, 1, state.dhcpdconf_file, state.shared_net_root);
	if (output_format == 'X' || output_format == 'J')
		parse_leases(&state, 1);
	else
		parse_leases(&state, 0);
	prepare_data(&state);
	do_counting(&state);
	if (state.sorts != NULL)
		mergesort_ranges(&state, state.ranges, state.num_ranges, NULL, 1);
	if (state.reverse_order == 1)
		flip_ranges(&state);
	ret_val = output_analysis(&state, output_format);
	clean_up(&state);
	return (ret_val);
}
