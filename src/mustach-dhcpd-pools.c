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

/*! \file mustach-dhcpd-pools.c
 * \brief Mustache templating specific functions.
 */

#include <config.h>

#include <fcntl.h>
#include <errno.h>
#include <error.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "close-stream.h"
#include "dhcpd-pools.h"
#include "error.h"
#include "mustach.h"
#include "xalloc.h"

/*! \struct expl
 * \brief A structure that travels through mustach via closure void pointer.
 */
struct expl {
	struct conf_t *state;
	struct range_t *range_p;
	struct shared_network_t *shnet_p;
	struct output_helper_t oh;
	int current;
};

static int must_enter(void *closure, const char *name);
static int must_leave(void *closure);

/*!  \brief Template base level tag parser and printer. */
static int must_put_base(void *closure, const char *name, int escape
			 __attribute__ ((unused)), FILE *file)
{
	struct expl *e = closure;

	if (!strcmp(name, "localtime")) {
		dp_time_tool(file, NULL, 0);
		return 0;
	}
	if (!strcmp(name, "number_of_ranges")) {
		fprintf(file, "%u", e->state->num_ranges);
		return 0;
	}
	if (!strcmp(name, "number_of_shared_networks")) {
		static uint32_t num = 0xffffffff;

		if (num == 0xffffffff) {
			/* Use of static num ensures this is done only once. */
			struct shared_network_t *shared_p;

			num = 0;
			for (shared_p = e->state->shared_net_root->next; shared_p;
			     shared_p = shared_p->next)
				num++;
		}
		fprintf(file, "%u", num);
		return 0;
	}
	if (!strcmp(name, "version")) {
		fprintf(file, "%s", PACKAGE_VERSION);
		return 0;
	}
	/* lease file */
	if (!strcmp(name, "lease_file_path")) {
		fprintf(file, "%s", e->state->dhcpdlease_file);
		return 0;
	}
	if (!strcmp(name, "lease_file_local_mtime")) {
		dp_time_tool(file, e->state->dhcpdlease_file, 0);
		return 0;
	}
	if (!strcmp(name, "lease_file_epoch_mtime")) {
		dp_time_tool(file, e->state->dhcpdlease_file, 1);
		return 0;
	}
	/* conf file */
	if (!strcmp(name, "conf_file_path")) {
		fprintf(file, "%s", e->state->dhcpdconf_file);
		return 0;
	}
	if (!strcmp(name, "conf_file_local_mtime")) {
		dp_time_tool(file, e->state->dhcpdconf_file, 0);
		return 0;
	}
	if (!strcmp(name, "conf_file_epoch_mtime")) {
		dp_time_tool(file, e->state->dhcpdconf_file, 1);
		return 0;
	}
	/* template file */
	if (!strcmp(name, "template_file_path")) {
		fprintf(file, "%s", e->state->mustach_template);
		return 0;
	}
	if (!strcmp(name, "template_file_local_mtime")) {
		dp_time_tool(file, e->state->mustach_template, 0);
		return 0;
	}
	if (!strcmp(name, "template_file_epoch_mtime")) {
		dp_time_tool(file, e->state->mustach_template, 1);
		return 0;
	}
	error(EXIT_FAILURE, 0, "mustach_dhcpd_pools: fmustach: unexpected tag: %s", name);
	return 1;
}

/*! \struct mustach_itf
 * \brief Mustach function pointers. */
static struct mustach_itf itf = {
	.start = NULL,
	.enter = must_enter,
	.put = must_put_base,
	.next = NULL,
	.leave = must_leave
};

/*!  \brief Mustach range aka {{#subnets}} tag parser and printer. */
static int must_put_range(void *closure, const char *name, int escape
			  __attribute__ ((unused)), FILE *file)
{
	struct expl *e = closure;

	if (!strcmp(name, "location")) {
		fprintf(file, "%s", e->range_p->shared_net->name);
		return 0;
	}
	if (!strcmp(name, "range")) {
		fprintf(file, "%s - ", ntop_ipaddr(&e->range_p->first_ip));
		fprintf(file, "%s", ntop_ipaddr(&e->range_p->last_ip));
		return 0;
	}
	if (!strcmp(name, "first_ip")) {
		fprintf(file, "%s", ntop_ipaddr(&e->range_p->first_ip));
		return 0;
	}
	if (!strcmp(name, "last_ip")) {
		fprintf(file, "%s", ntop_ipaddr(&e->range_p->last_ip));
		return 0;
	}
	if (!strcmp(name, "used")) {
		fprintf(file, "%g", e->range_p->count);
		return 0;
	}
	if (!strcmp(name, "touched")) {
		fprintf(file, "%g", e->range_p->touched);
		return 0;
	}
	if (!strcmp(name, "defined")) {
		fprintf(file, "%g", e->oh.range_size);
		return 0;
	}
	if (!strcmp(name, "free")) {
		fprintf(file, "%g", e->oh.range_size - e->range_p->count);
		return 0;
	}
	if (!strcmp(name, "percent")) {
		fprintf(file, "%g", e->oh.percent);
		return 0;
	}
	if (!strcmp(name, "touch_count")) {
		fprintf(file, "%g", e->oh.tc);
		return 0;
	}
	if (!strcmp(name, "touch_percent")) {
		fprintf(file, "%g", e->oh.tcp);
		return 0;
	}
	if (e->state->backups_found == 1) {
		if (!strcmp(name, "backup_count")) {
			fprintf(file, "%g", e->range_p->backups);
			return 0;
		}
		if (!strcmp(name, "backup_percent")) {
			fprintf(file, "%g", e->oh.bup);
			return 0;
		}
	}
	if (!strcmp(name, "status")) {
		fprintf(file, "%d", e->oh.status);
		return 0;
	}
	if (!strcmp(name, "gettimeofday")) {
		dp_time_tool(file, NULL, 1);
		return 0;
	}
	if (!strcmp(name, "lease_file_epoch_mtime")) {
		dp_time_tool(file, e->state->dhcpdlease_file, 1);
		return 0;
	}
	error(EXIT_FAILURE, 0, "mustach_dhcpd_pools: fmustach: unexpected tag: %s", name);
	return 1;
}

/*!  \brief Mustach shared networks aka {{#shared-networks}} tag parser and printer. */
static int must_put_shnet(void *closure, const char *name, int escape
			  __attribute__ ((unused)), FILE *file)
{
	struct expl *e = closure;

	if (!strcmp(name, "location")) {
		fprintf(file, "%s", e->shnet_p->name);
		return 0;
	}
	if (!strcmp(name, "defined")) {
		fprintf(file, "%g", e->shnet_p->available);
		return 0;
	}
	if (!strcmp(name, "used")) {
		fprintf(file, "%g", e->shnet_p->used);
		return 0;
	}
	if (!strcmp(name, "touched")) {
		fprintf(file, "%g", e->shnet_p->touched);
		return 0;
	}
	if (!strcmp(name, "free")) {
		fprintf(file, "%g", e->shnet_p->available - e->shnet_p->used);
		return 0;
	}
	if (!strcmp(name, "percent")) {
		fprintf(file, "%g", e->oh.percent);
		return 0;
	}
	if (!strcmp(name, "touch_count")) {
		fprintf(file, "%g", e->oh.tc);
		return 0;
	}
	if (!strcmp(name, "touch_percent")) {
		fprintf(file, "%g", e->oh.tcp);
		return 0;
	}
	if (e->state->backups_found == 1) {
		if (!strcmp(name, "backup_count")) {
			fprintf(file, "%g", e->shnet_p->backups);
			return 0;
		}
		if (!strcmp(name, "backup_percent")) {
			fprintf(file, "%g", e->oh.bup);
			return 0;
		}
	}
	if (!strcmp(name, "status")) {
		fprintf(file, "%d", e->oh.status);
		return 0;
	}
	if (!strcmp(name, "gettimeofday")) {
		dp_time_tool(file, NULL, 1);
		return 0;
	}
	if (!strcmp(name, "lease_file_epoch_mtime")) {
		dp_time_tool(file, e->state->dhcpdlease_file, 1);
		return 0;
	}
	error(EXIT_FAILURE, 0, "mustach_dhcpd_pools: fmustach: unexpected tag: %s", name);
	return 1;
}

/*!  \brief A function to move to next range when {{/subnets}} is encountered. */
static int must_next_range(void *closure)
{
	struct expl *e = closure;

	do {
		e->range_p++;
		e->current--;
		if (e->current <= 0)
			return 0;
	} while (range_output_helper(e->state, &e->oh, e->range_p));
	return 1;
}

/*!  \brief A function to move to next shared network when {{/shared-networks}}
 * is encountered.  */
static int must_next_shnet(void *closure)
{
	struct expl *e = closure;

	if (e->current == 1 || e->shnet_p == NULL)
		return 0;
	while (1) {
		e->shnet_p = e->shnet_p->next;
		if (e->shnet_p == NULL)
			break;
		if (shnet_output_helper(e->state, &e->oh, e->shnet_p))
			continue;
		else
			return 1;
	}
	return 0;
}

/*! \brief Function that is called when mustach is searching output loops from
 * template file.  */
static int must_enter(void *closure, const char *name)
{
	struct expl *e = closure;

	if (!strcmp(name, "subnets")) {
		itf.put = must_put_range;
		itf.next = must_next_range;
		e->current = e->state->num_ranges + 1;
		e->range_p = e->state->ranges;
		/* must_next_range() will skip_ok when needed */
		e->range_p--;
		return must_next_range(closure);
	}
	if (!strcmp(name, "shared-networks")) {
		itf.put = must_put_shnet;
		itf.next = must_next_shnet;
		e->shnet_p = e->state->shared_net_root;
		e->current = 0;
		return must_next_shnet(closure);
	}
	if (!strcmp(name, "summary")) {
		itf.put = must_put_shnet;
		itf.next = must_next_shnet;
		e->shnet_p = e->state->shared_net_root;
		e->current = 1;
		shnet_output_helper(e->state, &e->oh, e->shnet_p);
		return 1;
	}
	error(EXIT_FAILURE, 0, "mustach_dhcpd_pools: fmustach: unexpected tag: %s", name);
	return 1;
}

/*! \brief Function that is called when all elements within a print loop are outputed. */
static int must_leave(void *closure)
{
	struct expl *e = closure;

	e->shnet_p = e->state->shared_net_root;
	e->range_p = e->state->ranges;
	itf.put = must_put_base;
	return 0;
}

/*! \brief Read mustach template to memory. */
static char *must_read_template(const char *filename)
{
	int f;
	struct stat s;
	char *result;

	if (filename == NULL)
		error(EXIT_FAILURE, 0, "must_read_template: --mustach argument missing");
	if ((f = open(filename, O_RDONLY)) < 0) {
		error(EXIT_FAILURE, errno, "must_read_template: open: %s", filename);
	}
	fstat(f, &s);
	result = xmalloc(s.st_size + 1);
	if (read(f, result, s.st_size) != s.st_size) {
		error(EXIT_FAILURE, errno, "must_read_template: read: %s", filename);
	}
	close(f);
	result[s.st_size] = 0;
	return result;
}

/*! \brief Start mustach processing. */
int mustach_dhcpd_pools(struct conf_t *state)
{
	struct expl e = { .state = state };
	char *template;
	FILE *outfile;
	int ret;

	template = must_read_template(state->mustach_template);
	if (state->output_file) {
		outfile = fopen(state->output_file, "w+");
		if (outfile == NULL) {
			error(EXIT_FAILURE, errno, "mustach_dhcpd_pools: fopen: %s",
			      state->output_file);
		}
	} else {
		outfile = stdout;
	}
	ret = fmustach(template, &itf, &e, outfile);
	free(template);
	if (outfile == stdout) {
		if (fflush(stdout))
			error(EXIT_FAILURE, errno, "mustach_dhcpd_pools: fflush");
	} else {
		if (close_stream(outfile))
			error(EXIT_FAILURE, errno, "mustach_dhcpd_pools: fclose");
	}
	switch (ret) {
	case MUSTACH_OK:
		return 0;
	case MUSTACH_ERROR_SYSTEM:
		error(EXIT_FAILURE, 0, "mustach_dhcpd_pools: fmustach: system error");
		break;
	case MUSTACH_ERROR_UNEXPECTED_END:
		error(EXIT_FAILURE, 0, "mustach_dhcpd_pools: fmustach: unexpected end");
		break;
	case MUSTACH_ERROR_EMPTY_TAG:
		error(EXIT_FAILURE, 0, "mustach_dhcpd_pools: fmustach: empty tag");
		break;
	case MUSTACH_ERROR_TAG_TOO_LONG:
		error(EXIT_FAILURE, 0, "mustach_dhcpd_pools: fmustach: too long tag");
		break;
	case MUSTACH_ERROR_BAD_SEPARATORS:
		error(EXIT_FAILURE, 0, "mustach_dhcpd_pools: fmustach: bad separator");
		break;
	case MUSTACH_ERROR_TOO_DEPTH:
		error(EXIT_FAILURE, 0, "mustach_dhcpd_pools: fmustach: too deep");
		break;
	case MUSTACH_ERROR_CLOSING:
		error(EXIT_FAILURE, 0, "mustach_dhcpd_pools: fmustach: closing");
		break;
	case MUSTACH_ERROR_BAD_UNESCAPE_TAG:
		error(EXIT_FAILURE, 0, "mustach_dhcpd_pools: fmustach: bad escape tag");
		break;
	default:
		error(EXIT_FAILURE, 0, "mustach_dhcpd_pools: fmustach: unknown error");
	}
	return 1;
}
