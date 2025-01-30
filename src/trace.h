/* ureadahead
 *
 * Copyright © 2009 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef UREADAHEAD_TRACE_H
#define UREADAHEAD_TRACE_H

#include <limits.h>
#include <sys/types.h>


/**
 * FS_SYSTEM
 *
 * "fs" subsystem of the tracefs.
 **/
#define FS_SYSTEM "fs"

/**
 * FILEMAP_SYSTEM
 *
 * "filemap" subsystem of the tracefs.
 **/
#define FILEMAP_SYSTEM	"filemap"

/**
 * EVENTS:
 *
 * TraceFS events to enable.
 *
 **/
static const char *EVENTS[][2] = {
	/* required events for trace to work */
	{FS_SYSTEM, "do_sys_open"},
	{FS_SYSTEM, "open_exec"},
	/* The below events can also work */
	{FILEMAP_SYSTEM, "mm_filemap_fault"},
	{FILEMAP_SYSTEM, "mm_filemap_get_pages"},
	{FILEMAP_SYSTEM, "mm_filemap_map_pages"},
	/* optional events follow */
	{FS_SYSTEM, "uselib"}};

/**
 * NR_REQUIRED_EVENTS:
 *
 * Number of required events for ureadahead to function.
 * NOTE: make sure to match the number with the content of EVENTS above.
 **/
#define NR_REQUIRED_EVENTS 2

/**
 * NR_ALTERNATE_REQUIRED_EVENTS:
 *
 * Number of required events for ureadahead to achieve full potential.
 * NOTE: make sure to match the number with the content of EVENTS above.
 **/
#define NR_ALTERNATE_REQUIRED_EVENTS (2 + 3)

/**
 * NR_EVENTS:
 *
 * Number of total events.
 **/
#define NR_EVENTS (sizeof (EVENTS) / sizeof (EVENTS[0]))

typedef struct path_prefix_option {
        dev_t st_dev;
        char prefix[PATH_MAX];
} PathPrefixOption;

struct trace_context {
	int old_events_enabled[NR_EVENTS];
	int old_tracing_enabled;
	int old_buffer_size_kb;
};

int trace_begin (struct trace_context *ctx,
		 int daemonise,
		 int use_existing_trace_events,
		 int timeout);

int trace_process_events (struct trace_context *ctx,
			  const char *filename_to_replace,
			  const char *pack_file, /* Nullable */
			  const char *path_prefix_filter, /* Nullable */
			  const PathPrefixOption *path_prefix,
			  int use_existing_trace_events,
			  int force_ssd_mode);

#endif /* UREADAHEAD_TRACE_H */
