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



typedef struct path_prefix_option {
        dev_t st_dev;
        char prefix[PATH_MAX];
} PathPrefixOption;

int trace_begin (int daemonise, int use_existing_trace_events);

void signal_wait (int timeout);

int trace_process_events (const char *filename_to_replace,
			  const char *pack_file, /* Nullable */
			  const char *path_prefix_filter, /* Nullable */
			  const PathPrefixOption *path_prefix,
			  int use_existing_trace_events,
			  int force_ssd_mode);

#endif /* UREADAHEAD_TRACE_H */
