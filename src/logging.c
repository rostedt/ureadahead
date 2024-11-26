/* ureadahead
 *
 * logging.c - logging implementation
 *
 * Copyright 2025 Google LLC
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

/* Requires _GNU_SOURCE for vasprintf. */
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>

#include "logging.h"

enum LogSeverity log_minimum_severity = UREADAHEAD_LOG_MESSAGE;

void log_write (enum LogSeverity severity, const char *format, ...)
{
	va_list va;
	int written;
	FILE *fp = stdout;

	assert (UREADAHEAD_LOG_DEBUG <= severity
		&& severity <= UREADAHEAD_LOG_FATAL);
	assert (format != NULL);

	if (severity < log_minimum_severity)
		return;

	if (severity >= UREADAHEAD_LOG_WARN) {
		const char *severity_str = log_severity_string[severity];
		written = fprintf (stderr, "[%s] ureadahead: ", severity_str);
		fp = stderr;

		assert (written > 0);
	}

	va_start (va, format);
	written = vfprintf (fp, format, va);
	va_end (va);
	assert (written > 0);

	fputc ('\n', fp);
}

enum LogSeverity log_set_minimum_severity (enum LogSeverity new_minimum_severity)
{
	assert (UREADAHEAD_LOG_DEBUG <= new_minimum_severity
		&& new_minimum_severity <= UREADAHEAD_LOG_FATAL);

	enum LogSeverity previous_minimum_severity = log_minimum_severity;
	log_minimum_severity = new_minimum_severity;

	return log_minimum_severity;
}
