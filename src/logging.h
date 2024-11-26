/* ureadahead
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

#ifndef UREADAHEAD_LOGGING_H
#define UREADAHEAD_LOGGING_H

#define LOG_SEVERITIES \
	LOG_SEVERITY(DEBUG) \
	LOG_SEVERITY(INFO) \
	LOG_SEVERITY(MESSAGE) \
	LOG_SEVERITY(WARN) \
	LOG_SEVERITY(ERROR) \
	LOG_SEVERITY(FATAL)


#undef LOG_SEVERITY
#define LOG_SEVERITY(severity) UREADAHEAD_LOG_##severity,

/*
 * Logger severity.
 */
enum LogSeverity {
	LOG_SEVERITIES
};

#undef LOG_SEVERITY
#define LOG_SEVERITY(severity) #severity,

/* 
 * stringified severity.
 */
static const char *log_severity_string[] = {
	LOG_SEVERITIES
	NULL
};

extern enum LogSeverity log_minimum_severity;

/*
 * Outputs the log with given severity into stdout/stderr.
 *
 * It will output to stdout when the log severity is set to below
 * warn. otherwise, it will forward to stderr.
 *
 * Any message that has the severity below the one set by the
 * log_set_minimum_severity will be discarded without being
 * outputted to stdout/stderr.
 *
 * @severity: Severity of this specific log message.
 * @format: message format to output.
 */
void log_write (enum LogSeverity severity, const char *format, ...) 
	__attribute__ ((format (printf, 2, 3)));

/*
 * Configures new severity filter for subsequent logging output.
 *
 * Any logging attempt that uses the severity below the one set
 * with this function will be discarded before being passed to
 * the logger function.
 *
 * @new_minimum_severity: New minimum severity.
 *
 * returns previously set logger severity.
 */
enum LogSeverity log_set_minimum_severity (enum LogSeverity new_minimum_severity);

/*
 * Definition of macro to report errors.
 */

#define log_fatal(format, ...) \
	log_write (UREADAHEAD_LOG_FATAL, format, ##__VA_ARGS__)

#define log_error(format, ...) \
	log_write (UREADAHEAD_LOG_ERROR, format, ##__VA_ARGS__)

#define log_warn(format, ...) \
	log_write (UREADAHEAD_LOG_WARN, format, ##__VA_ARGS__)

#define log_message(format, ...) \
	log_write (UREADAHEAD_LOG_MESSAGE, format, ##__VA_ARGS__)

#define log_info(format, ...) \
	log_write (UREADAHEAD_LOG_INFO, format, ##__VA_ARGS__)

#define log_debug(format, ...) \
	log_write (UREADAHEAD_LOG_DEBUG, format, ##__VA_ARGS__)

#endif /* UREADAHEAD_LOGGING_H */
