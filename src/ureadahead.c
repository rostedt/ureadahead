/* ureadahead
 *
 * Copyright © 2009 Canonical Ltd.
 * Author: Scott James Remnant <scott@netsplit.com>.
 *
 * Inspired by readahead:
 *   Copyright © 2005 Ziga Mahkovec <ziga.mahkovec@klika.si>
 *   Copyright © 2006, 2007 Red Hat, Inc.
 * and sreadahead:
 *   Copyright © 2008 Intel Corporation,
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif /* HAVE_CONFIG_H */

#ifndef PACKAGE_NAME
# define PACKAGE_NAME    "ureadahead"
#endif /* PACKAGE_NAME */

#ifndef PACKAGE_VERSION
# define PACKAGE_VERSION "0.100.2"
#endif /* PACKAGE_VERSION */

#ifndef PACKAGE_STRING
# define PACKAGE_STRING  "ureadahead 0.100.2"
#endif /* PACKAGE_STRING */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/select.h>

#include <stdio.h>
#include <assert.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pack.h"
#include "trace.h"
#include "logging.h"


/**
 * daemonise:
 *
 * Set to 1 if we should become a daemon, rather than just running
 * in the foreground.
 **/
static int daemonise = 0;

/**
 * force_trace:
 *
 * Set to 1 if we should re-trace no matter what, the existing pack
 * file will not be read.
 **/
static int force_trace = 0;

/**
 * record_and_replay:
 *
 * Set to 1 if we should both enable tracing and perform readahead
 * process. Mutually exclusive from --force-trace and --dump.
 **/
static int record_and_replay = 0;

/**
 * timeout:
 *
 * Set to non-zero if we should stop tracing after a particular time,
 * rather than waiting for a signal.
 **/
static int timeout = 0;

/**
 * dump_pack:
 *
 * Set to 1 to only dump the current pack file.
 **/
static int dump_pack = 0;

/**
 * sort_pack:
 *
 * Set to how we want the pack sorted when dumping.
 **/
static SortOption sort_pack = SORT_OPEN;

/**
 * path_prefix:
 *
 * path_prefix.st_dev is set to >=0 if we should prepend path_prefix.prefix
 * to all path names on the device.
 **/
static PathPrefixOption path_prefix = { NODEV };

/**
 * pack_file:
 *
 * Path to the pack file to use.
 */
static char *pack_file = NULL;

/**
 * path_prefix_filter:
 *
 * Path prefix that files read during tracing have to start with to be included
 * in the pack file.
 */
static char *path_prefix_filter = NULL;

/**
 * use_existing_trace_events:
 *
 * Set to 1 if trace events (tracing/events/fs/) used to build the pack file
 * are enabled and disabled outside of ureadahead. Needed if trace events access
 * is never allowed (while setting buffer size and tracing on/off is allowed) by
 * the OS's SELinux policy.
 */
static int use_existing_trace_events = 0;

/**
 * force_ssd_mode:
 *
 * Querying sysfs to detect whether disk is rotational does not work for virtual
 * devices in vm, this will write pack header with rotational field set to 0.
 */
static int force_ssd_mode = 0;

static int
handle_path_prefix_option (const char *arg)
{
	struct stat st;
	dev_t st_dev;
	assert (arg != NULL);

	if (strlen (arg) >= PATH_MAX) {
		log_fatal("Illegal argument:"
			  " --path-prefix='%s' exceeds allowed path size",
			  arg);
		return -1;
	}

	if (lstat (arg, &st) < 0 || !S_ISDIR (st.st_mode)) {
		log_fatal("Illegal argument:"
			  " --path-prefix='%s' is not a directory",
			  arg);
		return -1;
	}

	path_prefix.st_dev = st.st_dev;
	strcpy (path_prefix.prefix, arg);

	return 0;
}

static int
handle_sort_option (const char *arg)
{
	assert (arg != NULL);
	if (strcmp (arg, "open") == 0) {
		sort_pack = SORT_OPEN;
	} else if (strcmp (arg, "path") == 0) {
		sort_pack = SORT_PATH;
	} else if (strcmp (arg, "disk") == 0) {
		sort_pack = SORT_DISK;
	} else if (strcmp (arg, "size") == 0) {
		sort_pack = SORT_SIZE;
	} else {
		log_fatal ("Illegal argument:"
			   " --sort needs to be one of 'open', 'path', 'disk', 'size'");
		return -1;
	}

	return 0;
}

enum OptionFlag {
	OPTION_TIMEOUT			= 't',
	OPTION_SORT			= 's',
	OPTION_PATH_PREFIX		= 'p',
	OPTION_PACK_FILE		= 'f',
	OPTION_PATH_PREFIX_FILTER	= 'i',
	OPTION_HELP			= 'h',
	OPTION_VERSION			= 'V',
	OPTION_VERBOSE			= 'v',
	OPTION_QUIET			= 'q',
	OPTION_DEBUG			= 'd',
};

/**
 * options:
 *
 * Command-line options accepted by this tool.
 **/
static struct option options[] = {
	/*
	 * boolean options
	 */
	{ "daemon", no_argument, &daemonise, 1 },
	{ "force-trace", no_argument, &force_trace, 1 },
	{ "dump", no_argument, &dump_pack, 1 },
	{ "use-existing-trace-events", no_argument, &use_existing_trace_events, 1 },
	{ "force-ssd-mode", no_argument, &force_ssd_mode, 1 },
	{ "record-and-replay", no_argument, &record_and_replay, 1 },

	/*
	 * boolean flags that has a special handling
	 */
	{ "help", no_argument, NULL, OPTION_HELP },
	{ "version", no_argument, NULL, OPTION_VERSION },
	{ "verbose", no_argument, NULL, OPTION_VERBOSE }, /* allows -v */
	{ "quiet", no_argument, NULL, OPTION_QUIET }, /* allows -q */
	{ "debug", no_argument, NULL, OPTION_DEBUG },

	/* options with parameters */
	{ "timeout", required_argument, NULL, OPTION_TIMEOUT },
	{ "sort", required_argument, NULL, OPTION_SORT },
	{ "path-prefix", required_argument, NULL, OPTION_PATH_PREFIX },
	{ "path-prefix-filter", required_argument, NULL, OPTION_PATH_PREFIX_FILTER },
	{ "pack-file", required_argument, NULL, OPTION_PACK_FILE },
	{ NULL, 0, NULL, 0 }
};

static void
print_usage () {
	printf ("Usage: %s [OPTION]... [PATH]\n", PACKAGE_NAME);
	printf ("Read required files in advance.\n\n");

	printf ("Options:\n"
		"  --daemon\n"
		"    Detach and run in background\n"
		"  --force-trace\n"
		"    Ignore existing pack file and force retracing\n"
		"    Mutually exclusive with --dump and --record-and-replay\n"
		"  --record-and-replay\n"
		"    Perform tracing and replaying together\n"
		"    Mutually exclusive with --force-trace and --dump\n"
		"  --timeout=SECONDS\n"
		"    Maximum duration of tracing (default: unset; continue until interrupt)\n"
		"  --dump\n"
		"    Dump the specified pack file and exit\n"
		"    Mutually exclusive with --force-trace and --record-and-replay\n"
		"  --sort=(open|path|disk|size)\n"
		"    Specify how to sort the pack file when dumping (default: open)\n"
		"  --path-prefix=PREFIX\n"
		"    Pathname to prepend for files on the device\n"
		"  --path-prefix-filter=PREFIX_FILTER\n"
		"    Path prefix that retained files during tracing must start with\n"
		"  --pack-file=PACK_FILE\n"
		"    Path of the pack file to use. takes precedence oveer [PATH]\n"
		"  --use-existing-trace-events\n"
		"    Do not enable/disable trace events\n"
		"  --force-ssd-mode\n"
		"    Force SSD setting in pack file during tracing\n"
		"  --help\n"
		"    Display this help and exit\n"
		"  --version\n"
		"    Output version information and exit\n"
		"  -v --verbose\n"
		"    Output informational messages\n"
		"  -q --quiet\n"
		"    Suppress non-error messages\n"
		"  --debug\n"
		"    Outputs debug messages\n"
		"\n"
	);

	printf ("PATH should be the location of a mounted filesystem "
		  "for which files should be read.  If not given, the root "
		  "filesystem is assumed.\n"
		  "\n"
		  "If PATH is not given, and no readahead information exists "
		  "for the root filesystem (or it is old), tracing is "
		  "performed instead to generate the information for the "
		  "next boot.\n");

	printf ("Report bugs to <ubuntu-devel@lists.ubuntu.com> \n");
}

static void
print_version () {
	printf ("%s\n\n", PACKAGE_STRING);
	printf ("This is free software; see the source for copying conditions. "
		"There is NO warranty; not even for MERCHANTABILITY or "
		"FITNESS FOR A PARTICULAR PURPOSE."
		"\n");
}

int parse_options (int argc, char **argv) {
	int output = 0;

	for (;;) {
		output = getopt_long (argc, argv, "vq", options, NULL);
		/* Done */
		if (output == -1)
			return optind;

		switch (output) {
		case 0: /* self-handling options, ignore */
			break;
		case '?': /* unknown option */
			return -1;
		case OPTION_TIMEOUT:
			timeout = atoi (optarg);
			break;
		case OPTION_SORT:
			if (handle_sort_option (optarg) != 0)
				return -1;
			break;
		case OPTION_PATH_PREFIX:
			if (handle_path_prefix_option (optarg) != 0)
				return -1;
			break;
		case OPTION_PATH_PREFIX_FILTER:
			if (path_prefix_filter) /* already set */
				return -1;
			path_prefix_filter = strdup (optarg);
			break;
		case OPTION_PACK_FILE:
			if (pack_file)  /* already set */
				return -1;
			pack_file = strdup (optarg);
			break;
		case OPTION_VERBOSE:
			log_set_minimum_severity (UREADAHEAD_LOG_INFO);
			break;
		case OPTION_QUIET:
			log_set_minimum_severity (UREADAHEAD_LOG_ERROR);
			break;
		case OPTION_DEBUG:
			log_set_minimum_severity (UREADAHEAD_LOG_DEBUG);
			break;
		case OPTION_HELP:
			print_usage ();
			exit (0);
		case OPTION_VERSION:
			print_version ();
			exit (0);
		default:
			__builtin_unreachable ();
		}
	}

	__builtin_unreachable ();
}

static void
sig_interrupt (int signum)
{
}

static void
await_for_signal (int timeout)
{
	struct sigaction act;
	struct timeval tv;
	struct sigaction old_sigterm;
	struct sigaction old_sigint;

	/* Sleep until we get signals */
	act.sa_handler = sig_interrupt;
	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;

	sigaction (SIGTERM, &act, &old_sigterm);
	sigaction (SIGINT, &act, &old_sigint);

	if (timeout) {
		tv.tv_sec = timeout;
		tv.tv_usec = 0;

		select (0, NULL, NULL, NULL, &tv);
	} else {
		pause ();
	}

	sigaction (SIGTERM, &old_sigterm, NULL);
	sigaction (SIGINT, &old_sigint, NULL);
}

int
main (int   argc,
      char *argv[])
{
	char *    filename = NULL;
	PackFile *file = NULL;

	int path_position = 0;
	if ((path_position = parse_options (argc, argv)) == -1)
		exit (1);

	if (dump_pack && force_trace) {
		log_fatal ("--dump and --force-trace are mutually exclusive");
		exit (1);
	}

	if ((dump_pack || force_trace) && record_and_replay) {
		log_fatal ("--record-and-replay flag is mutually exclusive from "
			   "--force-trace or --dump. exiting");
		exit (1);
	}

	/* Lookup the filename for the pack based on the path given
	 * (if any).
	 */
	filename = pack_file
		? strdup (pack_file)
		: pack_file_name (argv[path_position]);

	assert (filename != NULL);

	struct trace_context trace_ctx;

	if (record_and_replay) {
		/* read_pack operation can be costly, enough to lose the earlier
		 * file access that can be impactful to boot time.
		 * Enable tracepoints first.
		 */
		if (trace_begin (&trace_ctx, daemonise, use_existing_trace_events) < 0) {
			log_fatal ("Failed to enable tracepoints for recording. exiting");
			exit (6);
		}

		file = read_pack (filename, dump_pack);
		if (file) {
			if (do_readahead (file, daemonise) < 0) {
				log_fatal ("Failed to perform readahead. exiting");
				trace_cancel (&trace_ctx, use_existing_trace_events);
				exit (3);
			}
		}

		await_for_signal (timeout);
		if (trace_process_events (&trace_ctx, filename, pack_file,
					  path_prefix_filter,  &path_prefix,
					  use_existing_trace_events,
					  force_ssd_mode) < 0) {
			log_error ("Failed to process trace events, exiting.");
			exit (7);
		}
	} else if (force_trace) {
		if (trace_begin (&trace_ctx, daemonise, use_existing_trace_events) < 0) {
			log_fatal ("Failed to enable tracepoints for recording. exiting");
			exit (6);
		}
		await_for_signal (timeout);
		if (trace_process_events (&trace_ctx, filename, pack_file,
					  path_prefix_filter,  &path_prefix,
					  use_existing_trace_events,
					  force_ssd_mode) < 0) {
			log_error ("Failed to process trace events, exiting.");
			exit (7);
		}
	} else if (dump_pack) {
		file = read_pack (filename, dump_pack);
		if (! file) {
			log_fatal ("Pack file required, but couldn't be opened. exiting");
			exit (4);
		}
		pack_dump (file, sort_pack);
	} else {
		/* Open the file and do readahead if it exists, otherwise
		 * begin tracing and output a pack file.
		 */
		file = read_pack (filename, dump_pack);

		if (file) {
			if (do_readahead (file, daemonise) < 0) {
				log_fatal ("Failed to perform readahead. exiting");
				exit (3);
			}
		} else {
			if (trace_begin (&trace_ctx, daemonise, use_existing_trace_events) < 0) {
				log_fatal ("Failed to enable tracepoints for recording. exiting");
				exit (6);
			}
			await_for_signal (timeout);
			if (trace_process_events (&trace_ctx, filename, pack_file,
						  path_prefix_filter,  &path_prefix,
						  use_existing_trace_events,
						  force_ssd_mode) < 0) {
				log_error ("Failed to process trace events, exiting.");
				exit (7);
			}
		}
	}

	if (file)
		free_pack_content (file);

	free (filename);
	free (file);
	free (pack_file);
	free (path_prefix_filter);

	return 0;
}
