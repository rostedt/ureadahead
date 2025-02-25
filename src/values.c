/* ureadahead
 *
 * values.c - dealing with proc/sysfs values
 *
 * Copyright © 2009 Canonical Ltd.
 * Author: Scott James Remnant <scott@netsplit.com>.
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

#define _ATFILE_SOURCE


#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h> /* for atoi */
#include <string.h>
#include <stdlib.h> /* for atoi */
#include <unistd.h>

#include "values.h"
#include "logging.h"

int
get_value (int         dfd,
	   const char *path,
	   int *       value)
{
	int     fd;
	char    buf[80];
	ssize_t len;

	assert (path != NULL);
	assert (value != NULL);

	fd = openat (dfd, path, O_RDONLY);
	if (fd < 0) {
		log_error ("Failed to open %s: %s",
			   path, strerror (errno));
		return -1;
	}

	len = read (fd, buf, sizeof(buf) - 1);
	if (len < 0) {
		log_error ("failed to read %s: %s",
			   path, strerror (errno));
		close (fd);
		return -1;
	}

	buf[len] = '\0';
	*value = len ? atoi (buf) : 0;

	if (close (fd) < 0) {
		log_error ("Failed to close %s: %s",
			   path, strerror (errno));
		return -1;
	}

	return 0;
}

int
set_value (int         dfd,
	   const char *path,
	   int         value,
	   int *       oldvalue)
{
	int     fd;
	char    buf[80];
	ssize_t len;

	assert (path != NULL);

	fd = openat (dfd, path, O_RDWR);
	if (fd < 0) {
		log_error ("Failed to open %s: %s",
			   path, strerror (errno));
		return -1;
	}

	if (oldvalue) {
		len = read (fd, buf, sizeof(buf) - 1);
		if (len < 0) {
			log_error ("failed to read %s: %s",
				   path, strerror (errno));
			close (fd);
			return -1;
		}

		buf[len] = '\0';
		*oldvalue = atoi (buf);

		assert (lseek (fd, 0, SEEK_SET) == 0);
	}

	snprintf (buf, sizeof buf, "%d", value);

	len = write (fd, buf, strlen (buf));
	if (len < 0) {
		log_error ("failed to write %s: %s",
			   path, strerror (errno));
		close (fd);
		return -1;
	}

	assert (len > 0);

	if (close (fd) < 0) {
		log_error ("failed to close %s: %s",
			   path, strerror (errno));
		return -1;
	}

	return 0;
}
