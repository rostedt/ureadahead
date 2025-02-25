/* ureadahead
 *
 * pack.c - pack file handling
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

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/resource.h>

#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <blkid.h>
#include <ext2fs.h>

#include "pack.h"
#include "values.h"
#include "logging.h"


/* From linux/ioprio.h */
#define IOPRIO_CLASS_SHIFT 13

#define IOPRIO_CLASS_RT    1
#define IOPRIO_CLASS_IDLE  3

#define IOPRIO_WHO_PROCESS 1

#define IOPRIO_RT_HIGHEST  (0 | (IOPRIO_CLASS_RT << IOPRIO_CLASS_SHIFT))
#define IOPRIO_IDLE_LOWEST (7 | (IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT))


/**
 * PATH_PACKDIR:
 *
 * Path to the directory in which we write our pack files.
 **/
#define PATH_PACKDIR "/var/lib/ureadahead"

/**
 * NUM_THREADS:
 *
 * Number of threads to use when reading on an SSD.
 **/
#define NUM_THREADS 4

/**
 * READAHEAD_MAX_LENGTH:
 *
 * Maximum length that can be passed to readahead(). On kernels older than v4.10
 * readahead() reads up to 32 pages regardless of the provided length.
 **/
#define READAHEAD_MAX_LENGTH (32 * 4096)

typedef enum pack_flags {
	PACK_ROTATIONAL = 0x01,
} PackFlags;


/* Prototypes for static functions */
static void  print_time          (const char *message, struct timespec *start);
static int   do_readahead_hdd    (PackFile *file, int daemonise);
static void  preload_inode_group (ext2_filsys fs, int group);
static int   do_readahead_ssd    (PackFile *file, int daemonise);
static void *ra_thread           (void *ptr);


char *
pack_file_name (const char *arg)
{
	struct stat statbuf;

	/* If we're not given an argument, fall back to the root pack */
	if (! arg)
		return strdup (PATH_PACKDIR "/pack");

	/* Stat the path given, if it was a file, just return that as the
	 * filename.
	 */
	if (stat (arg, &statbuf) < 0) {
		log_error ("Failed to read stat of file %s: %s",
			   arg, strerror (errno));
		return NULL;
	}

	if (S_ISREG (statbuf.st_mode))
		return strdup (arg);

	/* Otherwise treat it as a mountpoint name */
	return pack_file_name_for_mount (arg);
}

char *
pack_file_name_for_mount (const char *mount)
{
	char *file;
	int written = 0;

	assert (mount != NULL);

	/* Strip the initial slash, if it's the root mountpoint, just return
	 * the default pack filename.
	 */
	if (mount[0] == '/')
		mount++;
	if (mount[0] == '\0')
		return strdup (PATH_PACKDIR "/pack");

	/* Prepend the mount point to the extension, and replace extra /s
	 * with periods.
	 */
	written = asprintf (&file, "%s/%s.pack",
			    PATH_PACKDIR, mount);
	assert (written != -1);
	for (char *ptr = file + strlen (PATH_PACKDIR) + 1; *ptr; ptr++)
		if (*ptr == '/')
			*ptr = '.';

	return file;
}

char *
pack_file_name_for_device (dev_t dev)
{
	FILE *fp;
	char *line = NULL;
	size_t n_line = 0;
	ssize_t bytes_read = 0;

	fp = fopen ("/proc/self/mountinfo", "r");
	if (! fp) {
		log_error ("Failed to open /proc/self/mountinfo: %s",
			   strerror (errno));
		return NULL;
	}

	while((bytes_read = getline (&line, &n_line, fp)) != -1) {
		char *       saveptr;
		char *       ptr;
		char *       device;
		unsigned int maj;
		unsigned int min;
		char *       mount;
		struct stat  statbuf;
		char *       result;

		/* Eliminate the last linebreak if exists. */
		char *end = strrchr (line, '\n');
		if (end)
			*end = '\0';

		/* mount ID */
		ptr = strtok_r (line, " \t\n", &saveptr);
		if (! ptr)
			continue;

		/* parent ID */
		ptr = strtok_r (NULL, " \t\n", &saveptr);
		if (! ptr)
			continue;

		/* major:minor */
		device = strtok_r (NULL, " \t\n", &saveptr);
		if (! device)
			continue;

		/* root */
		ptr = strtok_r (NULL, " \t\n", &saveptr);
		if (! ptr)
			continue;

		/* mount point */
		mount = strtok_r (NULL, " \t\n", &saveptr);
		if (! mount)
			continue;

		/* Check whether this is the right device */
		if (stat (mount, &statbuf) || statbuf.st_dev != dev)
			continue;

		/* Done, convert the mountpoint to a pack filename */
		if (fclose (fp) < 0) {
			free (line);
			log_error ("Failed to close stream of mountinfo: %s",
				   strerror (errno));
			return NULL;
		}

		result = pack_file_name_for_mount (mount);
		free (line);
		return result;
	}

	free (line);
	if (fclose (fp) < 0) {
		log_error ("Failed to close stream of mountinfo: %s",
			   strerror (errno));
		return NULL;
	}

	/* Fell through, can't generate pack file */
	log_error ("Cannot create path for pack file: insufficient data");
	return NULL;
}

static int
load_pages_in_core (int   fd,
		    off_t offset,
		    off_t length)
{
	while (length > 0) {
		const off_t read_length = length <= READAHEAD_MAX_LENGTH ?
			length : READAHEAD_MAX_LENGTH;
		int ret = readahead (fd, offset, read_length);
		if (ret < 0) {
			return ret;
		}
		offset += read_length;
		length -= read_length;
	}
	return 0;
}

void
free_pack_content (PackFile *file)
{
	free (file->groups);
	free (file->paths);
	free (file->blocks);
}

PackFile *
read_pack (const char *filename,
	   int         dump)
{
	struct timespec start;
	FILE *          fp;
	struct stat     stat;
	PackFile *      file;
	char            hdr[8];
	time_t          created;
	char            buf[80];

	assert (filename != NULL);
	clock_gettime (CLOCK_MONOTONIC, &start);

	/* Open the file, and then allocate the PackFile structure for it. */
	fp = fopen (filename, "r");
	if (! fp) {
		log_error ("Failed to open file %s: %s", filename,
			   strerror (errno));
		return NULL;
	}

	/* Obvious really... */
	if (fstat (fileno (fp), &stat) == 0)
		load_pages_in_core (fileno (fp), 0, stat.st_size);

	file = calloc (1, sizeof (PackFile));
	assert (file != NULL);

	/* Read and verify the header */
	if (fread (hdr, 1, 8, fp) < 8) {
		log_debug ("Short read of header");
		goto error;
	}

	if ((hdr[0] != 'u')
	    || (hdr[1] != 'r')
	    || (hdr[2] != 'a')) {
		log_debug ("Header format error");
		goto error;
	}

	if (hdr[3] != 2) {
		log_debug ("Pack version error");
		goto error;
	}

	file->rotational = !!(hdr[4] & PACK_ROTATIONAL);

	if (fread (&file->dev, sizeof file->dev, 1, fp) < 1) {
		log_debug ("Short read of device number");
		goto error;
	}

	if (fread (&created, sizeof created, 1, fp) < 1) {
		log_debug ("Short read of creation time");
		goto error;
	}

	/* If the file is too old, close and ignore it */
	if ((! dump) && (created < (time (NULL) - 86400 * 365))) {
		log_error ("Pack file %s is too old, cannot be used", filename);
		free (file);
		fclose (fp);
		return NULL;
	}

	strftime (buf, sizeof buf, "%a, %d %b %Y %H:%M:%S %z",
		  gmtime (&created));

	log_write (dump ? UREADAHEAD_LOG_MESSAGE : UREADAHEAD_LOG_INFO,
		   "%s: created %s for %s %d:%d", filename, buf,
		   file->rotational ? "hdd" : "ssd",
		   major (file->dev), minor (file->dev));


	/* Read in the number of group entries */
	if (fread (&file->num_groups, sizeof file->num_groups, 1, fp) < 1) {
		log_debug ("Short read of number of group entries");
		goto error;
	}

	file->groups = malloc (sizeof (int) * file->num_groups);
	assert (file->groups != NULL);

	/* Read in the group entries */
	if (fread (file->groups, sizeof (int), file->num_groups, fp) < file->num_groups) {
		log_debug ("Short read of group entries");
		goto error;
	}

	/* Read in the number of path entries */
	if (fread (&file->num_paths, sizeof file->num_paths, 1, fp) < 1) {
		log_debug ("Short read of number of path entries");
		goto error;
	}

	file->paths = malloc (sizeof (PackPath) * file->num_paths);
	assert (file->paths != NULL);

	/* Read in the path entries */
	if (fread (file->paths, sizeof (PackPath), file->num_paths, fp) < file->num_paths) {
		log_debug ("Short read of path entries");
		goto error;
	}

	/* Read in the number of block entries */
	if (fread (&file->num_blocks, sizeof file->num_blocks, 1, fp) < 1) {
		log_debug ("Short read of number of block entries");
		goto error;
	}

	file->blocks = malloc (sizeof (PackBlock) * file->num_blocks);
	assert (file->blocks != NULL);

	/* Read in the block entries */
	if (fread (file->blocks, sizeof (PackBlock), file->num_blocks, fp) < file->num_blocks) {
		log_debug ("Short read of block entries");
		goto error;
	}

	if ((log_minimum_severity <= UREADAHEAD_LOG_INFO) || dump) {
		off_t bytes;

		bytes = 0;
		for (size_t i = 0; i < file->num_blocks; i++)
			bytes += file->blocks[i].length;

		log_write (dump ? UREADAHEAD_LOG_MESSAGE : UREADAHEAD_LOG_INFO,
			   "%zu inode groups, %zu files, %zu blocks (%zu kB)",
			   file->num_groups, file->num_paths, file->num_blocks,
			   (size_t)bytes / 1024);
	}

	/* Done */
	if (fclose (fp) < 0) {
		log_error ("Failed to close file stream for %s: %s",
			   filename, strerror (errno));
		free_pack_content (file);
		free (file);
		return NULL;
	}

	print_time ("Read pack", &start);

	return file;

error:
	log_error ("Failed to read a pack file: content is corrupted or invalid");
	free_pack_content (file);
	free (file);
	fclose (fp);
	return NULL;
}

int
write_pack (const char *filename,
	    PackFile *  file)
{
	int    fd;
	FILE * fp;
	char   hdr[8];
	time_t now;

	assert (filename != NULL);
	assert (file != NULL);

	/* Open the file, making sure we truncate it and give it a
	 * sane mode
	 */
	fd = open (filename, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
	if (fd < 0) {
		log_error ("Failed to open a pack file before writing: %s",
			   strerror (errno));
		return -1;
	}

	fp = fdopen (fd, "w");
	if (! fp) {
		log_error ("Failed to open stream for writing a pack file: %s",
			   strerror (errno));
		close (fd);
		return -1;
	}

	/* Write out the header */
	hdr[0] = 'u';
	hdr[1] = 'r';
	hdr[2] = 'a';

	hdr[3] = 2;

	hdr[4] = 0;
	hdr[4] |= file->rotational ? PACK_ROTATIONAL : 0;

	hdr[5] = hdr[6] = hdr[7] = 0;

	if (fwrite (hdr, 1, 8, fp) < 8)
		goto error;

	if (fwrite (&file->dev, sizeof file->dev, 1, fp) < 1)
		goto error;

	time (&now);
	if (fwrite (&now, sizeof now, 1, fp) < 1)
		goto error;

	/* Write out the number of group entries */
	if (fwrite (&file->num_groups, sizeof file->num_groups, 1, fp) < 1)
		goto error;

	/* Write out the group entries */
	if (fwrite (file->groups, sizeof (int), file->num_groups, fp) < file->num_groups)
		goto error;

	/* Write out the number of path entries */
	if (fwrite (&file->num_paths, sizeof file->num_paths, 1, fp) < 1)
		goto error;

	/* Write out the path entries */
	if (fwrite (file->paths, sizeof (PackPath), file->num_paths, fp) < file->num_paths)
		goto error;

	/* Write out the number of block entries */
	if (fwrite (&file->num_blocks, sizeof file->num_blocks, 1, fp) < 1)
		goto error;

	/* Write out the block entries */
	if (fwrite (file->blocks, sizeof (PackBlock), file->num_blocks, fp) < file->num_blocks)
		goto error;

	if (log_minimum_severity <= UREADAHEAD_LOG_INFO) {
		off_t bytes;

		bytes = 0;
		for (size_t i = 0; i < file->num_blocks; i++)
			bytes += file->blocks[i].length;

		log_info ("%zu inode groups, %zu files, %zu blocks (%zu kB)",
			  file->num_groups, file->num_paths, file->num_blocks,
			  (size_t)bytes / 1024);
	}

	/* Flush, sync and close */
	if ((fflush (fp) < 0)
	    || (fsync (fd) < 0)
	    || (fclose (fp) < 0))
		goto error;

	return 0;
error:
	log_error ("Failed to write a pack file: %s",
		   strerror (errno));
	fclose (fp);
	return -1;
}

static void
print_time (const char *     message,
	    struct timespec *start)
{
 	struct timespec end;
 	struct timespec span;

	assert (message != NULL);
	assert (start != NULL);

	clock_gettime (CLOCK_MONOTONIC, &end);

	span.tv_sec = end.tv_sec - start->tv_sec;
	span.tv_nsec = end.tv_nsec - start->tv_nsec;

	if (span.tv_nsec < 0) {
		span.tv_sec--;
		span.tv_nsec += 1000000000;
	}

	log_info ("%s: %ld.%03lds", message,
		  span.tv_sec, span.tv_nsec / 1000000);

	start->tv_sec = end.tv_sec;
	start->tv_nsec = end.tv_nsec;
}


struct pack_sort {
	size_t    idx;
	PackPath *path;
	off_t     sort;
};

int
pack_sort_compar (const void *a,
		  const void *b)
{
	const struct pack_sort *ps_a;
	const struct pack_sort *ps_b;

	assert (a != NULL);
	assert (b != NULL);

	ps_a = a;
	ps_b = b;

	if (ps_a->sort < ps_b->sort) {
		return -1;
	} else if (ps_a->sort > ps_b->sort) {
		return 1;
	} else {
		return strcmp (ps_a->path->path, ps_b->path->path);
	}
}

void
pack_dump (PackFile * file,
	   SortOption sort)
{
	struct pack_sort *pack = NULL;
	int               page_size;

	assert (file != NULL);

	page_size = sysconf (_SC_PAGESIZE);

	/* Sort the pack file before we dump it */
	pack = malloc (sizeof (struct pack_sort) * file->num_paths);
	assert (pack != NULL);

	for (size_t i = 0; i < file->num_paths; i++) {
		pack[i].idx = i;
		pack[i].path = &file->paths[i];

		switch (sort) {
		case SORT_OPEN:
		case SORT_PATH:
			pack[i].sort = 0;
			break;
		case SORT_DISK:
			pack[i].sort = LLONG_MAX;
			for (size_t j = 0; j < file->num_blocks; j++) {
				if (file->blocks[j].pathidx != pack[i].idx)
					continue;

				pack[i].sort = file->blocks[j].physical;
				break;
			}
			break;
		case SORT_SIZE:
			pack[i].sort = 0;
			for (size_t j = 0; j < file->num_blocks; j++) {
				if (file->blocks[j].pathidx != pack[i].idx)
					continue;

				pack[i].sort += file->blocks[j].length;
			}
			break;
		default:
			__builtin_unreachable ();
		}
	}

	if (sort != SORT_OPEN)
		qsort (pack, file->num_paths, sizeof (struct pack_sort),
		       pack_sort_compar);

	/* Iterated the sorted pack */
	for (size_t i = 0; i < file->num_paths; i++) {
		struct stat statbuf;
		off_t       num_pages;
		size_t      block_count;
		off_t       block_bytes;
		char *      buf = NULL;
		char *      ptr;

		if (stat (pack[i].path->path, &statbuf) < 0) {
			log_warn ("%s: %s", pack[i].path->path,
				  strerror (errno));
			continue;
		}

		num_pages = (statbuf.st_size
			     ? (statbuf.st_size - 1) / page_size + 1
			     : 0);

		buf = malloc (num_pages + 1);
		assert (buf != NULL);
		memset (buf, '.', num_pages);
		buf[num_pages] = '\0';

		block_count = 0;
		block_bytes = 0;

		for (size_t j = 0; j < file->num_blocks; j++) {
			if (file->blocks[j].pathidx != pack[i].idx)
				continue;

			if (file->blocks[j].offset / page_size < num_pages)
				buf[file->blocks[j].offset / page_size] = '@';

			for (off_t k = file->blocks[j].offset / page_size + 1;
			     ((k < (file->blocks[j].offset + file->blocks[j].length) / page_size)
			      && (k < num_pages));
			     k++)
				buf[k] = '#';

			block_count++;
			block_bytes += file->blocks[j].length;
		}

		log_message ("%s (%zu kB), %zu blocks (%zu kB)",
			     pack[i].path->path, (size_t)statbuf.st_size / 1024,
			     block_count, (size_t)block_bytes / 1024);

		ptr = buf;
		while (strlen (ptr) > 74) {
			log_message ("  [%.74s]", ptr);
			ptr += 74;
		}

		if (strlen (ptr))
			log_message ("  [%-74s]", ptr);

		free (buf);
		log_message ("%s", "");

		for (size_t j = 0; j < file->num_blocks; j++) {
			if (file->blocks[j].pathidx != pack[i].idx)
				continue;

			log_message ("\t%zu, %zu bytes (at %zu)",
				     (size_t)file->blocks[j].offset,
				     (size_t)file->blocks[j].length,
				     (size_t)file->blocks[j].physical);
		}

		log_message ("%s", "");
	}

	free (pack);
}


int
do_readahead (PackFile *file,
	      int       daemonise)
{
	int             nr_open;
	struct rlimit   nofile;

	assert (file != NULL);

	/* Increase our maximum file open count so that we can actually
	 * open everything; if the file is larger than the kernel limit,
	 * then silently pretend the rest doesn't exist.
	 */
	if (get_value (AT_FDCWD, "/proc/sys/fs/nr_open", &nr_open) < 0)
		return -1;

	int limit_increase = (nr_open < 10)? nr_open : 10;

	if ((size_t)(nr_open - limit_increase) < file->num_paths) {
		file->num_paths = nr_open - limit_increase;
		log_info ("Truncating to first %zu paths", file->num_paths);
	}

	/* Adjust our resource limits */
	nofile.rlim_cur = limit_increase + file->num_paths;
	nofile.rlim_max = limit_increase + file->num_paths;

	if (setrlimit (RLIMIT_NOFILE, &nofile) < 0) {
		log_error ("Failed to adjust resource limit: %s",
			   strerror (errno));
		return -1;
	}

	if (file->rotational) {
		return do_readahead_hdd (file, daemonise);
	} else {
		return do_readahead_ssd (file, daemonise);
	}
}

static int
do_readahead_hdd (PackFile *file,
		  int       daemonise)
{
	struct timespec start;
	const char *    devname;
	ext2_filsys     fs = NULL;
	int *           fds = NULL;

	assert (file != NULL);

	/* Adjust our CPU and I/O priority, we want to stay in the
	 * foreground and hog all bandwidth to avoid jumping around the
	 * disk.
	 */
	if (setpriority (PRIO_PROCESS, getpid (), -20))
		log_warn ("Failed to set CPU priority: %s",
			  strerror (errno));

	if (syscall (__NR_ioprio_set, IOPRIO_WHO_PROCESS, getpid (),
		     IOPRIO_RT_HIGHEST) < 0)
		log_warn ("Failed to set I/O priority: %s",
			  strerror (errno));

	clock_gettime (CLOCK_MONOTONIC, &start);

	/* Attempt to open the device as an ext2/3/4 filesystem,
	 * and if successful do a bit of pre-loading of inode groups
	 * to speed up opening files.
	 */
	devname = blkid_devno_to_devname (file->dev);
	if (devname
	    && (! ext2fs_open (devname, 0, 0, 0, unix_io_manager, &fs))) {
		assert (fs != NULL);

		for (size_t i = 0; i < file->num_groups; i++)
			preload_inode_group (fs, file->groups[i]);

		ext2fs_close (fs);
	}

	print_time ("Preload ext2fs inodes", &start);

	/* Open all of the files */
	fds = malloc (sizeof (int) * file->num_paths);
	assert (fds != NULL);
	for (size_t i = 0; i < file->num_paths; i++) {
		fds[i] = open (file->paths[i].path, O_RDONLY | O_NOATIME);
		if (fds[i] < 0)
			log_warn ("%s: %s", file->paths[i].path,
				  strerror (errno));
	}

	print_time ("Open files", &start);

	/* Read in all of the blocks in a single pass for rotational
	 * disks, otherwise we'll have a seek time penalty.  For SSD,
	 * use a few threads to read in really fast.
	 */
	for (size_t i = 0; i < file->num_blocks; i++) {
		if ((fds[file->blocks[i].pathidx] < 0)
		    || (file->blocks[i].pathidx >= file->num_paths))
			continue;

		load_pages_in_core (fds[file->blocks[i].pathidx],
				    file->blocks[i].offset,
				    file->blocks[i].length);
	}

	for (size_t i = 0; i < file->num_paths; i++) {
		if (fds[i] < 0)
			continue;
		close(fds[i]);
	}

	free (fds);
	print_time ("Readahead", &start);
	return 0;
}

static void
preload_inode_group (ext2_filsys fs,
		     int         group)
{
	ext2_inode_scan scan = NULL;

	assert (fs != NULL);

	if (! ext2fs_open_inode_scan (fs, 0, &scan)) {
		assert (scan != NULL);

		if (! ext2fs_inode_scan_goto_blockgroup (scan, group)) {
			struct ext2_inode inode;
			ext2_ino_t        ino = 0;

			while ((! ext2fs_get_next_inode (scan, &ino, &inode))
			       && (ext2fs_group_of_ino (fs, ino) == group))
				;
		}

		ext2fs_close_inode_scan (scan);
	}
}


struct thread_ctx {
	PackFile *file;
	size_t    idx;
	int *     got;
};

static int
do_readahead_ssd (PackFile *file,
		  int       daemonise)
{
	struct timespec   start;
	pthread_t         thread[NUM_THREADS];
	struct thread_ctx ctx;

	assert (file != NULL);

	/* Can only --daemon for SSD */
	if (daemonise) {
		pid_t pid;

		pid = fork ();
		if (pid < 0) {
			log_error ("failed to fork: %s", strerror (errno));
			return -1;
		} else if (pid > 0) {
			_exit (0);
		}
	}

	clock_gettime (CLOCK_MONOTONIC, &start);

	ctx.file = file;
	ctx.idx = 0;
	ctx.got = calloc (file->num_paths, sizeof (int));
	assert (ctx.got != NULL);

	for (int t = 0; t < NUM_THREADS; t++)
		pthread_create (&thread[t], NULL, ra_thread, &ctx);
	for (int t = 0; t < NUM_THREADS; t++)
		pthread_join (thread[t], NULL);

	free (ctx.got);

	print_time ("Readahead", &start);

	return 0;
}

static void *
ra_thread (void *ptr)
{
	struct thread_ctx *ctx = ptr;

	if (syscall (__NR_ioprio_set, IOPRIO_WHO_PROCESS, 0,
		     IOPRIO_IDLE_LOWEST) < 0)
		log_warn ("Failed to set I/O priority: %s",
			  strerror (errno));

	for (;;) {
		size_t i;
		size_t pathidx;
		int    fd;

		i = __sync_fetch_and_add (&ctx->idx, 1);
		if (i >= ctx->file->num_blocks)
			break;

		pathidx = ctx->file->blocks[i].pathidx;
		if (pathidx > ctx->file->num_paths)
			continue;

		if (! __sync_bool_compare_and_swap (&ctx->got[pathidx], 0, 1))
			continue;

		fd = open (ctx->file->paths[pathidx].path,
			   O_RDONLY | O_NOATIME);
		if (fd < 0) {
			log_warn ("%s: %s", ctx->file->paths[pathidx].path,
				  strerror (errno));
			continue;
		}

		do {
			load_pages_in_core (fd,
					    ctx->file->blocks[i].offset,
					    ctx->file->blocks[i].length);
		} while ((++i < ctx->file->num_blocks)
			 && (ctx->file->blocks[i].pathidx == pathidx));

		close(fd);
	}

	return NULL;
}
