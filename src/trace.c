/* ureadahead
 *
 * trace.c - boot tracing
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


#include <sys/select.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/syscall.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>

#include <blkid.h>
#define NO_INLINE_FUNCS
#include <ext2fs.h>

#include <linux/fs.h>
#include <linux/fiemap.h>

#include <nih/macros.h>
#include <nih/main.h>
#include <tracefs.h>

#include "trace.h"
#include "pack.h"
#include "values.h"
#include "logging.h"


/**
 * INODE_GROUP_PRELOAD_THRESHOLD:
 *
 * Number of inodes in a group before we preload that inode's blocks.
 **/
#define INODE_GROUP_PRELOAD_THRESHOLD 8

/**
 * Constants for our hash table implementation.
 **/
#define HASH_BITS 16
#define HASH_SIZE (1 << HASH_BITS) // 16384
#define HASH_MASK (HASH_SIZE - 1)

/**
 * FILEMAP_START_MARK:
 *
 * Sentinel value of a file map range array.
 **/
#define FILEMAP_START_MARK	((unsigned long)-1)

/**
 * PAGE_SHIFT:
 *
 * Shift width of a page size (4096)
 **/
#define PAGE_SHIFT	12

#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)

typedef unsigned long long u64;
typedef long long s64;

/* glibc does not define getdents64() */
struct linux_dirent64 {
	u64		d_ino;
	s64		d_off;
	unsigned short	d_reclen;
	unsigned char	d_type;
	char		d_name[];
};
#define getdents64(fd, dirp, count) syscall(SYS_getdents64, fd, buf, BUFSIZ);

/* A half-open file range */
struct file_map {
	/* inclusive */
	off_t				start;
	/* exclusive */
	off_t				end;
};

/* Holds file maps of a file */
struct inode_data {
	struct inode_data		*next;
	unsigned long			inode;
	char				*dev_name;
	/* a sorted array of file maps */
	struct file_map			*map;
	int				nr_maps;
	int				order;
	char				*name;
};

/* Holds a list of inode_data for a device */
struct device_data {
	struct device_data		*next;
	char				*name;
	dev_t				id;
	int				nr_inodes;
	/* a sorted array of inodes */
	struct inode_data		*inodes;
};

/* tep types common to filemap events */
struct filemap_tep {
	struct tep_event	 *event;
	struct tep_format_field  *inode;
	struct tep_format_field  *device;
	struct tep_format_field  *index;
	struct tep_format_field  *last_index; /* May be NULL */
};

/* Hash table entry for processed path bookkeeping. */
struct path_data {
	struct path_data *next;
	size_t length;
	unsigned long hash;
	char path[PACK_PATH_MAX+1];
};

/* Hash table entry for processed dev:inode bookkeeping. */
struct dev_inode_data {
	struct dev_inode_data *next;

	dev_t dev_id;
	ino_t inode;
};

/* Prototypes for static functions */
static int       read_trace          (const char *path_prefix_filter,
				      const PathPrefixOption *path_prefix,
				      PackFile **files, size_t *num_files,
				      int force_ssd_mode);
static void      remove_untouched_blocks  (struct device_data **device_hash,
					  PackFile *file);
static int       read_trace_cb       (struct tep_event *event, struct tep_record *record,
				      int cpu, void *read_trace_context);
static int       read_path_trace     (struct tep_event *event, struct tep_record *record,
				      const char *path_prefix_filter,
				      const PathPrefixOption *path_prefix,
				      PackFile **files, size_t *num_files,
				      int force_ssd_mode);
static int       read_filemap_trace  (struct tep_event *event,
				      struct tep_record *record,
				      struct filemap_tep *fault,
				      struct filemap_tep *get_pages,
				      struct filemap_tep *map_pages,
				      struct device_data **device_hash);
static void      trace_add_file_map  (struct device_data **device_hash,
				      dev_t dev, unsigned long ino,
				      off_t index, off_t last_index);
static void      fix_path            (char *pathname);
static int       trace_add_path      (const char *pathname,
				      PackFile **files, size_t *num_files,
				      int force_ssd_mode);
static int       ignore_path         (const char *pathname);
static PackFile *trace_file          (dev_t dev,
				      PackFile **files, size_t *num_files,
				      int force_ssd_mode);
static int       trace_add_chunks    (PackFile *file, PackPath *path,
				      int fd, off_t size);
static int       trace_add_extents   (PackFile *file, PackPath *path,
				      int fd, off_t size,
				      off_t offset, off_t length);
static int       trace_add_groups    (PackFile *file);
static int       trace_sort_blocks   (PackFile *file);
static int       trace_sort_paths    (PackFile *file);
static void                  add_map            (struct inode_data *inode,
						 off_t index, off_t last_index);
static int		     cmp_file_map_range (const void *A, const void *B);
static int                   cmp_file_map       (const void *A, const void *B);
static struct inode_data    *add_inode          (struct device_data *dev, unsigned long ino);
static struct inode_data    *find_inode         (struct device_data *dev, unsigned long ino);
static int                   cmp_inodes_range   (const void *A, const void *B);
static int                   cmp_inodes         (const void *A, const void *B);
static struct device_data   *add_device         (struct device_data **device_hash, dev_t dev);
static struct device_data   *find_device        (struct device_data **device_hash, dev_t dev);
static void		 add_inodes	(struct device_data **device_hash,
					 PackFile **files, size_t *num_files,
					 int force_ssd_mode);

static int maybe_insert_path (struct path_data **path_table, const char *pathname);
static int maybe_insert_dev_inode_pair (struct dev_inode_data **dev_inode_table,
					dev_t dev_id, ino_t inode);

static inline off_t
min (const off_t a, const off_t b)
{
	return a > b ? b : a;
}

static inline off_t
max (const off_t a, const off_t b)
{
	return a > b ? a : b;
}

static void
sig_interrupt (int signum)
{
}

int
trace (struct trace_context *ctx,
       int daemonise,
       int timeout,
       const char *filename_to_replace,
       const char *pack_file,
       const char *path_prefix_filter,
       const PathPrefixOption *path_prefix,
       int use_existing_trace_events,
       int force_ssd_mode)
{
	struct sigaction  act;
	struct sigaction  old_sigterm;
	struct sigaction  old_sigint;
	struct timeval    tv;
	/* malloc'ed by read_trace, need free */
	PackFile *        files = NULL;
	size_t            num_files = 0;
	int               err = 0;

	if (! use_existing_trace_events) {
		bool failed = false;

		for (int i = 0; i < NR_EVENTS; i++) {
			int ret;
			enum tracefs_enable_state old_state = tracefs_event_is_enabled (NULL, EVENTS[i][0], EVENTS[i][1]);
			ctx->old_events_enabled[i] = (old_state == TRACEFS_ALL_ENABLED || old_state == TRACEFS_SOME_ENABLED);
			ret = tracefs_event_enable (NULL, EVENTS[i][0], EVENTS[i][1]);
			if (ret < 0) {
				if (i < NR_REQUIRED_EVENTS) {
					failed = true;
				} else if (failed && i < NR_ALTERNATE_REQUIRED_EVENTS) {
					log_error ("Failed to enable %s: %s", EVENTS[i][1],
						   strerror (errno));
					return -1;
				}
				log_debug ("Missing %s tracing: %d", EVENTS[i][1], ret);
			}
		}
	}
	/* cpu 0 to get the size per core, assuming all cpus have the same size */
	if ((ctx->old_buffer_size_kb = tracefs_instance_get_buffer_size (NULL, 0)) < 0) {
		log_error ("Failed to get the buffer size: %s",
			   strerror (errno));
		return -1;
	}
	if (tracefs_instance_set_buffer_size (NULL, 8192, -1) < 0) {
		log_error ("Failed to set the buffer size: %s",
			   strerror (errno));
		return -1;
	}
	if ((ctx->old_tracing_enabled = tracefs_trace_is_on (NULL)) < 0) {
		log_error ("Failed to get if the trace is on: %s",
			   strerror (errno));
		return -1;
	}
	if (tracefs_trace_on (NULL) < 0) {
		log_error ("Failed to set the trace on: %s",
			   strerror (errno));
		return -1;
	}

	if (daemonise) {
		pid_t pid;

		pid = fork ();
		if (pid < 0) {
			log_error ("Failed to fork: %s",
				   strerror (errno));
			return -1;
		} else if (pid > 0) {
			_exit (0);
		}
	}

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

	/* Restore previous tracing settings */
	if (ctx->old_tracing_enabled == 0 && tracefs_trace_off (NULL) < 0) {
		log_error ("Failed to set the trace off: %s",
			   strerror (errno));
		return -1;
	}
	if (! use_existing_trace_events) {
		for (int i = 0; i < NR_EVENTS; i++) {
			if (ctx->old_events_enabled[i] > 0)
				continue;
			tracefs_event_disable (NULL,
					       EVENTS[i][0], EVENTS[i][1]);
		}
	}

	/* Be nicer */
	if (nice (15))
		;

	/* Read trace log */
	if (read_trace (path_prefix_filter, path_prefix,
			&files, &num_files, force_ssd_mode) < 0)
		return -1;

	/*
	 * Restore the trace buffer size (which has just been read) and free
	 * a bunch of memory.
	 */
	if (tracefs_instance_set_buffer_size (NULL, ctx->old_buffer_size_kb, -1) < 0) {
		log_error ("Failed to restore the buffer size: %s",
			   strerror (errno));
		free (files);
		return -1;
	}

	/* Write out pack files */
	for (size_t i = 0; i < num_files; i++) {
		char *filename = NULL;
		if (pack_file) {
			filename = strdup (pack_file);
			assert (filename != NULL);
		} else {
			filename = pack_file_name_for_device (files[i].dev);
			if (! filename) {
				log_warn ("Failed to create filename for device %lu",
					  files[i].dev);
				goto free_file_contents;
			}

			/* If filename_to_replace is not NULL, only write out
			 * the file and skip others.
			 */
			if (filename_to_replace &&
			    strcmp (filename_to_replace, filename)) {
				log_info ("Skipping %s", filename);
				goto free_file_contents;
			}
		}
		log_info ("Writing %s", filename);

		/* We only need to apply additional sorting to the
		 * HDD-optimised packs, the SSD ones can read in random
		 * order quite happily.
		 *
		 * Also for HDD, generate the inode group preloading
		 * array.
		 */
		if (files[i].rotational) {
			trace_add_groups (&files[i]);

			trace_sort_blocks (&files[i]);
			trace_sort_paths (&files[i]);
		}

		if (write_pack (filename, &files[i]) < 0)
			log_error ("failed to write a pack file %s", filename);

		if (log_minimum_severity < UREADAHEAD_LOG_MESSAGE)
			pack_dump (&files[i], SORT_OPEN);

free_file_contents:
		free_pack_content (&files[i]);
		free (filename);
	}

	free (files);
	return 0;
}

/* data type for the tracefs_iterate_raw_events callback  */
struct read_trace_context {
	struct tep_event	 *do_sys_open;
	struct tep_event	 *open_exec;
	struct tep_event	 *uselib;
	struct filemap_tep	 filemap_fault;
	struct filemap_tep	 filemap_get_pages;
	struct filemap_tep	 filemap_map_pages;

	const char		 *path_prefix_filter;
	const PathPrefixOption   *path_prefix;
	PackFile		 **files;
	size_t			 *num_files;
	int			 force_ssd_mode;

	struct device_data       *device_hash[HASH_SIZE];
};

static void
init_filemap_tep (struct tep_handle *tep, const char *event_name,
		  struct filemap_tep *filemap)
{
	filemap->event = tep_find_event_by_name (tep, NULL, event_name);
	if (! filemap->event)
		return;
	filemap->inode = tep_find_field (filemap->event, "i_ino");
	assert (filemap->inode != NULL);
	filemap->device = tep_find_field (filemap->event, "s_dev");
	assert (filemap->device != NULL);
	filemap->index = tep_find_field (filemap->event, "index");
	assert (filemap->index != NULL);
	filemap->last_index = tep_find_field (filemap->event, "last_index");
	/* last_index can be NULL since fault does not have it */
}

static void free_device (struct device_data *dev)
{
	struct inode_data *inode;
	int i;

	for (i = 0; i < dev->nr_inodes; i++) {
		inode = &dev->inodes[i];
		/* inode->map has one meta data element at the start */
		inode->map--;
		free (inode->map);
		free (inode->name);
	}
	/* dev->inodes has one meta data element at the start */
	dev->inodes--;
	free (dev->inodes);
	free (dev->name);
	free (dev);
}

static void free_device_hash (struct device_data **device_hash)
{
	struct device_data *dev;
	int i;

	for (i = 0; i < HASH_SIZE; i++) {
		while (device_hash[i]) {
			dev = device_hash[i];
			device_hash[i] = dev->next;
			free_device (dev);
		}
	}
}

static int
read_trace (const char *path_prefix_filter,
	    const PathPrefixOption *path_prefix,
	    PackFile **files, size_t *num_files, int force_ssd_mode)
{
	int err = 0;
	const char *systems[] = { FS_SYSTEM, FILEMAP_SYSTEM, NULL };
	struct tep_handle *tep;
	struct read_trace_context context;

	assert (path_prefix != NULL);
	assert (files != NULL);
	assert (num_files != NULL);

	tep = tracefs_local_events_system (NULL, systems);
	if (!tep) {
		log_error ("Failed to get local events system: %s",
			   strerror (errno));
		return -1;
	}

	context.do_sys_open = tep_find_event_by_name (tep, FS_SYSTEM, "do_sys_open");
	context.open_exec = tep_find_event_by_name (tep, FS_SYSTEM, "open_exec");
	context.uselib = tep_find_event_by_name (tep, FS_SYSTEM, "uselib");
	init_filemap_tep (tep, "mm_filemap_fault", &context.filemap_fault);
	init_filemap_tep (tep, "mm_filemap_map_pages", &context.filemap_map_pages);
	init_filemap_tep (tep, "mm_filemap_get_pages", &context.filemap_get_pages);

	context.path_prefix_filter = path_prefix_filter;
	context.path_prefix = path_prefix;
	context.files = files;
	context.num_files = num_files;
	context.force_ssd_mode = force_ssd_mode;

	memset (context.device_hash, 0, sizeof(context.device_hash));

	if (tracefs_iterate_raw_events (tep, NULL, NULL, 0, read_trace_cb, &context) < 0) {
		log_error ("Failed to iterate raw events: %s",
			   strerror (errno));
		err = -1;
		goto out;
	}

	if (!*num_files) {
		/* Read the inodes directly */
		add_inodes (context.device_hash, files, num_files, force_ssd_mode);
	}

	/* Remove blocks no process touched if we have these events */
	if (context.filemap_fault.event != NULL &&
	    context.filemap_map_pages.event != NULL &&
	    context.filemap_get_pages.event != NULL) {
		for (int i = 0; i < *num_files; i++) {
			remove_untouched_blocks (context.device_hash, &(*files)[i]);
		}
	}

out:
	tep_free (tep);
	free_device_hash (context.device_hash);
	return err;
}

struct dir_stack {
	struct dir_stack		*next;
	char				*dir;
};

static void push_dir(struct dir_stack **dirs, char *dir)
{
	struct dir_stack *d;

	d = malloc(sizeof(*d));
	assert (d != NULL);

	d->dir = strdup(dir);
	assert (d->dir != NULL);

	d->next = *dirs;
	*dirs = d;
}

static char *pop_dir(struct dir_stack **dirs)
{
	struct dir_stack *d = *dirs;
	char *dir;

	if (!d)
		return NULL;

	dir = d->dir;
	*dirs = d->next;
	free(d);

	return dir;
}

/*
 * Given a specific device, map files to the recorded inodes. It doesn't
 * matter if two files have the same inode, only one is needed.
 * The pages pulled in via one of the inode files via the readahead()
 * system call will work for all the inodes files.
 *
 * Returns the number of inodes that were mapped + inos
 */
static int map_inodes(struct device_data *dev, unsigned device, char *fs,
		      struct inode_data **inodes)
{
	struct inode_data *inode;
	char filename[PATH_MAX];
	struct linux_dirent64 *dent;
	struct stat st;
	struct dir_stack *dirs = NULL;
	int found_inos = 0;
	char buf[BUFSIZ];
	int inos = 0;
	char *dir;
	int bpos;
	int fd;
	int n;

	/*
	 * Use a stack instead of recursion to process the files in
	 * an entire directory before going to the next one.
	 */
	push_dir(&dirs, fs);

	while ((dir = pop_dir(&dirs))) {
		/* If we are done, just pop the rest of the dirs */
		if (found_inos == dev->nr_inodes) {
			free(dir);
			continue;
		}

		fd = open(dir, O_RDONLY | O_DIRECTORY);
		if (fd < 0)
			continue;

		/* For root do not append '/' to the files */
		if (dir[1] == '\0')
			dir[0] = '\0';

		for (;;) {
			/* Grab a bunch of entries at once */
			n = getdents64(fd, buf, BUF_SIZE);
			if (n <= 0)
				break;

			for (bpos = 0; bpos < n; bpos += dent->d_reclen) {
				dent = (struct linux_dirent64 *)(buf + bpos);

				if (strcmp(dent->d_name, ".") == 0 ||
				    strcmp(dent->d_name, "..") == 0)
					continue;

				switch(dent->d_type) {
				case DT_DIR:
					if (fstatat(fd, dent->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
						continue;

					/* Make sure we stay on this device */
					if (st.st_dev != device)
						continue;

					snprintf(filename, PATH_MAX,
						 "%s/%s", dir, dent->d_name);
					push_dir(&dirs, filename);

					break;
				case DT_REG:
					inode = find_inode(dev, dent->d_ino);
					if (inode && !inode->name) {
						snprintf(filename, PATH_MAX,
							 "%s/%s", dir, dent->d_name);
						inode->name = strdup(filename);
						assert (inode->name != NULL);
						/* Need to sort the inodes by order */
						inodes[inos++] = inode;
						inode->dev_name = dev->name;
						/*
						 * No need to search more
						 * if we found everything
						 */
						if (++found_inos == dev->nr_inodes)
							goto last;
					}
					break;
				}
			}
		}
 last:
		close(fd);
		free(dir);
	}

	return inos;
}

static int cmp_inode_order(const void *A, const void *B)
{
	struct inode_data * const *a = A;
	struct inode_data * const *b = B;

	if ((*a)->order < (*b)->order)
		return -1;

	return (*a)->order > (*b)->order;
}

static void
add_inodes (struct device_data **device_hash, PackFile **files, size_t *num_files,
	    int force_ssd_mode)
{
	unsigned int major, minor, device;
	struct inode_data **inodes;
	struct device_data *dev;
	char mapname[PATH_MAX];
	char *line = NULL;
	size_t len = 0;
	FILE *fp;
	int inos;
	int ret;
	int i;

	/*
	 * First map the devices found in the trace to the file systems they
	 * represent.
	 */
	fp = fopen("/proc/self/mountinfo", "r");

	while (getline(&line, &len, fp) > 0) {
		ret = sscanf(line, "%*d %*d %d:%d / %"STRINGIFY(PATH_MAX)"s",
			     &major, &minor, mapname);
		if (ret != 3)
			continue;

		device = makedev(major, minor);
		dev = find_device (device_hash, device);
		if (!dev)
			continue;

		/*
		 * Create an array of all the inodes, to sort them in the order they
		 * were found in the trace.
		 */
		inodes = calloc(dev->nr_inodes, sizeof(*inodes));
		assert (inodes != NULL);

		dev->name = strdup(mapname);
		assert(dev->name);

		inos = map_inodes(dev, device, mapname, inodes);

		/* Add the files in order of when they were found */
		qsort(inodes, inos, sizeof(*inodes), cmp_inode_order);

		for (i = 0; i < inos; i++) {
			trace_add_path (inodes[i]->name,
					files, num_files,
					force_ssd_mode);
		}
		free(inodes);

	}
	fclose(fp);
	free(line);
}

static void
remove_untouched_blocks  (struct device_data **device_hash,
			  PackFile *file)
{
	PackBlock *reduced_blocks = NULL;
	size_t num_blocks = 0;

	struct file_map *maps;
	size_t nr_maps = 0;
	size_t filemapidx = 0;
	size_t pathidx = -1;

	/* Iterate both blocks and filemaps in order to get the intersection of them
	 * to drop file ranges that no process read */
	for (int blockidx = 0; blockidx < file->num_blocks; blockidx++) {
		PackBlock *block = &file->blocks[blockidx];
		struct file_map block_range = {
			block->offset >> PAGE_SHIFT,
			(block->offset + block->length) >> PAGE_SHIFT};

		/* Prepare the sorted filemap ranges for the next file */
		if (block->pathidx != pathidx) {
			struct device_data *dev = NULL;
			struct inode_data *inode = NULL;

			pathidx = block->pathidx;
			filemapidx = 0;

			dev = find_device (device_hash, file->dev);
			if (dev)
				inode = find_inode (dev, file->paths[pathidx].ino);

			if (! dev || ! inode) {
				/* A file was opened but not read. We only want dentry. */
				reduced_blocks = realloc (reduced_blocks,
					sizeof(PackBlock) * (++num_blocks));
				assert (reduced_blocks != NULL);
				reduced_blocks[num_blocks - 1].pathidx = block->pathidx;
				reduced_blocks[num_blocks - 1].offset = 0;
				reduced_blocks[num_blocks - 1].length = 0;
				reduced_blocks[num_blocks - 1].physical = 0;

				nr_maps = 0;
				/* The following loops will skip remaining blocks of this path */
				continue;
			}

			maps = inode->map;
			nr_maps = inode->nr_maps;
		}

		/* skip filemaps until we find an overlap with the blocks */
		while (filemapidx < nr_maps &&
			cmp_file_map (&maps[filemapidx], &block_range) < 0)
				filemapidx++;

		/* Add blocks while they overlap with the accessed ranges */
		for (;;) {
			loff_t new_offset, new_end, new_length, new_physical;

			if (filemapidx >= nr_maps)
				break;

			struct file_map *range = &maps[filemapidx];

			if (cmp_file_map (range, &block_range) > 0)
				break;

			new_offset = max (range->start << PAGE_SHIFT, block->offset);
			new_end = min (range->end << PAGE_SHIFT, block->offset + block->length);
			new_length = new_end - new_offset;
			new_physical = block->physical + new_offset - block->offset;

			/* new_length is zero when they touch each other. */
			if (new_length > 0) {
				reduced_blocks = realloc (reduced_blocks,
					sizeof(PackBlock) * (++num_blocks));
				assert (reduced_blocks != NULL);
				reduced_blocks[num_blocks - 1].pathidx = block->pathidx;
				reduced_blocks[num_blocks - 1].offset = new_offset;
				reduced_blocks[num_blocks - 1].length = new_length;
				reduced_blocks[num_blocks - 1].physical = new_physical;
			}

			/* Next block still can overlap with this range. Next blockidx loop. */
			if (range->end > block_range.end)
				break;
			/* Otherwise, see if the next filemap is still in this block. */
			filemapidx++;
		}
	}

	free (file->blocks);
	file->blocks = reduced_blocks;
	file->num_blocks = num_blocks;
}

static int
read_trace_cb  (struct tep_event *event,
	        struct tep_record *record,
	        int cpu, void *read_trace_context)
{
	struct read_trace_context *context = read_trace_context;

	if ((context->do_sys_open && event->id == context->do_sys_open->id) ||
	    (context->open_exec && event->id == context->open_exec->id) ||
	    (context->uselib && event->id == context->uselib->id))
		return read_path_trace (event, record,
				        context->path_prefix_filter,
					context->path_prefix,
				        context->files, context->num_files,
				        context->force_ssd_mode);

	if ((context->filemap_fault.event && event->id == context->filemap_fault.event->id) ||
	    (context->filemap_get_pages.event && event->id == context->filemap_get_pages.event->id) ||
	    (context->filemap_map_pages.event && event->id == context->filemap_map_pages.event->id))
		return read_filemap_trace (event, record,
				           &context->filemap_fault,
					   &context->filemap_get_pages,
					   &context->filemap_map_pages,
					   context->device_hash);

	return 0;
}

static int
read_path_trace  (struct tep_event *event, struct tep_record *record,
	          const char *path_prefix_filter,
	          const PathPrefixOption *path_prefix,
	          PackFile **files, size_t *num_files,
	          int force_ssd_mode)
{
	char *path, *tep_path = NULL;
	int   len;

	tep_path = tep_get_field_raw(NULL, event, "filename", record, &len, 0);
	if (! tep_path) {
		log_warn ("Field 'filename' not found for event %s", event->name);
		return 0;
	}

	path = strndup(tep_path, len);
	if (! path) {
		log_error ("strndup failed: %s", strerror (errno));
		return -1;
	}

	fix_path (path);

	if (path_prefix_filter &&
		strncmp (path, path_prefix_filter,
				strlen (path_prefix_filter))) {
		log_warn ("Skipping %s due to path prefix filter", path);
		goto out;
	}

	if (path_prefix->st_dev != NODEV && path[0] == '/') {
		struct stat stbuf;
		char *rewritten;
		asprintf (&rewritten,
			  "%s%s", path_prefix->prefix, path);
		if (! lstat (rewritten, &stbuf) &&
			stbuf.st_dev == path_prefix->st_dev) {
				/* If |rewritten| exists on the same device as
				 * path_prefix->st_dev, record the rewritten one
				 * instead of the original path.
				 */
			free (path);
			path = rewritten;
		}
	}
	trace_add_path (path, files, num_files, force_ssd_mode);

out:
	free (path);

	return 0;
}

static void
fix_path (char *pathname)
{
	char *ptr;

	assert (pathname != NULL);

	for (ptr = pathname; *ptr; ptr++) {
		size_t len;

		if (ptr[0] != '/')
			continue;

		len = strcspn (ptr + 1, "/");

		/* // and /./, we shorten the string and repeat the loop
		 * looking at the new /
		 */
		if ((len == 0) || ((len == 1) && ptr[1] == '.')) {
			memmove (ptr, ptr + len + 1, strlen (ptr) - len);
			ptr--;
			continue;
		}

		/* /../, we shorten back to the previous / or the start
		 * of the string and repeat the loop looking at the new /
		 */
		if ((len == 2) && (ptr[1] == '.') && (ptr[2] == '.')) {
			char *root;

			for (root = ptr - 1;
			     (root >= pathname) && (root[0] != '/');
			     root--)
				;
			if (root < pathname)
				root = pathname;

			memmove (root, ptr + len + 1, strlen (ptr) - len);
			ptr = root - 1;
			continue;
		}
	}

	while ((ptr != pathname) && (*(--ptr) == '/'))
		*ptr = '\0';
}


static int
trace_add_path (const char *pathname,
		PackFile ** files,
		size_t *    num_files,
		int         force_ssd_mode)
{
	struct stat     statbuf;
	int             fd;
	PackFile *      file;
	PackPath *      path;
	static struct dev_inode_data **inode_hash = NULL;
	static struct path_data **path_hash = NULL;

	/* Used when the file to be included turns out
	 * to be a symlink.
	 * stores a resolved path from the symlink.
	 */
	static char resolved_pathname[PATH_MAX];

	assert (pathname != NULL);
	assert (files != NULL);
	assert (num_files != NULL);

	/* We can't really deal with relative paths since we don't know
	 * the working directory that they were opened from.
	 */
	if (pathname[0] != '/') {
		log_warn ("%s: %s", pathname, _("Ignored relative path"));
		return 0;
	}

	/* Certain paths aren't worth caching, because they're virtual or
	 * temporary filesystems and would waste pack space.
	 */
	if (ignore_path (pathname))
		return 0;

	/* Ignore paths that won't fit in the pack; we could use PATH_MAX,
	 * but with 1000 files that'd be 4M just for the
	 * pack.
	 */
	if (strlen (pathname) > PACK_PATH_MAX) {
		log_warn ("%s: %s", pathname, _("Ignored far too long path"));
		return 0;
	}

	/* Use a hash table of paths to eliminate duplicate path names from
	 * the table since that would waste pack space (and fds).
	 */
	if (! path_hash) {
		path_hash = calloc (HASH_SIZE, sizeof (struct path_data *));
		assert (path_hash != NULL);
	}

	/* Try to insert a new path into hash table,
	 * or abort in case if it already exists (processed).
	 */
	if (! maybe_insert_path (path_hash, pathname))
		return 0;

	/* Start checking the file type to see if it can be
	 * resolved down to some ordinary file.
	 */
	if (lstat (pathname, &statbuf) < 0)
		return 0;

	/* Check if it is a symlink,
	 * and resolve to a file that symlink points to.
	 */
	if (S_ISLNK (statbuf.st_mode)) {
		if (! realpath (pathname, resolved_pathname))
			return 0;

		pathname = resolved_pathname;

		/* Prevent resolved_path_name from going above
		 * PACK_PATH_MAX.
		 */
		if (strlen (resolved_pathname) > PACK_PATH_MAX) {
			log_warn ("%s: %s", resolved_pathname, _("Ignored far too long path"));
			return 0;
		}

		if (! maybe_insert_path (path_hash, resolved_pathname))
			return 0;

		/* Update statbuf with the actual information of the file
		 * that symlink points to.
		 */
		if (stat (resolved_pathname, &statbuf) < 0)
			return 0;
	}

	if (! S_ISREG (statbuf.st_mode))
		return 0;

	/* Open and stat again to get the genuine details, in case it
	 * changes under us.
	 */
	fd = open (pathname, O_RDONLY | O_NOATIME);
	if (fd < 0) {
		log_warn ("%s: %s: %s", pathname,
			  _("File vanished or error reading"),
			  strerror (errno));
		return -1;
	}

	if (fstat (fd, &statbuf) < 0) {
		log_warn ("%s: %s: %s", pathname,
			  _("Error retrieving file stat"),
			  strerror (errno));
		close (fd);
		return -1;
	}

	/* Double-check that it's really still a file */
	if (! S_ISREG (statbuf.st_mode)) {
		close (fd);
		return 0;
	}

	/* Some people think it's clever to split their filesystem across
	 * multiple devices, so we need to generate a different pack file
	 * for each device.
	 *
	 * Lookup file based on the dev_t, potentially creating a new
	 * pack file in the array.
	 */
	file = trace_file (statbuf.st_dev, files, num_files, force_ssd_mode);

	/* Grow the PackPath array and fill in the details for the new
	 * path.
	 */
	file->paths = realloc (file->paths,
			       (sizeof (PackPath)
			        * (file->num_paths + 1)));
	assert (file->paths != NULL);

	path = &file->paths[file->num_paths++];
	memset (path, 0, sizeof (PackPath));

	path->group = -1;
	path->ino = statbuf.st_ino;

	strncpy (path->path, pathname, PACK_PATH_MAX);
	path->path[PACK_PATH_MAX] = '\0';

	/* The paths array contains each unique path opened, but these
	 * might be symbolic or hard links to the same underlying files
	 * and we don't want to read the same block more than once.
	 *
	 * Use a hash table of dev_t/ino_t pairs to make sure we only
	 * read the blocks of an actual file the first time.
	 */
	if (! inode_hash) {
		inode_hash = calloc (HASH_SIZE, sizeof (struct dev_inode_data *));
		assert (inode_hash != NULL);
	}

	if (! maybe_insert_dev_inode_pair (inode_hash, statbuf.st_dev, statbuf.st_ino))
		return 0;

	/* There's also no point reading zero byte files, since they
	 * won't have any blocks (and we can't mmap zero bytes anyway).
	 */
	if (! statbuf.st_size) {
		close (fd);
		return 0;
	}

	/* Now read the in-memory chunks of this file and add those to
	 * the pack file too.
	 */
	trace_add_chunks (file, path, fd, statbuf.st_size);
	close (fd);

	return 0;
}

static int
ignore_path (const char *pathname)
{
	assert (pathname != NULL);

	if (! strncmp (pathname, "/proc/", 6))
		return TRUE;
	if (! strncmp (pathname, "/sys/", 5))
		return TRUE;
	if (! strncmp (pathname, "/dev/", 5))
		return TRUE;
	if (! strncmp (pathname, "/tmp/", 5))
		return TRUE;
	if (! strncmp (pathname, "/run/", 5))
		return TRUE;
	if (! strncmp (pathname, "/var/run/", 9))
		return TRUE;
	if (! strncmp (pathname, "/var/log/", 9))
		return TRUE;
	if (! strncmp (pathname, "/var/lock/", 10))
		return TRUE;

	return FALSE;
}


static PackFile *
trace_file (dev_t       dev,
	    PackFile ** files,
	    size_t *    num_files,
	    int         force_ssd_mode)
{
	char *          filename = NULL;
	int             rotational;
	PackFile *      file;
	int             written;

	assert (files != NULL);
	assert (num_files != NULL);

	/* Return any existing file structure for this device */
	for (size_t i = 0; i < *num_files; i++)
		if ((*files)[i].dev == dev)
			return &(*files)[i];

	if (force_ssd_mode) {
		rotational = FALSE;
	} else {
		/* Query sysfs to see whether this disk is rotational; this
		 * obviously won't work for virtual devices and the like, so
		 * default to TRUE for now.
		 */
		written = asprintf (&filename, "/sys/dev/block/%d:%d/queue/rotational",
				    major (dev), minor (dev));
		assert (written != -1);
		if (access (filename, R_OK) < 0) {
			/* For devices managed by the scsi stack, the minor device number has to be
			 * masked to find the queue/rotational file.
			 */
			free (filename);
			written = asprintf (&filename, "/sys/dev/block/%d:%d/queue/rotational",
					     major (dev), minor (dev) & 0xffff0);
			assert (written != -1);
		}

		if (get_value (AT_FDCWD, filename, &rotational) < 0) {
			log_warn (_("Unable to obtain rotationalness for device %u:%u"),
				major (dev), minor (dev));
			rotational = TRUE;
		}
	}

	/* Grow the PackFile array and fill in the details for the new
	 * file.
	 */
	*files = realloc (*files, sizeof (PackFile) * (*num_files + 1));
	assert (*files != NULL);

	file = &(*files)[(*num_files)++];
	memset (file, 0, sizeof (PackFile));

	file->dev = dev;
	file->rotational = rotational;
	file->num_paths = 0;
	file->paths = NULL;
	file->num_blocks = 0;
	file->blocks = NULL;

	free (filename);

	return file;
}


static int
trace_add_chunks (PackFile *file,
		  PackPath *path,
		  int       fd,
		  off_t     size)
{
	static int    page_size = -1;
	void *        buf;
	off_t         num_pages;
	unsigned char *vec = NULL;

	assert (file != NULL);
	assert (path != NULL);
	assert (fd >= 0);
	assert (size > 0);

	if (page_size < 0)
		page_size = sysconf (_SC_PAGESIZE);

	/* Map the file into memory */
	buf = mmap (NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		log_warn ("%s: %s: %s", path->path,
			  _("Error mapping into memory"),
			  strerror (errno));
		return -1;
	}

	/* Grab the core memory map of the file */
	num_pages = (size - 1) / page_size + 1;
	vec = malloc (num_pages);
	assert (vec != NULL);
	memset (vec, 0, num_pages);

	if (mincore (buf, size, vec) < 0) {
		log_warn ("%s: %s: %s", path->path,
			  _("Error retrieving page cache info"),
			  strerror (errno));
		munmap (buf, size);
		free (vec);
		return -1;
	}

	/* Clean up */
	if (munmap (buf, size) < 0) {
		log_warn ("%s: %s: %s", path->path,
			  _("Error unmapping from memory"),
			  strerror (errno));
		free (vec);
		return -1;
	}


	/* Now we can figure out which contiguous bits of the file are
	 * in core memory.
	 */
	for (off_t i = 0; i < num_pages; i++) {
		off_t offset;
		off_t length;

		if (! vec[i])
			continue;

		offset = i * page_size;
		length = page_size;

		while (((i + 1) < num_pages) && vec[i + 1]) {
			length += page_size;
			i++;
		}

		/* The rotational crowd need this split down further into
		 * on-disk extents, the non-rotational folks can just use
		 * the chunks data.
		 */
		if (file->rotational) {
			trace_add_extents (file, path, fd, size,
					   offset, length);
		} else {
			PackBlock *block;

			file->blocks = realloc (file->blocks,
						(sizeof (PackBlock)
						* (file->num_blocks + 1)));
			assert (file->blocks != NULL);

			block = &file->blocks[file->num_blocks++];
			memset (block, 0, sizeof (PackBlock));

			block->pathidx = file->num_paths - 1;
			block->offset = offset;
			block->length = length;
			block->physical = -1;
		}
	}
	free (vec);

	return 0;
}

struct fiemap *
get_fiemap (int   fd,
	    off_t offset,
	    off_t length)
{
	struct fiemap *fiemap;

	assert (fd >= 0);

	fiemap = calloc (1, sizeof (struct fiemap));
	assert (fiemap != NULL);

	fiemap->fm_start = offset;
	fiemap->fm_length = length;
	fiemap->fm_flags = 0;

	do {
		/* Query the current number of extents */
		fiemap->fm_mapped_extents = 0;
		fiemap->fm_extent_count = 0;

		if (ioctl (fd, FS_IOC_FIEMAP, fiemap) < 0) {
			log_error ("failed to query file extents: %s",
				   strerror(errno));
			free (fiemap);
			return NULL;
		}

		/* Always allow room for one extra over what we were told,
		 * so we know if they changed under us.
		 */
		fiemap = realloc (fiemap,
				  (sizeof (struct fiemap)
				  + (sizeof (struct fiemap_extent)
				     * (fiemap->fm_mapped_extents + 1))));

		assert (fiemap != NULL);
		fiemap->fm_extent_count = fiemap->fm_mapped_extents + 1;
		fiemap->fm_mapped_extents = 0;

		memset (fiemap->fm_extents, 0, (sizeof (struct fiemap_extent)
						* fiemap->fm_extent_count));

		if (ioctl (fd, FS_IOC_FIEMAP, fiemap) < 0) {
			log_error ("failed to query file extents: %s",
				   strerror(errno));
			free (fiemap);
			return NULL;
		}
	} while (fiemap->fm_mapped_extents
		 && (fiemap->fm_mapped_extents >= fiemap->fm_extent_count));

	return fiemap;
}

static int
trace_add_extents (PackFile *file,
		   PackPath *path,
		   int       fd,
		   off_t     size,
		   off_t     offset,
		   off_t     length)
{
	struct fiemap *fiemap = NULL;

	assert (file != NULL);
	assert (path != NULL);
	assert (fd >= 0);
	assert (size > 0);

	/* Get the extents map for this chunk, then iterate the extents
	 * and put those in the pack instead of the chunks.
	 */
	fiemap = get_fiemap (fd, offset, length);
	if (! fiemap) {
		log_warn ("Error retrieving chunk extents for %s", path->path);
		return -1;
	}

	for (__u32 j = 0; j < fiemap->fm_mapped_extents; j++) {
		PackBlock *block;
		off_t      start;
		off_t      end;

		if (fiemap->fm_extents[j].fe_flags & FIEMAP_EXTENT_UNKNOWN)
			continue;

		/* Work out the intersection of the chunk and extent */
		start = max (fiemap->fm_start,
				 fiemap->fm_extents[j].fe_logical);
		end = min ((fiemap->fm_start + fiemap->fm_length),
			       (fiemap->fm_extents[j].fe_logical
				+ fiemap->fm_extents[j].fe_length));

		/* Grow the blocks array to add the extent */
		file->blocks = realloc (file->blocks,
					(sizeof (PackBlock)
					 * (file->num_blocks + 1)));
		assert (file->blocks != NULL);

		block = &file->blocks[file->num_blocks++];
		memset (block, 0, sizeof (PackBlock));

		block->pathidx = file->num_paths - 1;
		block->offset = start;
		block->length = end - start;
		block->physical = (fiemap->fm_extents[j].fe_physical
				   + (start - fiemap->fm_extents[j].fe_logical));
	}

	free (fiemap);

	return 0;
}

static int
trace_add_groups (PackFile *file)
{
	const char *devname;
	ext2_filsys fs = NULL;

	assert (file != NULL);

	devname = blkid_devno_to_devname (file->dev);
	if (devname
	    && (! ext2fs_open (devname, 0, 0, 0, unix_io_manager, &fs))) {
		size_t  num_groups = 0;
		size_t *num_inodes = NULL;
		size_t  mean = 0;
		size_t  hits = 0;

		assert (fs != NULL);

		/* Calculate the number of inode groups on this filesystem */
		num_groups = ((fs->super->s_blocks_count - 1)
			      / fs->super->s_blocks_per_group) + 1;

		/* Fill in the pack path's group member, and count the
		 * number of inodes in each group.
		 */
		num_inodes = calloc (num_groups, sizeof (size_t));
		assert (num_inodes != NULL);

		for (size_t i = 0; i < file->num_paths; i++) {
			file->paths[i].group = ext2fs_group_of_ino (fs, file->paths[i].ino);
			num_inodes[file->paths[i].group]++;
		}

		/* Iterate the groups and add any group that exceeds the
		 * inode preload threshold.
		 */
		for (size_t i = 0; i < num_groups; i++) {
			mean += num_inodes[i];
			if (num_inodes[i] > INODE_GROUP_PRELOAD_THRESHOLD) {
				file->groups = realloc (file->groups,
							(sizeof (int)
							 * (file->num_groups + 1)));
				assert (file->groups != NULL);
				file->groups[file->num_groups++] = i;
				hits++;
			}
		}

		mean /= num_groups;

		log_debug ("%zu inode groups, mean %zu inodes per group, %zu hits",
			   num_groups, mean, hits);

		free (num_inodes);
		ext2fs_close (fs);
	}

	return 0;
}


static int
block_compar (const void *a,
	      const void *b)
{
	const PackBlock *block_a = a;
	const PackBlock *block_b = b;

	assert (block_a != NULL);
	assert (block_b != NULL);

	if (block_a->physical < block_b->physical) {
		return -1;
	} else if (block_a->physical > block_b->physical) {
		return 1;
	} else {
		return 0;
	}
}

static int
trace_sort_blocks (PackFile *file)
{
	assert (file != NULL);

	/* Sort the blocks array by physical location, since these are
	 * read in a separate pass to opening files, there's no reason
	 * to consider which path each block is in - and thus resulting
	 * in a linear disk read.
	 */
	qsort (file->blocks, file->num_blocks, sizeof (PackBlock),
	       block_compar);

	return 0;
}

static int
path_compar (const void *a,
	     const void *b)
{
	const PackPath * const *path_a = a;
	const PackPath * const *path_b = b;

	assert (path_a != NULL);
	assert (path_b != NULL);

	if ((*path_a)->group < (*path_b)->group) {
		return -1;
	} else if ((*path_a)->group > (*path_b)->group) {
		return 1;
	} else if ((*path_a)->ino < (*path_b)->ino) {
		return -1;
	} else if ((*path_b)->ino > (*path_b)->ino) {
		return 1;
	} else {
		return strcmp ((*path_a)->path, (*path_b)->path);
	}
}

static int
trace_sort_paths (PackFile *file)
{
	PackPath **paths = NULL;
	size_t *   new_idx = NULL;
	PackPath * new_paths;

	assert (file != NULL);

	/* Sort the paths array by ext2fs inode group, ino_t then path.
	 *
	 * Mucking around with things like the physical locations of
	 * first on-disk blocks of the dentry and stuff didn't work out
	 * so well, sorting by path was better, but this seems the best.
	 * (it looks good on blktrace too)
	 */
	paths = malloc (sizeof (PackPath *) * file->num_paths);
	assert (paths != NULL);

	for (size_t i = 0; i < file->num_paths; i++)
		paths[i] = &file->paths[i];

	qsort (paths, file->num_paths, sizeof (PackPath *),
	       path_compar);

	/* Calculate the new indexes of each path element in the old
	 * array, and then update the block array's path indexes to
	 * match.
	 */
	new_idx = malloc (sizeof (size_t) * file->num_paths);
	assert (new_idx != NULL);
	for (size_t i = 0; i < file->num_paths; i++)
		new_idx[paths[i] - file->paths] = i;

	for (size_t i = 0; i < file->num_blocks; i++)
		file->blocks[i].pathidx = new_idx[file->blocks[i].pathidx];

	/* Finally generate a new paths array with the new order and
	 * attach it to the file.
	 */
	new_paths = malloc (sizeof (PackPath) * file->num_paths);
	assert (new_paths != NULL);
	for (size_t i = 0; i < file->num_paths; i++)
		memcpy (&new_paths[new_idx[i]], &file->paths[i],
			sizeof (PackPath));

	free (file->paths);
	file->paths = new_paths;

	free (paths);
	free (new_idx);
	return 0;
}

/* This gets called for every flemap event in the ring buffer in order */
static int read_filemap_trace  (struct tep_event *event,
				struct tep_record *record,
				struct filemap_tep *fault,
				struct filemap_tep *get_pages,
				struct filemap_tep *map_pages,
				struct device_data **device_hash)
{
	unsigned long long ino;
	unsigned long long device;
	unsigned long long index;
	unsigned long long last_index;
	int major, minor;

	struct filemap_tep *tep;

	if (event->id == fault->event->id)
		tep = fault;
	else if (event->id == get_pages->event->id)
		tep = get_pages;
	else if (event->id == map_pages->event->id)
		tep = map_pages;
	else
		return 1;

	if (tep_read_number_field (tep->inode, record->data, &ino) < 0)
		return 1;

	if (tep_read_number_field (tep->device, record->data, &device) < 0)
		return 1;

	if (tep_read_number_field (tep->index, record->data, &index) < 0)
		return 1;

	if (tep->last_index) {
		if (tep_read_number_field (tep->last_index, record->data, &last_index) < 0)
			return 1;
	} else {
		last_index = index;
	}

	/* The major bit shift is 20 in the trace. */
	major = device >> 20;
	minor = device & 0xff;

	trace_add_file_map (device_hash, makedev (major, minor), ino, index, last_index);

	return 0;
}

/*
 * The mm_filemap_add_to_page_cache event was read and gives the device, inode number,
 * and page index. Note the offset into the file that this page is for is found by:
 *  offset = index * page_size
 */
static void trace_add_file_map (struct device_data **device_hash,
				dev_t dev_id, unsigned long ino,
				off_t index, off_t last_index)
{
	struct device_data *dev;
	struct inode_data *inode;
	struct file_map *map, *lower_bound, *upper_bound;
	struct file_map key;
	int idx;

	dev = find_device (device_hash, dev_id);
	if (! dev)
		dev = add_device (device_hash, dev_id);

	inode = find_inode (dev, ino);
	if (! inode)
		inode = add_inode (dev, ino);

	key.start = index;
	key.end = last_index + 1; /* make it a half-open interval */

	/*
	 * The cmp_file_map will match not only if it finds a mapping that the
	 * index is in, but also if the index is at the end of a mapping or
	 * the begging of one. In the latter case, it will return the mapping
	 * that touchs the index.
	 */
	map = bsearch (&key, inode->map, inode->nr_maps, sizeof(key), cmp_file_map);
	if (! map) {
		/* A new index that also does not touch a mapping. */
		add_map (inode, index, last_index);
		return;
	}

	if (map->start <= key.start && map->end >= key.end)
		/* Nothing to do, it is already accounted for */
		return;

	/* find the lower/upper bound of matching ranges. The length usually is 1 or
	 * 2 , so linear search is efficient enough. */
	lower_bound = map;
	upper_bound = map;
	while (lower_bound - 1 >= inode->map && cmp_file_map (lower_bound - 1, &key) == 0)
		lower_bound--;
	map = upper_bound;
	while (upper_bound + 1 < inode->map + inode->nr_maps && cmp_file_map (upper_bound + 1, &key) == 0)
		upper_bound++;

	/* extend the first map to the new range */
	lower_bound->start = min (lower_bound->start, key.start);
	lower_bound->end = max (upper_bound->end, key.end);

	/* If there's only one overlapping, then we are done */
	if (lower_bound == upper_bound)
		return;

	/* remove the merged maps */
	idx = upper_bound - inode->map;
	/* If the upper_bound map was not at the end, then adjust the inode map array */
	if (idx < inode->nr_maps - 1)
		memmove (lower_bound + 1, upper_bound + 1, sizeof(*map) * (inode->nr_maps - idx - 1));
	inode->nr_maps -= upper_bound - lower_bound;
}

/* Returns a match if A is within or touches B. */
static int cmp_file_map (const void *A, const void *B)
{
	const struct file_map *a = A;
	const struct file_map *b = B;

	if (a->end < b->start)
		return -1;

	return b->end < a->start;
}

/*
 * Insert this new index into the inode array.
 * Note, the inode array has a meta data element before it that has
 * FILEMAP_START_MARK as it's "start" element. This is to help the
 * cmp_file_map_range() function to know if the new index is between
 * two other indexes, as it returns the mapping after the index when
 * the index is before it. To do so, it needs to check the element before the
 * element being tested. In order to test the first element (without knowing
 * that it is on the first element), it needs to look before that element.
 * The FILEMAP_START_MARK element will be the element before the first one.
 */
static void add_map (struct inode_data *inode, off_t index, off_t last_index)
{
	struct file_map *map;
	struct file_map key;
	int idx;

	/* Handle the first two trivial cases */
	switch (inode->nr_maps) {
	case 0:
		/* Allocate 2: 1 for this element an 1 for the FILEMAP_START_MARK */
		map = calloc (sizeof(*inode->map), 2);
		assert (map != NULL);

		/* Add a buffer element at the beginning for cmp_file_map_range() */
		map->start = FILEMAP_START_MARK;
		/* The inode->map will skip over that element */
		map++;
		inode->map = map;
		break;
	case 1:
		/* The allocated array starts one element before the inode->map */
		map = inode->map - 1;
		/* Allocate three. 2 for the elements and one for the FILEMAP_START_MARK */
		map = realloc (map, sizeof(*inode->map) * 3);
		assert (map != NULL);

		inode->map = map + 1;

		/* If the current element is greater than the new one, then move it */
		if (inode->map[0].start > index) {
			inode->map[1] = inode->map[0];
			map = &inode->map[0];
		} else
			map = &inode->map[1];
		break;
	default:
		key.start = index;
		/* convert it from an inclusive interval to a half-open interval */
		key.end = last_index + 1;

		/*
		 * The cmp_file_map_range() will return the map that is after
		 * the index (or NULL if the index is greater than all existing
		 * maps).
		 */
		map = bsearch (&key, inode->map, inode->nr_maps, sizeof(*map),
			       cmp_file_map_range);
		/*
		 * Find the index into the array that this new map index will
		 * be inserted.
		 */
		if (map)
			idx = map - inode->map;
		else
			idx = inode->nr_maps;
		/* Set map to the start of the allocation */
		map = inode->map - 1;
		map = realloc (map, sizeof(*map) * (inode->nr_maps + 2));
		assert (map != NULL);
		map++;
		inode->map = map;

		/* If the new index is not at the end, make room for it */
		if (idx < inode->nr_maps)
			memmove (&map[idx + 1], &map[idx],
				 sizeof(*map) * (inode->nr_maps - idx));
		map = &map[idx];
	}
	map->start = index;
	/* convert it from an inclusive interval to a half-open interval */
	map->end = last_index + 1;
	inode->nr_maps++;
}

/*
 * Range is called when the offset does not touch any of the
 * existing mappings.
 *
 * Returns NULL, if A is bigger than all the other elements.
 * Otherwise, returns the element just after A.
 */
static int cmp_file_map_range (const void *A, const void *B)
{
	const struct file_map *a = A;
	const struct file_map *b2 = B;
	const struct file_map *b1 = b2 - 1;

	if (a->end < b2->start) {
		/* Check if a is between b1 and b2 */
		if (b1->start == FILEMAP_START_MARK || a->start > b1->end)
			return 0;
		else
			return -1;
	}

	/*
	 * This is only called when a search failed,
	 * so a should never be within b.
	 * If we are here, then a > b.
	 */
	return 1;
}

/*
 * add_inode() works the same as add_map() above. Where it creates an
 * array that has a meta element at the start to use for searching
 * for the location between to other elements.
 */
static struct inode_data *add_inode (struct device_data *dev, unsigned long ino)
{
	struct inode_data *inode;
	struct inode_data key;
	int index;

	switch (dev->nr_inodes) {
	case 0:
		/* Add a marker to the beginning of the array for the range compare */
		inode = calloc (sizeof(key), 2);
		assert (inode != NULL);
		inode->inode = FILEMAP_START_MARK;
		inode++;
		dev->inodes = inode;
		break;
	case 1:
		inode = dev->inodes - 1;
		inode = realloc (inode, sizeof(key) * 3);
		assert (inode != NULL);
		dev->inodes = inode + 1;

		/* If the current element is greater than the new one, then move it */
		if (dev->inodes[0].inode > ino) {
			dev->inodes[1] = dev->inodes[0];
			inode = &dev->inodes[0];
		} else
			inode = &dev->inodes[1];
		break;
	default:
		key.inode = ino;

		/*
		 * Returns the inode after the current one, or NULL
		 * if it's the first one.
		 */
		inode = bsearch (&key, dev->inodes, dev->nr_inodes, sizeof(key),
			         cmp_inodes_range);
		if (inode)
			index = inode - dev->inodes;
		else
			index = dev->nr_inodes;

		/* Set to the start of the allocated array */
		inode = dev->inodes - 1;
		inode = realloc (inode, sizeof(key) * (dev->nr_inodes + 2));
		assert (inode != NULL);
		inode++;
		dev->inodes = inode;

		/* Make room for the new inode if it's not at the end of the array */
		if (index < dev->nr_inodes)
			memmove (&inode[index + 1], &inode[index],
				 sizeof(key) * (dev->nr_inodes - index));
		inode = &inode[index];
	}
	memset (inode, 0, sizeof(*inode));
	inode->inode = ino;
	/* Keep track of the order of inodes as they are found */
	inode->order = dev->nr_inodes++;
	return inode;
}

/*
 * Compare to cause bsearch to:
 *
 * Return NULL, if A is bigger than all the other elements.
 * Otherwise, return the element just after A.
 */
static int cmp_inodes_range (const void *A, const void *B)
{
	const struct inode_data *a = A;
	const struct inode_data *b2 = B;
	const struct inode_data *b1 = b2 - 1;

	if (a->inode < b2->inode) {
		/* if a is between b1 and b2, then it's a match */
		if (b1->inode == FILEMAP_START_MARK || a->inode > b1->inode)
			return 0;
		else
			return -1;
	}

	/*
	 * This is only called when a search failed,
	 * so a->inode should never equal b->node.
	 * If we are here, then a > b.
	 */
	return 1;
}

static struct inode_data *find_inode (struct device_data *dev, unsigned long ino)
{
	struct inode_data key;

	key.inode = ino;

	/* Returns a map that just touches the offset */
	return bsearch (&key, dev->inodes, dev->nr_inodes, sizeof(key), cmp_inodes);
}

static int cmp_inodes (const void *A, const void *B)
{
	const struct inode_data *a = A;
	const struct inode_data *b = B;

	if (a->inode < b->inode)
		return -1;

	return a->inode > b->inode;
}

static struct device_data *add_device (struct device_data **device_hash,
				       dev_t id)
{
	struct device_data *dev;
	int key = id & HASH_MASK;

	dev = calloc (1, sizeof(*dev));
	assert (dev != NULL);

	dev->id = id;
	dev->next = device_hash[key];
	device_hash[key] = dev;

	return dev;
}

static struct device_data *find_device (struct device_data **device_hash,
					dev_t id)
{
	struct device_data *dev;
	int key = id & HASH_MASK;

	for (dev = device_hash[key]; dev; dev = dev->next) {
		if (dev->id == id)
			break;
	}

	return dev;
}

static int
maybe_insert_path (struct path_data **path_table, const char *pathname)
{
	assert (pathname != NULL);
	assert (path_table != NULL);

	/* Simple DJB2 hashing. */
	size_t i;
	unsigned long hash = 5381;
	size_t length = strlen (pathname);

	for (i = 0; i < length; i++)
		hash = ((hash << 5) + hash) + (unsigned long)pathname[i];

	int key = hash & HASH_MASK;

	struct path_data *data;
	for (data = path_table[key]; data; data = data->next) {
		if (data->hash == hash &&
		    data->length == length &&
		    strcmp (pathname, data->path) == 0)
			return 0;
	}

	/* Path not found. add a new one,
	 * and insert it to the start of linked list.
	 */
	data = calloc (1, sizeof (struct path_data));
	assert (data != NULL);

	data->hash = hash;
	data->length = length;

	strncpy (data->path, pathname, PACK_PATH_MAX);
	data->path[PACK_PATH_MAX] = '\0';

	data->next = path_table[key];
	path_table[key] = data;

	return 1;
}

static int
maybe_insert_dev_inode_pair (struct dev_inode_data **dev_inode_table, dev_t dev_id, ino_t inode)
{
	assert (dev_inode_table != NULL);
	/* We use inode for more uniquely distributed key
	 * as opposed to device id.
	 */
	int key = inode & HASH_MASK;

	struct dev_inode_data *data;
	for (data = dev_inode_table[key]; data; data = data->next) {
		if (data->inode == inode && data->dev_id == dev_id)
			return 0;
	}

	/* dev/inode pair not found. add a new one,
	 * and insert it to the start of linked list.
	 */
	data = calloc (1, sizeof (struct dev_inode_data));
	assert (data != NULL);

	data->dev_id = dev_id;
	data->inode  = inode;

	data->next = dev_inode_table[key];
	dev_inode_table[key] = data;

	return 1;
}
