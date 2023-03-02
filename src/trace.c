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
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <tracefs.h>
#include <dirent.h>

#include <blkid.h>
#define NO_INLINE_FUNCS
#include <ext2fs.h>

#include <linux/fs.h>
#include <linux/fiemap.h>

#include <nih/macros.h>
#include <nih/alloc.h>
#include <nih/string.h>
#include <nih/list.h>
#include <nih/hash.h>
#include <nih/main.h>
#include <nih/logging.h>
#include <nih/error.h>

#include "trace.h"
#include "pack.h"
#include "values.h"
#include "file.h"

/**
 * PATH_DEBUGFS:
 *
 * Path to the usual debugfs mountpoint.
 **/
#define PATH_DEBUGFS     "/sys/kernel/debug"

/**
 * PATH_DEBUGFS_TMP:
 *
 * Path to the temporary debugfs mountpoint that we mount it on if it
 * hasn't been mounted at the usual place yet.
 **/
#define PATH_DEBUGFS_TMP "/var/lib/ureadahead/debugfs"

/**
 * PATH_TRACEFS:
 *
 * Path to the usual tracefs (since kernel 4.1) mountpoint.
 **/
#define PATH_TRACEFS     "/sys/kernel/tracing"

/**
 * INODE_GROUP_PRELOAD_THRESHOLD:
 *
 * Number of inodes in a group before we preload that inode's blocks.
 **/
#define INODE_GROUP_PRELOAD_THRESHOLD 8

#define HASH_BITS 16
#define HASH_SIZE (1 << HASH_BITS) // 16384
#define HASH_MASK (HASH_SIZE - 1)

#define ARRAY_START_MARK	((unsigned long)-1)

#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)

#define BUF_SIZE 32768

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
#define getdents64(fd, dirp, count) syscall(SYS_getdents64, fd, buf, BUF_SIZE);

struct file_map {
	off_t				start;
	off_t				end;
};

struct inode_data {
	struct inode_data		*next;
	unsigned long			inode;
	char				*dev_name;
	struct file_map			*map;
	int				nr_maps;
	int				order;
	char				*name;
};

struct device_data {
	struct device_data		*next;
	char				*name;
	int				id;
	int				nr_inodes;
	struct inode_data		*inodes;
};

struct trace_data {
	struct tracefs_instance		*instance;
	struct tep_handle		*tep;
	struct tep_event		*filemap_event;
	struct tep_format_field		*filemap_inode;
	struct tep_format_field		*filemap_index;
	struct tep_format_field		*filemap_device;
	struct device_data		*device_hash[HASH_SIZE];
	int				next_inode;
};



/* Prototypes for static functions */
static int       read_trace        (struct trace_data *data,
				    PackFile **files, size_t *num_files,
				    int force_ssd_mode);

static int       trace_add_path    (struct inode_data *inode, const char *pathname,
				    PackFile **files, size_t *num_files, int force_ssd_mode);
static int       ignore_path       (const char *pathname);
static PackFile *trace_file        (dev_t dev,
				    PackFile **files, size_t *num_files, int force_ssd_mode);
static int       trace_add_chunks  (struct inode_data *inode, const void *parent,
				    PackFile *file, PackPath *path,
				    int fd, off_t size);
static int       trace_add_groups  (const void *parent, PackFile *file);
static int       trace_sort_blocks (const void *parent, PackFile *file);
static int       trace_sort_paths  (const void *parent, PackFile *file);

static int	 callback          (struct tep_event *event, struct tep_record *record,
				    int cpu, void *data);
static void add_file_page(struct trace_data *tdata, int device, unsigned long ino, off_t offset);
static void add_map(struct inode_data *inode, off_t offset);
static int cmp_file_map_range(const void *A, const void *B);
static int cmp_file_map(const void *A, const void *B);
static struct inode_data *add_inode(struct trace_data *tdata,
				    struct device_data *dev, unsigned long ino);
static int cmp_inodes_range(const void *A, const void *B);
static struct inode_data *find_inode(struct device_data *dev, unsigned long ino);
static int cmp_inodes(const void *A, const void *B);
static struct device_data *add_device(struct trace_data *tdata, int id);
static struct device_data *find_device(struct trace_data *tdata, int id);


static void
sig_interrupt (int signum)
{
}

static int enable_event(struct tracefs_instance *instance,
			const char *system, const char *event, int *enabled)
{
	int ret;

	if (enabled)
		*enabled = tracefs_event_is_enabled(instance, system, event) == TRACEFS_ALL_ENABLED;
	ret = tracefs_event_enable(instance, system, event);
	if (ret < 0) {
		/* fs/uselib may not exist, and that is OK. */
		errno = ENOENT;
		nih_return_system_error (-1);
	}
	return ret;
}

static int reset_event(struct tracefs_instance *instance,
		       const char *system, const char *event, int enabled)
{
	int ret;

	if (enabled)
		ret = tracefs_event_enable(instance, system, event);
	else
		ret = tracefs_event_disable(instance, system, event);
	if (ret < 0)
		nih_error_raise_system ();

	return ret;
}

static void drop_cache(void)
{
	int fd;

	fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
	nih_assert (fd >= 0);
	write(fd, "1", 1);
	close(fd);
}

static void free_device(struct device_data *dev)
{
	struct inode_data *inode;
	int i;

	for (i = 0; i < dev->nr_inodes; i++) {
		inode = &dev->inodes[i];
		/* inode->map has one meta data element at the start */
		inode->map--;
		free(inode->map);
		free(inode->name);
	}
	/* dev->inodes has one meta data element at the start */
	dev->inodes--;
	free(dev->inodes);
	free(dev->name);
	free(dev);
}

static void free_trace_data(struct trace_data *tdata)
{
	struct device_data *dev;
	int i;

	for (i = 0; i < HASH_SIZE; i++) {
		while (tdata->device_hash[i]) {
			dev = tdata->device_hash[i];
			tdata->device_hash[i] = dev->next;
			free_device(dev);
		}
	}
}

int
trace (int daemonise,
       int timeout,
       const char *filename_to_replace,
       const char *pack_file,
       const char *path_prefix_filter,
       const PathPrefixOption *path_prefix,
       int use_existing_trace,
       int force_ssd_mode,
       int drop_caches)
{
	const char *systems[] = { "filemap", NULL };
	struct tracefs_instance *instance = NULL;
	struct tep_handle	*tep;
	struct trace_data	data;
	int                 unmount;
	int                 old_event_enabled = 0;
	int                 old_tracing_enabled = 0;
	int                 old_buffer_size_kb = 0;
	const char         *tracing_dir = NULL;
	struct sigaction    act;
	struct sigaction    old_sigterm;
	struct sigaction    old_sigint;
	struct timeval      tv;
	nih_local PackFile *files = NULL;
	size_t              num_files = 0;
	ssize_t              num_cpus = 0;

	/*
	 * tracefs_tracing_dir_is_mounted() returns:
	 *  0 if it was not mounted (but it mounted it)
	 *  1 if it was already mounted
	 * -1 on error.
	 */
	unmount = tracefs_tracing_dir_is_mounted(true, &tracing_dir);
	if (umount < 0)
		return -1;
	/* Returns 1 if it is already mounted and 0 if it mounted it */
	unmount = !unmount;

	num_cpus = sysconf(_SC_NPROCESSORS_CONF);
	if (num_cpus <= 0)
		num_cpus = 1;

	old_tracing_enabled = tracefs_trace_is_on(instance);

	/* The error path expects data to be initialized */
	memset(&data, 0, sizeof(data));

	if (! use_existing_trace) {
		/* Start tracing as soon as possible */
		old_buffer_size_kb = tracefs_instance_get_buffer_size(instance, -1);
		if (old_buffer_size_kb < 0)
			goto error;

		/* buffer size is per cpu */
		old_buffer_size_kb /= num_cpus;
		if (tracefs_instance_set_buffer_size (instance, 8192, -1) < 0)
			goto error;

		old_tracing_enabled = tracefs_trace_is_on(instance);

		/* Enable tracing of loading pages from the block devices */
		if (enable_event (instance, "filemap", "mm_filemap_add_to_page_cache",
				  &old_event_enabled) < 0)
			goto error;

		/*
		 * There may be a lot of files being read while this was being
		 * setup. Drop the file caches to force the applications to
		 * reload if needed, and that will be recorded in the trace.
		 */
		if (drop_caches)
			drop_cache();

		if (tracefs_trace_on(instance))
			goto error;
	}

	tep = tracefs_local_events_system(NULL, systems);
	nih_assert (tep != NULL);

	data.tep = tep;
	data.instance = instance;

	data.filemap_event = tep_find_event_by_name(tep, NULL, "mm_filemap_add_to_page_cache");
	nih_assert (data.filemap_event != NULL);

	data.filemap_inode = tep_find_field(data.filemap_event, "i_ino");
	nih_assert (data.filemap_inode != NULL);

	data.filemap_index = tep_find_field(data.filemap_event, "index");
	nih_assert (data.filemap_index != NULL);

	data.filemap_device = tep_find_field(data.filemap_event, "s_dev");
	nih_assert (data.filemap_device != NULL);

	if (daemonise) {
		pid_t pid;

		pid = fork ();
		if (pid < 0) {
			nih_error_raise_system ();
			goto error;
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

	if (! use_existing_trace) {
		tracefs_trace_off(instance);

		if (reset_event(instance, "filemap", "mm_filemap_add_to_page_cache",
				old_event_enabled) < 0)
			goto error;
	}

	/* Be nicer */
	if (nice (15))
		;

	/* Read the pages that were traced */
	if (read_trace (&data, &files, &num_files, force_ssd_mode))
		goto error;

	tep_free(tep);

	if (! use_existing_trace) {
		/* Restore previous tracing settings */
		if (old_tracing_enabled)
			tracefs_trace_on(instance);
		else
			tracefs_trace_off(instance);

		/*
		 * Restore the trace buffer size (which has just been read) and free
		 * a bunch of memory.
		 */
		if (tracefs_instance_set_buffer_size(instance, old_buffer_size_kb, -1) < 0)
			goto error;
	}

	/* Unmount the temporary debugfs mount if we mounted it */
	if (unmount
	    && (umount (tracing_dir) < 0)) {
		nih_error_raise_system ();
		goto error;
	}

	/* Write out pack files */
	for (size_t i = 0; i < num_files; i++) {
		nih_local char *filename = NULL;
		if (pack_file) {
			filename = NIH_MUST (nih_strdup (NULL, pack_file));
		} else {
			filename = pack_file_name_for_mount (NULL, files[i].dev_path);
			if (! filename) {
				NihError *err;

				err = nih_error_get ();
				nih_warn ("%s", err->message);
				nih_free (err);

				continue;
			}

			/* If filename_to_replace is not NULL, only write out
			 * the file and skip others.
			 */
			if (filename_to_replace &&
			    strcmp (filename_to_replace, filename)) {
				nih_info ("Skipping %s", filename);
				continue;
			}
		}
		nih_info ("Writing %s", filename);

		/* We only need to apply additional sorting to the
		 * HDD-optimised packs, the SSD ones can read in random
		 * order quite happily.
		 *
		 * Also for HDD, generate the inode group preloading
		 * array.
		 */
		if (files[i].rotational) {
			trace_add_groups (files, &files[i]);

			trace_sort_blocks (files, &files[i]);
			trace_sort_paths (files, &files[i]);
		}

		write_pack (filename, &files[i]);

		if (nih_log_priority < NIH_LOG_MESSAGE)
			pack_dump (&files[i], SORT_OPEN);
	}

	free_trace_data(&data);

	return 0;
error:
	free_trace_data(&data);

	if (unmount)
		umount (tracing_dir);

	return -1;
}

/* This gets called for every event in the ring buffer in order */
static int callback(struct tep_event *event, struct tep_record *record, int cpu,
		    void *data)
{
	struct trace_data *tdata = data;
	unsigned long long ino;
	unsigned long long device;
	unsigned long long index;

	if (event->id != tdata->filemap_event->id)
		return 0;

	if (tep_read_number_field(tdata->filemap_inode, record->data, &ino) < 0)
		return 1;

	if (tep_read_number_field(tdata->filemap_device, record->data, &device) < 0)
		return 1;

	if (tep_read_number_field(tdata->filemap_index, record->data, &index) < 0)
		return 1;


	add_file_page(tdata, device, ino, index);

	return 0;
}

/*
 * The mm_filemap_add_to_page_cache event was read and gives the device, inode number,
 * and page index. Note the offset into the file that this page is for is found by:
 *  offset = index * page_size
 */
static void add_file_page(struct trace_data *tdata, int device, unsigned long ino, off_t index)
{
	struct device_data *dev;
	struct inode_data *inode;
	struct file_map *map;
	struct file_map key;
	int idx;

	dev = find_device(tdata, device);
	if (!dev)
		dev = add_device(tdata, device);

	inode = find_inode(dev, ino);
	if (!inode)
		inode = add_inode(tdata, dev, ino);

	key.start = index;
	key.end = index + 1;

	/*
	 * The cmp_file_map will match not only if it finds a mapping that the
	 * index is in, but also if the index is at the end of a mapping or
	 * the begging of one. In the latter case, it will return the mapping
	 * that touchs the index.
	 */
	map = bsearch(&key, inode->map, inode->nr_maps, sizeof(key), cmp_file_map);
	if (!map) {
		/* A new index that also does not touch a mapping. */
		add_map(inode, index);
		return;
	}

	if (map->start <= index && map->end > index)
		/* Nothing to do, it is already accounted for */
		return;

	/* index is after the mapping, extend the mapping */
	if (map->end == index) {
		/* The size of the new index is just one (page_size) */
		map->end++;

		/* If this mapping is the last one, then we are done */
		if ((map - inode->map) == (inode->nr_maps - 1))
			return;
	} else {
		/* The index is just ahead of this mapping (make sure of that) */
		nih_assert( map->start == index + 1);

		/* The size of the new index is just one (page_size) */
		map->start--;

		/* If this mapping is the first one, then we are done */
		if (map == inode->map)
			return;

		/* The following code looks to see if we need to merge mappings */
		map--;
	}

	/* If the addition of this index connected two mappings then merge them. */
	if (map->end != map[1].start)
		return;

	/* Merge the two maps */
	map->end = map[1].end;
	map++;
	idx = map - inode->map;
	inode->nr_maps--;

	/* If the second map was not at the end, then adjust the inode map array */
	if (idx < inode->nr_maps)
		memmove(map, &map[1], sizeof(*map) * (inode->nr_maps - idx));
}

/* Returns a match if A is within or touches B */
static int cmp_file_map(const void *A, const void *B)
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
 * ARRAY_START_MARK as it's "start" element. This is to help the
 * cmp_file_map_range() function to know if the new index is between
 * two other indexes, as it returns the mapping after the index when
 * the index is before it. To do so, it needs to check the element before the
 * element being tested. In order to test the first element (without knowing
 * that it is on the first element), it needs to look before that element.
 * The ARRAY_START_MARK element will be the element before the first one.
 */
static void add_map(struct inode_data *inode, off_t index)
{
	struct file_map *map;
	struct file_map key;
	int idx;

	/* Handle the first two trivial cases */
	switch (inode->nr_maps) {
	case 0:
		/* Allocate 2: 1 for this element an 1 for the ARRAY_START_MARK */
		map = malloc(sizeof(*inode->map) * 2);
		nih_assert (map != NULL);

		/* Add a buffer element at the beginning for cmp_file_map_range() */
		map->start = ARRAY_START_MARK;
		/* The inode->map will skip over that element */
		map++;
		inode->map = map;
		break;
	case 1:
		/* The allocated array starts one element before the inode->map */
		map = inode->map - 1;
		/* Allocate three. 2 for the elements and one for the ARRAY_START_MARK */
		map = realloc(map, sizeof(*inode->map) * 3);
		nih_assert (map != NULL);

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
		key.end = index + 1;

		/*
		 * The cmp_file_map_range() will return the map that is after
		 * the index (or NULL if the index is greater than all existing
		 * maps).
		 */
		map = bsearch(&key, inode->map, inode->nr_maps, sizeof(*map),
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
		map = realloc(map, sizeof(*map) * (inode->nr_maps + 2));
		nih_assert (map != NULL);
		map++;
		inode->map = map;

		/* If the new index is not at the end, make room for it */
		if (idx < inode->nr_maps)
			memmove(&map[idx + 1], &map[idx],
				sizeof(*map) * (inode->nr_maps - idx));
		map = &map[idx];
	}
	map->start = index;
	map->end = index + 1;
	inode->nr_maps++;
}

/*
 * Range is called when the offset does not touch any of the
 * existing mappings.
 *
 * Returns NULL, if A is bigger than all the other elements.
 * Otherwise, returns the element just after A.
 */
static int cmp_file_map_range(const void *A, const void *B)
{
	const struct file_map *a = A;
	const struct file_map *b2 = B;
	const struct file_map *b1 = b2 - 1;

	if (a->end < b2->start) {
		/* Check if a is between b1 and b2 */
		if (b1->start == ARRAY_START_MARK || a->start > b1->end)
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
static struct inode_data *add_inode(struct trace_data *tdata,
				    struct device_data *dev, unsigned long ino)
{
	struct inode_data *inode;
	struct inode_data key;
	int index;

	switch (dev->nr_inodes) {
	case 0:
		/* Add a marker to the beginning of the array for the range compare */
		inode = malloc(sizeof(key) * 2);
		nih_assert (inode != NULL);
		inode->inode = ARRAY_START_MARK;
		inode++;
		dev->inodes = inode;
		break;
	case 1:
		inode = dev->inodes - 1;
		inode = realloc(inode, sizeof(key) * 3);
		nih_assert (inode != NULL);
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
		inode = bsearch(&key, dev->inodes, dev->nr_inodes, sizeof(key),
			      cmp_inodes_range);
		if (inode)
			index = inode - dev->inodes;
		else
			index = dev->nr_inodes;

		/* Set to the start of the allocated array */
		inode = dev->inodes - 1;
		inode = realloc(inode, sizeof(key) * (dev->nr_inodes + 2));
		nih_assert (inode != NULL);
		inode++;
		dev->inodes = inode;

		/* Make room for the new inode if it's not at the end of the array */
		if (index < dev->nr_inodes)
			memmove(&inode[index + 1], &inode[index],
				sizeof(key) * (dev->nr_inodes - index));
		inode = &inode[index];
	}
	memset(inode, 0, sizeof(*inode));
	inode->inode = ino;
	dev->nr_inodes++;
	/* Keep track of the order of inodes as they are found */
	inode->order = tdata->next_inode++;
	return inode;
}

/*
 * Compare to cause bsearch to:
 *
 * Return NULL, if A is bigger than all the other elements.
 * Otherwise, return the element just after A.
 */
static int cmp_inodes_range(const void *A, const void *B)
{
	const struct inode_data *a = A;
	const struct inode_data *b2 = B;
	const struct inode_data *b1 = b2 - 1;

	if (a->inode < b2->inode) {
		/* if a is between b1 and b2, then it's a match */
		if (b1->inode == ARRAY_START_MARK || a->inode > b1->inode)
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

static struct inode_data *find_inode(struct device_data *dev, unsigned long ino)
{
	struct inode_data key;

	key.inode = ino;

	/* Returns a map that just touches the offset */
	return bsearch(&key, dev->inodes, dev->nr_inodes, sizeof(key), cmp_inodes);
}

static int cmp_inodes(const void *A, const void *B)
{
	const struct inode_data *a = A;
	const struct inode_data *b = B;

	if (a->inode < b->inode)
		return -1;

	return a->inode > b->inode;
}

static struct device_data *add_device(struct trace_data *tdata, int id)
{
	struct device_data *dev;
	int key = id & HASH_MASK;

	dev = calloc(1, sizeof(*dev));
	nih_assert (dev != NULL);

	dev->id = id;
	dev->next = tdata->device_hash[key];
	tdata->device_hash[key] = dev;

	return dev;
}

static struct device_data *find_device(struct trace_data *tdata, int id)
{
	struct device_data *dev;
	int key = id & HASH_MASK;

	for (dev = tdata->device_hash[key]; dev; dev = dev->next) {
		if (dev->id == id)
			break;
	}

	return dev;
}

struct dir_stack {
	struct dir_stack		*next;
	char				*dir;
};

static void push_dir(struct dir_stack **dirs, char *dir)
{
	struct dir_stack *d;

	d = malloc(sizeof(*d));
	nih_assert (d != NULL);

	d->dir = strdup(dir);
	nih_assert (d->dir != NULL);

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
		      struct inode_data **inodes, int inos)
{
	struct inode_data *inode;
	char filename[PATH_MAX];
	struct linux_dirent64 *dent;
	struct stat st;
	struct dir_stack *dirs = NULL;
	int found_inos = 0;
	char buf[BUF_SIZE];
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
						nih_assert (inode->name != NULL);
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

static int
read_trace (struct trace_data *tdata, PackFile **files, size_t *num_files,
	    int force_ssd_mode)
{
	unsigned int major, minor, device;
	struct inode_data **inodes;
	struct device_data *dev;
	char mapname[PATH_MAX];
	char *line = NULL;
	size_t len = 0;
	FILE *fp;
	int inos = 0;
	int ret;
	int i;

	tracefs_iterate_raw_events(tdata->tep, tdata->instance, NULL, 0, callback, tdata);

	/* Fail of nothing was found */
	if (!tdata->next_inode)
		return -1;

	/*
	 * First map the devices found in the trace to the file systems they
	 * represent.
	 */
	fp = fopen("/proc/self/mountinfo", "r");

	/*
	 * Create an array of all the inodes, to sort them in the order they
	 * were found in the trace.
	 */
	inodes = calloc(tdata->next_inode, sizeof(*inodes));
	nih_assert (inodes != NULL);

	while (getline(&line, &len, fp) > 0) {
		ret = sscanf(line, "%*d %*d %d:%d / %"STRINGIFY(PATH_MAX)"s",
			     &major, &minor, mapname);
		if (ret != 3)
			continue;

		/*
		 * Here's a bit of disconnect. The devices in the trace are
		 * represented as major << 20 | minor, whereas the devices in
		 * stat() are represented as major << 8 | minor.
		 */
		device = major << 20 | minor;
		dev = find_device(tdata, device);
		if (!dev)
			continue;

		dev->name = strdup(mapname);
		nih_assert(dev->name);
		device = makedev(major, minor);

		inos = map_inodes(dev, device, mapname, inodes, inos);
	}
	fclose(fp);
	free(line);

	/* Add the files in order of when they were found */
	qsort(inodes, inos, sizeof(*inodes), cmp_inode_order);

	for (i = 0; i < inos; i++) {
		trace_add_path(inodes[i], inodes[i]->name,
			       files, num_files,
			       force_ssd_mode);
	}

	return 0;
}

static int
trace_add_path (struct inode_data *inode,
		const char *pathname,
		PackFile ** files,
		size_t *    num_files,
		int         force_ssd_mode)
{
	static NihHash *path_hash = NULL;
	struct stat     statbuf;
	int             fd;
	PackFile *      file;
	PackPath *      path;
	static NihHash *inode_hash = NULL;
	nih_local char *inode_key = NULL;

	nih_assert (pathname != NULL);
	nih_assert (files != NULL);
	nih_assert (num_files != NULL);

	/* We can't really deal with relative paths since we don't know
	 * the working directory that they were opened from.
	 */
	if (pathname[0] != '/') {
		nih_warn ("%s: %s", pathname, _("Ignored relative path"));
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
		nih_warn ("%s: %s", pathname, _("Ignored far too long path"));
		return 0;
	}

	/* Use a hash table of paths to eliminate duplicate path names from
	 * the table since that would waste pack space (and fds).
	 */
	if (! path_hash)
		path_hash = NIH_MUST (nih_hash_string_new (NULL, 2500));

	if (nih_hash_lookup (path_hash, pathname)) {
		return 0;
	} else {
		NihListEntry *entry;

		entry = NIH_MUST (nih_list_entry_new (path_hash));
		entry->str = NIH_MUST (nih_strdup (entry, pathname));

		nih_hash_add (path_hash, &entry->entry);
	}

	/* Make sure that we have an ordinary file
	 * This avoids us opening a fifo or socket or symlink.
	 */
	if ((lstat (pathname, &statbuf) < 0)
	    || (S_ISLNK (statbuf.st_mode))
	    || (! S_ISREG (statbuf.st_mode)))
		return 0;

	/* Open and stat again to get the genuine details, in case it
	 * changes under us.
	 */
	fd = open (pathname, O_RDONLY | O_NOATIME);
	if (fd < 0) {
		nih_warn ("%s: %s: %s", pathname,
			  _("File vanished or error reading"),
			  strerror (errno));
		return -1;
	}

	if (fstat (fd, &statbuf) < 0) {
		nih_warn ("%s: %s: %s", pathname,
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
	file->paths = NIH_MUST (nih_realloc (file->paths, *files,
					     (sizeof (PackPath)
					      * (file->num_paths + 1))));

	file->dev_path = inode->dev_name;

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
	if (! inode_hash)
		inode_hash = NIH_MUST (nih_hash_string_new (NULL, 2500));

	inode_key = NIH_MUST (nih_sprintf (NULL, "%llu:%llu",
					   (unsigned long long)statbuf.st_dev,
					   (unsigned long long)statbuf.st_ino));

	if (nih_hash_lookup (inode_hash, inode_key)) {
		close (fd);
		return 0;
	} else {
		NihListEntry *entry;

		entry = NIH_MUST (nih_list_entry_new (inode_hash));
		entry->str = inode_key;
		nih_ref (entry->str, entry);

		nih_hash_add (inode_hash, &entry->entry);
	}

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
	trace_add_chunks (inode, *files, file, path, fd, statbuf.st_size);
	close (fd);

	return 0;
}

static int
ignore_path (const char *pathname)
{
	nih_assert (pathname != NULL);

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
	nih_local char *filename = NULL;
	int             rotational;
	PackFile *      file;

	nih_assert (files != NULL);
	nih_assert (num_files != NULL);

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
		filename = NIH_MUST (nih_sprintf (NULL, "/sys/dev/block/%d:%d/queue/rotational",
						major (dev), minor (dev)));
		if (access (filename, R_OK) < 0) {
			/* For devices managed by the scsi stack, the minor device number has to be
			 * masked to find the queue/rotational file.
			 */
			nih_free (filename);
			filename = NIH_MUST (nih_sprintf (NULL, "/sys/dev/block/%d:%d/queue/rotational",
							major (dev), minor (dev) & 0xffff0));
		}

		if (get_value (AT_FDCWD, filename, &rotational) < 0) {
			NihError *err;

			err = nih_error_get ();
			nih_warn (_("Unable to obtain rotationalness for device %u:%u: %s"),
				major (dev), minor (dev), err->message);
			nih_free (err);

			rotational = TRUE;
		}
	}

	/* Grow the PackFile array and fill in the details for the new
	 * file.
	 */
	*files = NIH_MUST (nih_realloc (*files, NULL,
					(sizeof (PackFile) * (*num_files + 1))));

	file = &(*files)[(*num_files)++];
	memset (file, 0, sizeof (PackFile));

	file->dev = dev;
	file->rotational = rotational;
	file->num_paths = 0;
	file->paths = NULL;
	file->num_blocks = 0;
	file->blocks = NULL;

	return file;
}


static int
trace_add_chunks (struct inode_data *inode,
		  const void *parent,
		  PackFile *  file,
		  PackPath *  path,
		  int         fd,
		  off_t       size)
{
	static int               page_size = -1;

	nih_assert (inode != NULL);
	nih_assert (file != NULL);
	nih_assert (path != NULL);
	nih_assert (fd >= 0);
	nih_assert (size > 0);

	if (page_size < 0)
		page_size = sysconf (_SC_PAGESIZE);


	/* Add all the blocks that were traced being loaded */
	for (int i = 0; i < inode->nr_maps; i++) {
		struct file_map *map = &inode->map[i];
		PackBlock *block;
		off_t offset;
		off_t length;

		offset = map->start * page_size;
		length = (map->end - map->start) * page_size;

		file->blocks = NIH_MUST (nih_realloc (file->blocks, parent,
						      (sizeof (PackBlock)
						       * (file->num_blocks + 1))));

		block = &file->blocks[file->num_blocks++];
		memset (block, 0, sizeof (PackBlock));

		block->pathidx = file->num_paths - 1;
		block->offset = offset;
		block->length = length;
		block->physical = -1;
	}

	return 0;
}

static int
trace_add_groups (const void *parent,
		  PackFile *  file)
{
	const char *devname;
	ext2_filsys fs = NULL;

	nih_assert (file != NULL);

	devname = blkid_devno_to_devname (file->dev);
	if (devname
	    && (! ext2fs_open (devname, 0, 0, 0, unix_io_manager, &fs))) {
		nih_assert (fs != NULL);
		size_t            num_groups = 0;
		nih_local size_t *num_inodes = NULL;
		size_t            mean = 0;
		size_t            hits = 0;

		nih_assert (fs != NULL);

		/* Calculate the number of inode groups on this filesystem */
		num_groups = ((fs->super->s_blocks_count - 1)
			      / fs->super->s_blocks_per_group) + 1;

		/* Fill in the pack path's group member, and count the
		 * number of inodes in each group.
		 */
		num_inodes = NIH_MUST (nih_alloc (NULL, (sizeof (size_t)
							 * num_groups)));
		memset (num_inodes, 0, sizeof (size_t) * num_groups);

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
				file->groups = NIH_MUST (nih_realloc (file->groups, parent,
								      (sizeof (int)
								       * (file->num_groups + 1))));
				file->groups[file->num_groups++] = i;
				hits++;
			}
		}

		mean /= num_groups;

		nih_debug ("%zu inode groups, mean %zu inodes per group, %zu hits",
			   num_groups, mean, hits);

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

	nih_assert (block_a != NULL);
	nih_assert (block_b != NULL);

	if (block_a->physical < block_b->physical) {
		return -1;
	} else if (block_a->physical > block_b->physical) {
		return 1;
	} else {
		return 0;
	}
}

static int
trace_sort_blocks (const void *parent,
		   PackFile *  file)
{
	nih_assert (file != NULL);

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

	nih_assert (path_a != NULL);
	nih_assert (path_b != NULL);

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
trace_sort_paths (const void *parent,
		  PackFile *  file)
{
	nih_local PackPath **paths = NULL;
	nih_local size_t *   new_idx = NULL;
	PackPath *           new_paths;

	nih_assert (file != NULL);

	/* Sort the paths array by ext2fs inode group, ino_t then path.
	 *
	 * Mucking around with things like the physical locations of
	 * first on-disk blocks of the dentry and stuff didn't work out
	 * so well, sorting by path was better, but this seems the best.
	 * (it looks good on blktrace too)
	 */
	paths = NIH_MUST (nih_alloc (NULL, (sizeof (PackPath *)
					    * file->num_paths)));

	for (size_t i = 0; i < file->num_paths; i++)
		paths[i] = &file->paths[i];

	qsort (paths, file->num_paths, sizeof (PackPath *),
	       path_compar);

	/* Calculate the new indexes of each path element in the old
	 * array, and then update the block array's path indexes to
	 * match.
	 */
	new_idx = NIH_MUST (nih_alloc (NULL,
				       (sizeof (size_t) * file->num_paths)));
	for (size_t i = 0; i < file->num_paths; i++)
		new_idx[paths[i] - file->paths] = i;

	for (size_t i = 0; i < file->num_blocks; i++)
		file->blocks[i].pathidx = new_idx[file->blocks[i].pathidx];

	/* Finally generate a new paths array with the new order and
	 * attach it to the file.
	 */
	new_paths = NIH_MUST (nih_alloc (parent,
					 (sizeof (PackPath) * file->num_paths)));
	for (size_t i = 0; i < file->num_paths; i++)
		memcpy (&new_paths[new_idx[i]], &file->paths[i],
			sizeof (PackPath));

	nih_unref (file->paths, parent);
	file->paths = new_paths;

	return 0;
}
