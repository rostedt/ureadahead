/*
 * Copyright 2024 Google LLC

 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#define _GNU_SOURCE /* to use tdestroy */
#include <search.h>

#include <nih/alloc.h>
#include <nih/hash.h>
#include <nih/logging.h>
#include <sys/types.h>
#include "nih/list.h"

#include "ranges.h"

int compare_range (const void *a, const void *b)
{
	Range *range_a = (struct range *) a;
	Range *range_b = (struct range *) b;

	if (range_a->end <= range_b->start)
		return -1;
	else if (range_a->start >= range_b->end)
		return 1;
	else
		return 0;
}

/* Range comparison function that is compatible with tsearch.
   Compares ranges as inclusive intervals. */
int compare_inclusive_range (const void *a, const void *b)
{
	Range *range_a = (struct range *) a;
	Range *range_b = (struct range *) b;

	if (range_a->end < range_b->start)
		return -1;
	else if (range_a->start > range_b->end)
		return 1;
	else
		return 0;
}

int range_set_destructor (void *ptr)
{
	RangeSet *set = ptr;
	if (set->btree) {
		tdestroy (set->btree, (void (*)(void *))nih_free);
	}
	return 0;
}

RangeSet *range_set_new (const void *parent)
{
	RangeSet *set = NIH_MUST (nih_alloc (parent, sizeof (*set)));
	set->num = 0;
	set->btree = NULL;
	nih_alloc_set_destructor (set, range_set_destructor);
	return set;
}

void add_range (RangeSet *set, loff_t start, loff_t end)
{
	Range **found;
	nih_local Range *range = NIH_MUST (nih_alloc (NULL, sizeof (*range)));
	range->start = start;
	range->end = end;

	/* Compare as inclusive ranges to include adjacent ranges to merge */
	while (set->btree &&
		(found = tfind (range, &set->btree,
			 compare_inclusive_range)) != NULL) {
		Range *overlapping = *found;

		/* if the found range contains the new range, we're done */
		if (overlapping->start <= range->start && overlapping->end >= range->end)
			return;

		/* Remove the overlapping range, making the new range contain it */
		tdelete (overlapping, &set->btree, compare_inclusive_range);
		if (overlapping->start < range->start)
			range->start = overlapping->start;
		if (overlapping->end > range->end)
			range->end = overlapping->end;
		set->num--;
		nih_free (overlapping);
	}

	/* Insert the new range into the tree by tsearch */
	NIH_MUST (tsearch (range, &set->btree, compare_range));
	set->num++;
	nih_ref (range, set); /* Let the range belong to where it is inserted */
}

Range (*sorted_range_set_array)[];
size_t num_sorted_range_set_array;

void collect_range_set_array (const void *nodep,
	VISIT visit,
	int level)
{
	/* Sort values by descending order */
	if (visit == leaf || visit == postorder) {
		/* nodep is a pointer to a pointer to the data. See man 3 twalk. */
		/* Copy Ranges instead of pointers since Ranges are small. */
		(*sorted_range_set_array)[num_sorted_range_set_array++] = **((Range **)nodep);
	}
}

size_t sorted_range_array (const void *parent,
	RangeSet *set, Range (**array)[])
{
	sorted_range_set_array = NIH_MUST (nih_realloc (*array, parent, sizeof (Range) * set->num));
	*array = sorted_range_set_array;
	num_sorted_range_set_array = 0;
	twalk (set->btree, collect_range_set_array);

	return num_sorted_range_set_array;
}

struct file_range_sets_entry {
	NihList entry;
	struct devino {
		dev_t dev;
		ino_t ino;
	} file;
	RangeSet *set;
};

const struct devino *file_range_sets_key (NihList *entry)
{
	return &((struct file_range_sets_entry *) entry)->file;
}

uint32_t ino_hash (dev_t dev, ino_t ino)
{
	return (uint32_t) (dev ^ ino);
}

uint32_t file_range_sets_hash (const struct devino *key)
{
	return ino_hash (key->dev, key->ino);
}

int file_range_sets_cmp (const struct devino *key1, const struct devino *key2)
{
	if (key1->dev < key2->dev)
		return -1;
	else if (key1->dev > key2->dev)
		return 1;
	else if (key1->ino < key2->ino)
		return -1;
	else if (key1->ino > key2->ino)
		return 1;
	else
		return 0;

}

FileRangeSets *file_range_sets_new (const void *parent)
{
	return NIH_MUST (nih_hash_new (parent, 2500,
				       (NihKeyFunction)file_range_sets_key,
				       (NihHashFunction)file_range_sets_hash,
				       (NihCmpFunction)file_range_sets_cmp));

}

RangeSet *
file_range_sets_lookup (FileRangeSets *sets, dev_t dev, ino_t ino)
{
	NihList *inode_hash = nih_hash_lookup (sets, &(struct devino){dev, ino});
	if (! inode_hash)
		return NULL;
	return ((struct file_range_sets_entry *) inode_hash)->set;
}

void
file_range_sets_add (FileRangeSets *sets, dev_t dev, ino_t ino, RangeSet *set)
{
	struct file_range_sets_entry *entry = NIH_MUST (nih_alloc (sets, sizeof (*entry)));
	nih_list_init(&entry->entry);
	entry->file.dev = dev;
	entry->file.ino = ino;
	entry->set = set;
	nih_ref (set, entry);
	NIH_MUST (nih_hash_add (sets, &entry->entry));
}
