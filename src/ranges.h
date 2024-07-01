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


#ifndef UREADAHEAD_RANGES_H
#define UREADAHEAD_RANGES_H

#ifndef _ATFILE_SOURCE
#define _ATFILE_SOURCE
#endif

#include <sys/types.h>

#include <nih/hash.h>
#include <nih/macros.h>


NIH_BEGIN_EXTERN

/* A type to represents a range. */
typedef struct range {
	loff_t start;
	loff_t end;
} Range;

/* Set of non-overlapping ranges. */
typedef struct range_set {
	/* The number of Ranges */
	size_t num;
	/* Binary search tree of struct range for tsearch */
	void *btree;
} RangeSet;

/* Hash from a file to a RangeSet. */
typedef NihHash FileRangeSets;

RangeSet *range_set_new (const void *parent);
/* Add a range to the set. Overlapping or adjacent ranges will be merged. */
void add_range (RangeSet *set, loff_t start, loff_t end);
/* Build a sorted array of the set's ranges in *array. Returns the number of
 * elements.  If *array is not NULL, nih_realloc() is used to resize it. */
size_t sorted_range_array (const void *parent, RangeSet *set, Range (**array)[]);

/* Range comparison function that is compatible with tsearch.
 * Compares ranges as half-open intervals. */
int compare_range (const void *a, const void *b);

FileRangeSets *file_range_sets_new (const void *parent);
RangeSet *file_range_sets_lookup (FileRangeSets *sets, dev_t dev, ino_t ino);
void file_range_sets_add (FileRangeSets *sets, dev_t dev, ino_t ino, RangeSet *set);


NIH_END_EXTERN

#endif /* UREADAHEAD_RANGES_H */

