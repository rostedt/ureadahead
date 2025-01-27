# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.62)
AC_INIT([ureadahead], [0.100.2], [ubuntu-devel@lists.ubuntu.com])
AC_COPYRIGHT([[Copyright © 2009 Canonical Ltd.]])
AC_CONFIG_SRCDIR([src/ureadahead.c])
AC_CONFIG_MACRO_DIR([m4])

AC_GNU_SOURCE

AM_INIT_AUTOMAKE([1.11 foreign nostdinc color-tests silent-rules])
AM_SILENT_RULES([yes])
AM_MAINTAINER_MODE([enable])

LT_PREREQ(2.2.4)
LT_INIT

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
PKG_PROG_PKG_CONFIG

# Checks for libraries.
PKG_CHECK_MODULES([BLKID], [blkid >= 2.16])
PKG_CHECK_MODULES([EXT2FS], [ext2fs >= 1.41])
PKG_CHECK_MODULES([TRACEFS], [libtracefs >= 1.6])
PKG_CHECK_MODULES([TRACEEVENT], [libtraceevent >= 1.7])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_PROG_CC_C99
AC_SYS_LARGEFILE

# Checks for library functions.

AC_CONFIG_FILES([ Makefile src/Makefile ])
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT
