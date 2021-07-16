/* Erasure of sensitive data, generic implementation.
   Copyright (C) 2016-2019 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.
   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */
/* An assembler implementation of explicit_bzero can be created as an
   assembler alias of an optimized bzero implementation.
   Architecture-specific implementations also need to define
   __explicit_bzero_chk.  */

#include <string.h>

/* This is for compatibility with older versions of GLIBC */
#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 25

#pragma message "Using ad-hoc explicit_bzero"

#ifndef __HSMSIM_EXPLICIT_BZERO
#define __HSMSIM_EXPLICIT_BZERO

#include <stddef.h>
void explicit_bzero(void *s, size_t len);

#endif

#endif