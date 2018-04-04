/* Elementary Unicode string functions.
   Copyright (C) 2001-2002, 2005-2018 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as published
   by the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

#ifndef IDN_UNISTR_H
#define IDN_UNISTR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


/* Conventions:

   All functions prefixed with u8_ operate on UTF-8 encoded strings.
   Their unit is an uint8_t (1 byte).

   All functions prefixed with u16_ operate on UTF-16 encoded strings.
   Their unit is an uint16_t (a 2-byte word).

   All functions prefixed with u32_ operate on UCS-4 encoded strings.
   Their unit is an uint32_t (a 4-byte word).

   All argument pairs (s, n) denote a Unicode string s[0..n-1] with exactly
   n units.

   All arguments starting with "str" and the arguments of functions starting
   with u8_str/u16_str/u32_str denote a NUL terminated string, i.e. a string
   which terminates at the first NUL unit.  This termination unit is
   considered part of the string for all memory allocation purposes, but
   is not considered part of the string for all other logical purposes.

   Functions returning a string result take a (resultbuf, lengthp) argument
   pair.  If resultbuf is not NULL and the result fits into *lengthp units,
   it is put in resultbuf, and resultbuf is returned.  Otherwise, a freshly
   allocated string is returned.  In both cases, *lengthp is set to the
   length (number of units) of the returned string.  In case of error,
   NULL is returned and errno is set.  */


/* Elementary string checks.  */

/* Check whether an UTF-8 string is well-formed.
   Return NULL if valid, or a pointer to the first invalid unit otherwise.  */
extern const uint8_t *
       u8_check (const uint8_t *s, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* _UNISTR_H */
