/*
 * Copyright(c) 2017 Tim Ruehsen
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * This file is part of libidn.
 */

#include <config.h>

#include <assert.h> // assert
#include <stdint.h> // uint8_t, uint32_t
#include <stdlib.h> // malloc, free
#include <string.h> // memcpy

#include "idna.h"
#include "pr29.h"
#include "punycode.h"
#include "stringprep.h"
#include "tld.h"
#include "fuzzer.h"

/* This not a real fuzzer, more for code coverage and regression testing */

#define countof(a) (sizeof(a)/sizeof(*(a)))

static Idna_rc _idna_errors[] = {
	-1, // catch default case
	IDNA_SUCCESS,
	IDNA_STRINGPREP_ERROR,
	IDNA_PUNYCODE_ERROR,
	IDNA_CONTAINS_NON_LDH,
	IDNA_CONTAINS_LDH,
	IDNA_CONTAINS_MINUS,
	IDNA_INVALID_LENGTH,
	IDNA_NO_ACE_PREFIX,
	IDNA_ROUNDTRIP_VERIFY_ERROR,
	IDNA_CONTAINS_ACE_PREFIX,
	IDNA_ICONV_ERROR,
	IDNA_MALLOC_ERROR,
	IDNA_DLOPEN_ERROR
};

static Pr29_rc _pr29_errors[] = {
	-1, // catch default case
	PR29_SUCCESS,
	PR29_PROBLEM,
	PR29_STRINGPREP_ERROR
};

static Punycode_status _punycode_errors[] = {
	-1, // catch default case
	PUNYCODE_SUCCESS,
	PUNYCODE_BAD_INPUT,
	PUNYCODE_BIG_OUTPUT,
	PUNYCODE_OVERFLOW
};

static Stringprep_rc _stringprep_errors[] = {
	-1, // catch default case
	STRINGPREP_OK,
	STRINGPREP_CONTAINS_UNASSIGNED,
	STRINGPREP_CONTAINS_PROHIBITED,
	STRINGPREP_BIDI_BOTH_L_AND_RAL,
	STRINGPREP_BIDI_LEADTRAIL_NOT_RAL,
	STRINGPREP_BIDI_CONTAINS_PROHIBITED,
	STRINGPREP_TOO_SMALL_BUFFER,
	STRINGPREP_PROFILE_ERROR,
	STRINGPREP_FLAG_ERROR,
	STRINGPREP_UNKNOWN_PROFILE,
	STRINGPREP_ICONV_ERROR,
	STRINGPREP_NFKC_FAILED,
	STRINGPREP_MALLOC_ERROR
};

static Tld_rc _tld_errors[] = {
	-1, // catch default case
	TLD_SUCCESS,
	TLD_INVALID,
	TLD_NODATA,
	TLD_MALLOC_ERROR,
	TLD_ICONV_ERROR,
	TLD_NO_TLD,
	TLD_NOTLD
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int it;

	if (size)
		return 0;

	for (it = 0; it < countof(_idna_errors); it++)
		idna_strerror(_idna_errors[it]);

	for (it = 0; it < countof(_pr29_errors); it++)
		pr29_strerror(_pr29_errors[it]);

	for (it = 0; it < countof(_punycode_errors); it++)
		punycode_strerror(_punycode_errors[it]);

	for (it = 0; it < countof(_stringprep_errors); it++)
		stringprep_strerror(_stringprep_errors[it]);

	for (it = 0; it < countof(_tld_errors); it++)
		tld_strerror(_tld_errors[it]);

	return 0;
}
