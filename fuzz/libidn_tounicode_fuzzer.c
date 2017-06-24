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
#include "idn-free.h"
#include "fuzzer.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *domain = (char *) malloc(size + 1);
	char *out;

	assert(domain != NULL);

	// 0 terminate
	memcpy(domain, data, size);
	domain[size] = 0;

	if ((size & 3) == 0) {
		uint32_t *out = (uint32_t *) malloc(size);
		size_t outlen;

		assert(out != NULL);

		outlen = size / 4;
		idna_to_unicode_44i((uint32_t *)data, size / 4, out, &outlen, 0);
		outlen = size / 4;
		idna_to_unicode_44i((uint32_t *)data, size / 4, out, &outlen, IDNA_ALLOW_UNASSIGNED|IDNA_USE_STD3_ASCII_RULES);

		free(out);

		uint32_t *data0 = (uint32_t *) malloc(size + 4), *out0;
		assert(data0 != NULL);
		memcpy(data0, data, size);
		data0[size / 4] = 0;

		if (idna_to_unicode_4z4z(data0, &out0, 0) == IDNA_SUCCESS)
			idn_free(out0);
		if (idna_to_unicode_4z4z(data0, &out0, IDNA_ALLOW_UNASSIGNED|IDNA_USE_STD3_ASCII_RULES) == IDNA_SUCCESS)
			idn_free(out0);

		free(data0);

		if (idna_to_unicode_8z4z(domain, &out0, 0) == IDNA_SUCCESS)
			idn_free(out0);
		if (idna_to_unicode_8z4z(domain, &out0, IDNA_ALLOW_UNASSIGNED|IDNA_USE_STD3_ASCII_RULES) == IDNA_SUCCESS)
			idn_free(out0);
	}

	if (idna_to_unicode_8z8z(domain, &out, 0) == IDNA_SUCCESS)
		idn_free(out);
	if (idna_to_unicode_8z8z(domain, &out, IDNA_ALLOW_UNASSIGNED|IDNA_USE_STD3_ASCII_RULES) == IDNA_SUCCESS)
		idn_free(out);
	if (idna_to_unicode_8zlz(domain, &out, 0) == IDNA_SUCCESS)
		idn_free(out);
	if (idna_to_unicode_8zlz(domain, &out, IDNA_ALLOW_UNASSIGNED|IDNA_USE_STD3_ASCII_RULES) == IDNA_SUCCESS)
		idn_free(out);
	if (idna_to_unicode_lzlz(domain, &out, 0) == IDNA_SUCCESS)
		idn_free(out);
	if (idna_to_unicode_lzlz(domain, &out, IDNA_ALLOW_UNASSIGNED|IDNA_USE_STD3_ASCII_RULES) == IDNA_SUCCESS)
		idn_free(out);

	free(domain);

	return 0;
}
