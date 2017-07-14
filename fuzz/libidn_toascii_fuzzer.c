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
	char *domain;
	char *out;

	if (size > 1024)
		return 0;

	domain = (char *) malloc(size + 1);
	assert(domain != NULL);

	if ((size & 3) == 0) {
		uint32_t *data0 = (uint32_t *) malloc(size + 4);
		char *asc = (char *) malloc(64);

		assert(data0 != NULL);
		assert(asc != NULL);

		idna_to_ascii_4i((uint32_t *)data, size / 4, asc, 0);
		idna_to_ascii_4i((uint32_t *)data, size / 4, asc, IDNA_ALLOW_UNASSIGNED|IDNA_USE_STD3_ASCII_RULES);

		free(asc);

		memcpy(data0, data, size);
		data0[size / 4] = 0;
		if (idna_to_ascii_4z(data0, &out, 0) == IDNA_SUCCESS)
			idn_free(out);
		if (idna_to_ascii_4z(data0, &out, IDNA_ALLOW_UNASSIGNED|IDNA_USE_STD3_ASCII_RULES) == IDNA_SUCCESS)
			idn_free(out);
		free(data0);
	}

	// 0 terminate
	memcpy(domain, data, size);
	domain[size] = 0;

	if (idna_to_ascii_8z(domain, &out, 0) == IDNA_SUCCESS)
		idn_free(out);
	if (idna_to_ascii_8z(domain, &out, IDNA_ALLOW_UNASSIGNED|IDNA_USE_STD3_ASCII_RULES) == IDNA_SUCCESS)
		idn_free(out);
	if (idna_to_ascii_lz(domain, &out, 0) == IDNA_SUCCESS)
		idn_free(out);
	if (idna_to_ascii_lz(domain, &out, IDNA_ALLOW_UNASSIGNED|IDNA_USE_STD3_ASCII_RULES) == IDNA_SUCCESS)
		idn_free(out);

	free(domain);

	return 0;
}
