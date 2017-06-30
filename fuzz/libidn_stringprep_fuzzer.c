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

#include "stringprep.h"
#include "pr29.h"
#include "tld.h"
#include "idn-free.h"
#include "fuzzer.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *wdata = (char *) malloc(size + 1);
	char *label = (char *) malloc(size + 1);
	char *out;
	size_t errpos;

	assert(wdata != NULL);
	assert(label != NULL);

	// 0 terminate
	memcpy(label, data, size);
	label[size] = 0;

	stringprep_check_version(label);
	stringprep_strerror(0);
	stringprep_strerror(-1);

	if (stringprep_profile(label, &out, "Nodeprep", 0) == STRINGPREP_OK)
		idn_free(out);

	pr29_8z(label); /* internally calls stringprep_utf8_to_ucs4() */
	if (tld_get_z(label, &out) == TLD_SUCCESS) /* internally calls tld_get_4() */
		idn_free(out);
	const Tld_table *tld = tld_default_table("fr", NULL);
	tld_check_8z(label, &errpos, NULL);
	tld_check_lz(label, &errpos, NULL);

	memcpy(wdata, data, size);
	wdata[size] = 0;
	stringprep(wdata, size, 0, stringprep_nameprep);
	memcpy(wdata, data, size);
	wdata[size] = 0;
	stringprep(wdata, size, STRINGPREP_NO_UNASSIGNED, stringprep_nameprep);

	if ((size & 3) == 0) {
		uint32_t *u32 = (uint32_t *) malloc(size + 4);

		assert(u32 != NULL);

		memcpy(u32, data, size);
		u32[size / 4] = 0;
		stringprep_4zi(u32, size / 4, 0, stringprep_xmpp_nodeprep);

		memcpy(u32, data, size);
		u32[size / 4] = 0;
		if (tld_get_4z(u32, &out) == TLD_SUCCESS) /* internally calls tld_get_4() */
			idn_free(out);

		tld_check_4tz(u32, &errpos, tld);
		tld_check_4z(u32, &errpos, NULL);

		free(u32);
	}

	free(label);
	free(wdata);

	return 0;
}
