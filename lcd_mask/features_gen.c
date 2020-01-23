/*
 * Copyright 2019 Two Sigma Investments, LP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include <string.h>
#include <err.h>

#include "../src/linux/cpufeatures.h"
#include "../src/linux/cpuid.h"
#include "../src/linux/cpuid-deps.c"
#include "../src/linux/capflags.c"

static bool has_feature_register_mask(int feature)
{
	return !!reverse_cpuid[feature/32].leaf;
}

static const char *find_dependency(int feature)
{
	for (const struct cpuid_dep *d = cpuid_deps; d->feature; d++) {
		if (d->feature == feature)
			return x86_cap_flags[d->depends];
	}
	return NULL;
}

static int gen_features(FILE *f)
{
	fprintf(f, "[\n");
	bool need_comma = false;
	for (int feature = 0; feature < NCAPINTS*32; feature++) {
		const char *name = x86_cap_flags[feature];

		if (!has_feature_register_mask(feature) || !name)
			continue;

		const struct cpuid_reg *cr = &reverse_cpuid[feature/32];
		const char *dependency = find_dependency(feature);

		if (need_comma)
			fprintf(f, ",\n");

		fprintf(f, "{");

#define PROP_LAST(key,fmt,val) fprintf(f, "\"" key "\":" fmt, val)
#define PROP(key,fmt,val) PROP_LAST(key, fmt ",", val)

		PROP("name",    "\"%s\"", name);
		PROP("leaf",    "%u",     cr->leaf);
		PROP("subleaf", "%u",     cr->subleaf == SL_UNUSED ? 0 : cr->subleaf);
		PROP("reg",     "\"%s\"", cr->reg == CPUID_EAX ? "eax" :
					  cr->reg == CPUID_EBX ? "ebx" :
					  cr->reg == CPUID_ECX ? "ecx" :
					  cr->reg == CPUID_EDX ? "edx" : NULL);
		PROP("bit",     "%u",     feature%32);
		if (dependency)
			PROP_LAST("dep", "\"%s\"", dependency);
		else
			PROP_LAST("dep", "null", NULL);
		fprintf(f, "}");

		need_comma = true;

	}
	fprintf(f, "\n]");
}

int main(int argc, const char *argv[])
{
	if (argc != 2)
		errx(1, "Usage: feature_gen [OUTPUT]");

	FILE *f = fopen(argv[1], "w");
	gen_features(f);
	
	return 0;
}
