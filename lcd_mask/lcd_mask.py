#!/usr/bin/env python3
# Copyright 2019 Two Sigma Investments, LP.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import re
import json
import itertools
import functools
import subprocess
from collections import Counter

# This tool finds the lowest commnon denominator among multiple CPUs
# and reports what needs to be masked for application to see uniform CPU
# features.

def compact(l):
    return [e for e in l if e]

def script_dir():
    return os.path.dirname(os.path.realpath(__file__))

def get_feature_defs():
    return json.loads(open(script_dir() + "/features.json").read())

def build_reg_features_lut(feature_defs):
    key_fn = lambda f: (f['leaf'], f['subleaf'], f['reg'])
    feature_defs = sorted(feature_defs, key=key_fn)
    reg_lut = {k:list(v) for (k,v) in itertools.groupby(feature_defs, key_fn)}
    return reg_lut

def extract_machine_features(cpuid_results, reg_features_lut):
    machine = {'features': set(), 'xsavearea': None}

    for cr in cpuid_results:
        for reg in ['eax', 'ebx', 'ecx', 'edx']:
            key = (cr['leaf'], cr['subleaf'], reg)
            reg_data = cr[reg]

            if key == (0x0d, 0, 'ecx'):
                machine['xsavearea'] = reg_data

            reg_feature_defs = reg_features_lut.get(key)
            if reg_feature_defs is None:
                continue

            for feature in reg_feature_defs:
                if reg_data & (1<<feature['bit']):
                    machine['features'].add(feature['name'])

    return machine


def parse_cpuid_line(line):
    m = re.match(r"^\s*0x(\w+) 0x(\w+): eax=0x(\w+) ebx=0x(\w+) ecx=0x(\w+) edx=0x(\w+)$", line)
    if m:
        return {'leaf': int(m.group(1), 16), 'subleaf': int(m.group(2), 16),
                'eax':  int(m.group(3), 16), 'ebx':     int(m.group(4), 16),
                'ecx':  int(m.group(5), 16), 'edx':     int(m.group(6), 16)}

def get_cpu_brand(path):
    try:
        brand = "unknown"
        family = "unknown"
        result = subprocess.Popen(["cpuid".format(script_dir()), '-f', path],
                                  stdout=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = result.communicate()
        for line in stdout.split("\n"):
            m = re.match(r"^\s*brand = \"(.+)\"$", line)
            if m:
                brand = m.group(1)
            m = re.match(r"^\s*\(synth\) = (.+)$", line)
            if m:
                family = m.group(1)

        return (brand, family)
    except Exception as e:
        return ("error ({})".format(e), "error")

def read_machine_features(path, reg_features_lut):
    lines = [line.strip() for line in open(path, 'r').readlines()]
    cpuids = compact([parse_cpuid_line(line) for line in lines])
    machine = extract_machine_features(cpuids, reg_features_lut)
    machine['name'] = path.split('/')[-1]
    machine['brand'], machine['family'] = get_cpu_brand(path)

    if not machine['features']:
        raise RuntimeError("No features detected for {}".format(path))

    return machine

def simplify_mask(mask, feature_defs):
    feature_deps = {f['name']: f['dep'] for f in feature_defs}

    new_mask = set()
    for m in mask:
        dep = feature_deps[m]
        if dep not in mask:
            new_mask.add(m)

    return new_mask

def compute_mask(machines, feature_defs):
    features = [m['features'] for m in machines]
    common_features = functools.reduce(lambda a,b: a&b, features)

    mask = set()
    for m in machines:
        mask |= m['features'] - common_features

    mask = simplify_mask(mask, feature_defs)

    if "xsave" in common_features:
        max_xsavearea = max([m['xsavearea'] for m in machines])

        if any([m['xsavearea'] != max_xsavearea for m in machines]):
            mask.add("xsavearea={}".format(max_xsavearea))

    return mask

def print_breakdown(features, total=None):
    if total is None:
        total = len(features)
    counts = Counter(features)
    width = max(len(f) for f in features) + 2
    for feature,count in reversed(sorted(counts.items(), key=lambda e: e[1])):
        print("{feature:{width}} {count:>4} ({perc:.0f}%)".format(
            width=width, feature=feature, count=count, perc=100*count/total))


def main():
    if len(sys.argv) <= 1:
        raise RuntimeError("Usage: lcd_mask.py [FILE]... # one file per machine, generated with 'cpuid -r -1'")

    cpuid_paths = sys.argv[1:]
    feature_defs = get_feature_defs()
    reg_features_lut = build_reg_features_lut(feature_defs)
    machines = [read_machine_features(path, reg_features_lut) for path in cpuid_paths]

    mask = compute_mask(machines, feature_defs)

    print_breakdown(["Total machines" for m in machines])

    print("\n----------------[ BRAND ]----------------")
    print_breakdown([m['brand'] for m in machines])

    print("\n----------------[ FAMILY ]---------------")
    print_breakdown([m['family'] for m in machines])

    if not mask:
        print("\nAll machines offer the same cpu feature set")
        return

    print("\n-----------[ UNIQUE FEATURES ]-----------")
    print_breakdown([f for m in machines for f in m['features'] if f in mask], len(machines))

    print("\n-----------[ RECOMMENDED MASK ]----------")
    print(",".join(sorted(mask)))

if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        print("FAILED:", e)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(1)
