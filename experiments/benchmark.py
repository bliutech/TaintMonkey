#!/usr/bin/env python3
"""
python experiments/benchmark.py
"""

import os
from collections import defaultdict


# Collect all test cases in the dataset/ directory
# and group them by the CWE they are testing.
def collect_test_cases():
    test_cases = defaultdict(list)
    for root, dirs, files in os.walk("dataset/"):
        for file in files:
            if file == "app.py":
                cwe = os.path.basename(os.path.dirname(root))
                test_case_name = os.path.basename(root)
                test_case_path = os.path.join(root, file)
                test_cases[cwe].append((test_case_name, test_case_path))
    return test_cases


print("Collecting test cases...")
test_cases = collect_test_cases()
print(f"Found {len(test_cases)} CWEs with test cases.")
for cwe, cases in test_cases.items():
    print(f"CWE: {cwe} - {len(cases)} test cases")
    for case_name, case_path in cases:
        print(f"  - {case_name}: {case_path}")
