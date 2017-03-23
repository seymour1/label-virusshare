#!/bin/bash

# This script builds and verifies that all hashes are included
# for each hash file.
for i in {000..283}; do
    python test_hashes.py $i
done
