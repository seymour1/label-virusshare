#!/bin/bash

for i in $(seq 0 210);
do
  for j in $(seq 0 11);
  do
    if [ ! -f analyses/VirusShare_00`printf %03d $i`.ldjson.$j ]; then
      echo "$i $j"
    fi
  done
done
