#!/bin/bash

#source /home/seymour1/label/env/bin/activate
cd /home/seymour1/label

declare -A USERS

USERS=([0]=denmark1 [1]=frankz2 [2]=jcory1 [3]=jjseymour3 [4]=julio3 [5]=jwenzel1 [6]=kchu2 [7]=lcook1 [8]=nasif1 [9]=nicholas [10]=pankaj [11]=pw97976 [12]=tadams2 [13]=svallab1 [14]=rmurph2 [15]=arti6 [16]=jack_schmandt [17]=docfink [18]=brookew1 [19]=tong2 [20]=seth_jenkins [21]=mcpat1 [22]=dad)

for hashnum in $(seq 253 23 305); do
  for K in "${!USERS[@]}"; do
    python scrape_analyses.py key/${USERS[$K]} $(($hashnum + $K)) &
  done
  wait
  echo "All users completed chunks! Starting next batch ($hashnum)."
done
echo ${USERS[1]}

exit 0
