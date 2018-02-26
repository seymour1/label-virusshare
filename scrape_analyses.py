import json
import urllib
import urllib2
import time
import argparse
import os.path
import random
import socket
from retrying import retry
import sys
import pprint
from Queue import Queue
from threading import Thread
import time
import datetime

BATCH_SIZE = 4          # VirusTotal allows 4 analyses per HTTP request

# Given a VirusShare md5 hash file, return a list of lists of BATCH_SIZE hashes
def batch_hashes(hashnum):
    with open(("hashes/VirusShare_00" + str(hashnum).zfill(3) + ".md5"),'r') as infile:
        # First 6 lines of hashes file are file descriptors
        hashes = [line.strip() for line in infile.readlines()[6:]]
    # Batch up the hashes in chunks of size batchsize
    return [hashes[i:i+BATCH_SIZE] for i in xrange(0, len(hashes), BATCH_SIZE)]

# Given a batch of hashes, retrieve latest analyses for those hashes
# to VirusTotal in one HTTP request.
@retry(stop_max_attempt_number=5)
def retrieve_batch(batch, api_key):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    resource_str = ','.join(batch)
    parameters = {"resource": resource_str,
                  "apikey": api_key}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req, timeout = 20)
    raw_results = response.read()
    results = json.loads(raw_results)
    for i in xrange(BATCH_SIZE):
        results[i]['md5'] = batch[i]
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'Retrieve results for single VirusShare md5 file')
    parser.add_argument('keyfile', help='Filepath for key')
    parser.add_argument('hashnum', help='hashfile to work on')
    args = parser.parse_args()

    if os.path.exists("analyses/VirusShare_00" + str(args.hashnum).zfill(3) + ".ldjson"):
        raise ValueError('The chosen hash number has already been analyzed. Try another.')

    with open(args.keyfile,'r') as keyfile:
        api_key = [line.strip() for line in keyfile][0]

    with open("analyses/VirusShare_00" + str(args.hashnum).zfill(3) + ".ldjson",'w') as outfile:
        for batch in batch_hashes(args.hashnum):
            for result in retrieve_batch(batch, api_key):
                outfile.write(json.dumps(result) + "\n")
            time.sleep(60)
