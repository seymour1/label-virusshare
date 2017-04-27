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
# Straight from VirusTotal API documentation, except for retry decorator
@retry(stop_max_attempt_number=5)
def retrieve_batch(batch, api_key):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    resource_str = ','.join(batch)
    parameters = {"resource": resource_str,
                  "apikey": api_key}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req, timeout = 20)
    results = response.read()
    return results

# Thread-Safe function for removing a batch from the queue and sending to VirusTotal.
def label_batch(in_q, out_q, api_key):
    while not in_q.empty():
        batch = in_q.get()

        # Request the most recent analyses of those hashes from VirusTotal
        results = json.loads(retrieve_batch(batch, api_key))
        # For each analysis...
        for i in xrange(BATCH_SIZE):
            results[i]['md5'] = batch[i]  # Add the MD5 hash to the VT results, to easily map to VirusShare corpus
        out_q.put(results)
        in_q.task_done()
        # Throttle down to respect 4 HTTP requests/minute
        time.sleep(15)

# Thread-Safe handler for writing results to file.
def output_results(in_q, out_q, hashnum):
    # Write the analysis to the corresponding file on disk, to be easily unsplit later
    with open("analyses/VirusShare_00" + str(hashnum).zfill(3) + ".ldjson",'w') as outfile:
        while not in_q.empty():
            while not out_q.empty():
                for result in out_q.get():
                    outfile.write(json.dumps(result) + "\n")
                    outfile.flush()
                out_q.task_done()

def main(hashnum):

    if os.path.exists("analyses/VirusShare_00" + str(hashnum).zfill(3) + ".ldjson"):
        raise ValueError('The chosen hash number has already been analyzed. Try another.')

    in_q = Queue()
    out_q = Queue()

    with open("keys.txt",'r') as keyfile:
        api_keys = [line.strip() for line in keyfile]

    for batch in batch_hashes(hashnum):
        in_q.put(batch)

    workers = {}
    for api_key in api_keys:
        workers[api_key] = Thread(target=label_batch, args=(in_q, out_q, api_key))
        workers[api_key].setDaemon(True)
        workers[api_key].start()

    out_worker = Thread(target=output_results, args=(in_q, out_q, hashnum))
    out_worker.setDaemon(True)
    out_worker.start()

    in_q.join()
    out_q.join()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'Retrieve results for single VirusShare md5 file')
    parser.add_argument('-n','--hashnum', help='Set file number', required=True)
    args = parser.parse_args()
    main(args.hashnum)
    exit()



