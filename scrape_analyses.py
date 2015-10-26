import simplejson as json
import urllib
import urllib2
import time
import argparse

BATCH_SIZE = 25          # VirusTotal allows 25 analyses per HTTP request
BATCHES_PER_DAY = 230    # Can make 5760 requests/day = 230 batches

# Given a VirusShare md5 hash file, return a list of lists of BATCH_SIZE hashes
def batch_hashes(hash_num):
    with open(("hashes/VirusShare_00" + str(hash_num).zfill(3) + ".md5"),'r') as file:
        # First 6 lines of hashes file are file descriptors
        hashes = [line.strip() for line in file.readlines()[6:]]
    # Batch up the hashes in chunks of size batchsize
    return [hashes[i:i+BATCH_SIZE] for i in xrange(0, len(hashes), BATCH_SIZE)]

# Given a batch of hashes, retrieve latest analyses for those hashes
# to VirusTotal in one HTTP request.
# Straight from VirusTotal API documentation.
def retrieve_batch(batch):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    with open("api_key",'r') as key_file:
        api_key = key_file.readlines()[0].strip()
    resource_str = ','.join(batch)
    parameters = {"resource": resource_str,
                  "apikey": api_key}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    results = response.read()
    return results

def main(hash_num, chunk_num):

    if hash_num < 0 or hash_num > 210:
        raise ValueError('Invalid argument, hash number must be in range(0, 210)')

    if chunk_num < 0 or chunk_num > 11:
        raise ValueError('Invalid argument, chunk number must be in range(0, 11)')

    start_batch = chunk_num * BATCH_SIZE * BATCHES_PER_DAY
    end_batch = (chunk_num + 1) * BATCH_SIZE * BATCHES_PER_DAY

    # For each batch of hashes...
    for batch in batch_hashes(hash_num)[start_batch:end_batch]:

        # Request the most recent analyses of those hashes from VirusTotal
        results = json.loads(retrieve_batch(batch))

        # For each analysis...
        for i in xrange(BATCH_SIZE):
            results[i]['md5'] = batch[i]  # Add the MD5 hash to the VT results, to easily map to VirusShare corpus

            # Write the analysis to the corresponding file on disk, to be easily unsplit later
            with open("analyses/VirusShare_00" + str(chunk_num).zfill(3) + ".ldjson." + str(batch_num),'a') as file:
                file.write(json.dumps(results[i]) + "\n")

        # Throttle down to respect 4 HTTP requests/minute
        time.sleep(15)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'Retrieve results for single VirusShare chunk')
    parser.add_argument('hash_num', help='The file number for the VirusShare hashes, i.e. {0..210}')
    parser.add_argument('chunk_num', help='Which chunk of batches to work on, i.e. {0..11}')
    args = parser.parse_args()
    main(int(args.hash_num), int(args.chunk_num))
    exit()
