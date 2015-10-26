import simplejson as json
import urllib
import urllib2
import time
import argparse

BATCH_SIZE = 25

# Given a VirusShare md5 hash file, return a list of lists of BATCH_SIZE hashes
def batch_hashes(chunk_num):
    with open("hashes/VirusShare_00" + chunk_num.zfill(3) + ".md5",'r') as file:
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

def main(chunk_num):

    if chunk_num < 0 or chunk_num > 210:
        raise ValueError('Invalid argument, chunk number must be in range(0, 210)')

    for batch in batch_hashes[1]:
        results = retrieve_batch(batch)
        for i in xrange(BATCH_SIZE):
            result = json.loads(results)
            result['md5'] = batch[i]
            with open("analyses/VirusShare_00" + chunk_num.zfill(3) + ".ldjson",'a') as file:
                file.write(json.dumps(result) + "\n")

        # Throttle down to respect 4 HTTP requests/minute
        time.sleep(15)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'Retrieve results for single VirusShare chunk')
    parser.add_argument('chunk_num', help='The VirusShare chunk to work on, i.e. {0..210}')
    args = parser.parse_args()
    main(args.chunk_num)
    exit()
