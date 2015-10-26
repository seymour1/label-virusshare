import simplejson as json
import urllib
import urllib2
import time

def load_hashes():
    with open("VirusShare_00169.md5",'r') as file:
        hashes = [line.strip() for line in file.readlines()[6:]]
    return [hashes[i:i+25] for i in xrange(0, len(hashes), 25)]

def load_scan_ids():
    with open("out.txt",'r') as file:
        ids = [line.strip().split(',')[1] for line in file.readlines()\
                if line != "Never scanned\n"]
    return [ids[i:i+25] for i in xrange(0, len(ids), 25)]

def send_batch(batch):
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

    with open("out2.txt", 'a') as file:
        for item in json.loads(results):
            file.write(json.dumps(item) + "\n")

scan_ids = load_scan_ids()
for batch in scan_ids:
    send_batch(batch)
 
#batched_hashes = load_data()
#counter = 0
#for batch in batched_hashes:
#    print "Sending batch", counter
#    counter += 1
#    send_batch(batch)
#    time.sleep(15)
