import json
import argparse
import logging
import glob

# Logging Information
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(levelname)s: %(message)s')

fh = logging.FileHandler('test_hashes.log')
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)
logger.addHandler(fh)

ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(formatter)
logger.addHandler(ch)

parser = argparse.ArgumentParser()
parser.add_argument("hash_num", help="file that we want to verify")
args = parser.parse_args()

hashes = set()
hash_num = args.hash_num

logger.info("Verifying consistency for VirusShare_00" + str(hash_num).zfill(3))
logger.debug("Generating hashes from ../hashes/VirusShare_00" + str(hash_num).zfill(3) + ".md5")
with open(("../hashes/VirusShare_00" + str(hash_num).zfill(3) + ".md5"),'r') as file:
    for line in file.readlines()[6:]:
        hashes.add(line.strip())

for filename in glob.glob("../analyses/VirusShare_00" + str(hash_num).zfill(3) + ".*"):
    logger.debug("Removing hashes from " + filename)
    with open(filename,'r') as file:
        for line in file.readlines():
            hashes.remove(json.loads(line.strip())["md5"])

if len(hashes) == 0:
    logger.info("VirusShare_00" + str(hash_num).zfill(3) + ".ldjson is consistent with hashfile")
else:
    logger.error("VirusShare_00" + str(hash_num).zfill(3) + ".ldjson is inconsistent with hashfile")
