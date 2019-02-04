import asyncio
import aiohttp
from tenacity import retry
from datetime import datetime
from itertools import cycle
import json

import logging
logging.basicConfig(
                    filename='retrieve_analyses.log',
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    filemode='w',
                    level=logging.INFO
)


VIRUSTOTAL_API_ENDPOINT = "https://www.virustotal.com/vtapi/v2/file/report"
BATCH_SIZE = 4          # VirusTotal allows 4 analyses per HTTP request


# Given a VirusShare md5 hash file, return a list of lists of BATCH_SIZE hashes
def batch_hashes(hashnum_first, hashnum_last):
    batches = []
    for hashnum in range(hashnum_first, hashnum_last + 1):
        with open(("hashes/VirusShare_00" + str(hashnum).zfill(3) + ".md5"),'r') as infile:
            # First 6 lines of hashes file are file descriptors
            hashes = [line.strip() for line in infile.readlines()[6:]]
        # Batch up the hashes in chunks of size batchsize
        batches.extend([(hashnum, hashes[i:i+BATCH_SIZE]) for i in range(0, len(hashes), BATCH_SIZE)])
    return batches


def distribute_batches(api_keys, batches):
    distributed_batches = {}
    for key in api_keys:
        distributed_batches[key] = []

    for key, batch in zip(cycle(api_keys), batches):
        distributed_batches[key].append(batch)
    return distributed_batches


@retry
async def retrieve_analysis(api_key, hashnum, hashes):
    resource_string = ','.join(hashes)
    params = {"resource": resource_string,
              "apikey": api_key}

    await(asyncio.sleep(60))
    logging.info('MAKING URL CALL for user {} and resource string {}'.format(api_key, resource_string))
    async with aiohttp.ClientSession() as session:
        async with session.get(VIRUSTOTAL_API_ENDPOINT, params=params) as response:
            raw_results = await response.text()
            logging.debug(raw_results)
            analyses = json.loads(raw_results)
            logging.info("API CALL COMPLETE for user {} and resource string {}".format(api_key, resource_string))
            with open("analyses/VirusShare_00" + str(hashnum).zfill(3) + ".ldjson",'a') as outfile:
                for i in range(BATCH_SIZE):
                    analyses[i]['md5'] = hashes[i]
                    outfile.write(json.dumps(analyses[i]) + "\n")
            logging.info("ANALYSIS WRITTEN TO DISK for user {} and resource string {}".format(api_key, resource_string))


async def run_queries(api_key, batches):
    for batch in batches:
        await retrieve_analysis(api_key, *batch)

if __name__ == '__main__':
    with open("keys",'r') as keyfile:
        api_keys = [line.strip() for line in keyfile]

    batches = batch_hashes(0,8)
    distributed = distribute_batches(api_keys, batches)

    loop = asyncio.get_event_loop()
    tasks = [run_queries(api_key, distributed[api_key]) for api_key in api_keys]
    loop.run_until_complete(asyncio.wait(tasks))
