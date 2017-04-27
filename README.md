# label-virusshare

A project to label the VirusShare malware corpus using VirusTotal's public API.

# Description

VirusShare (http://virusshare.com/) consists of a large number of malicious executable files. However, these files aren't labeled with their malware family.

VirusTotal (https://www.virustotal.com/) is a service which runs executables through a large number of antivirus vendors, and returns whether each AV detected the file as being malicious and the labeling of the file by the AV. VirusTotal has a public API which limits the number of requests that an individual can make daily/monthly.

This project aims to provide the VirusTotal analyses for each file in the VirusShare corpus, so that VirusShare can more easily be used for supervised machine learning.

# Requirements
* Python 2.7 (will not currently work under Python 3.0)
* Active VirusTotal API public key (PLEASE do not use a VT private API key, for licensing issues)

# To Run:
1. Clone the repository.
2. In the root of the repository, copy and paste your API key into a file.
3. Run scrape\_analyses.py with your key file as a parameter, and optionally a hash/chunk pair. This should use up your entire VirusTotal quota for the day, and will label a corresponding section of the VirusShare data.
