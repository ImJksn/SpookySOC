"""
    hashHandler.py
    Purpose: Perform hash reputation lookups against several services.
    Author: Jackson Nestler
    Version: BETA
    Source: https://gitlab.com/jksn/spookySOC
"""
"""BETA INFORMATION

SpookySOC is currently in BETA. Changes may occur, including but not limited to the following:
- Lookup services are added or removed.
- Format of returned results may change.
- What information is returned may change.
- Code format may change.
- License may change.

As a BETA TESTER, I simply request the following:
- Follow the LICENSE file from the Git repository -> GNU AGPLv3 license.
- Report bugs as they occur. Feel free to open a pull request!
- Give copious feedback, as much as you can. Good, bad, ugly, "unimportant", whatever!

Thanks a bunch! You're awesome.

- Jackson Nestler (@jksn)

"""

from Modules import text
import requests
import time

def virusTotalHash(hash, apikey):

    text.printGreen("VIRUSTOTAL: https://www.virustotal.com/gui/")
    headers = {'x-apikey': apikey}
    url = 'https://www.virustotal.com/api/v3/files/%s' %hash
    response = requests.get(url=url, headers=headers)
    if response.status_code == 200:
        returned = response.json()
        print("Hash: " + str(returned['data']['id']))
        print("Analysis URL: " + str(returned['data']['links']['self']))
        print("Last Analyzed: " + time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(returned['data']['attributes']['last_analysis_date'])))
        print("Last Analysis Stats: ")
        print("  - Engines Failed to Analyze: " + str(returned['data']['attributes']['last_analysis_stats']['failure']))
        print("  - Engines Deemed Malicious: " + str(returned['data']['attributes']['last_analysis_stats']['malicious']))
        print("  - Engines Deemed Suspicious: " + str(returned['data']['attributes']['last_analysis_stats']['suspicious']))
        print("  - Engines Did Not Determine Malicious: " + str(returned['data']['attributes']['last_analysis_stats']['undetected']))
        print("Community Reputation: " + str(returned['data']['attributes']['reputation']))
        print("Community Harmless Votes: " + str(returned['data']['attributes']['total_votes']['harmless']))
        print("Community Malicious Votes: " + str(returned['data']['attributes']['total_votes']['malicious']))

def threatMinerHash(filehash):
    text.printGreen("THREATMINER: https://www.threatminer.org/")
    # API Documentation: https://www.threatminer.org/api.php
    # Request types ("RT") are different between domains, IPs, and hashes!
    # RT 1: Metadata
    # RT 2: HTTP Traffic
    # RT 3: Hosts (domains and IPs)
    # RT 5: Registry Keys
    # RT 6: AV Detections
    # RT 7: Report Tagging
    url = "https://api.threatminer.org/v2/sample.php"

    # Get metadata.
    params = {'q': filehash, 'rt': '1'}
    response = requests.get(url=url, params=params)
    if response.status_code == 200:
        returned = response.json()
        if returned['status_code'] == 200:
            for value in returned['results']:
                print ("File Type: " + str(value['file_type']))
                print ("File Name: " + str(value['file_name']))
                print ("Last Analyzed: " + str(value['date_analyzed']))
        else:
            text.printRed("  * No metadata was found.")

    # Get HTTP Traffic.
    params = {'q': filehash, 'rt': '2'}
    response = requests.get(url=url, params=params)
    if response.status_code == 200:
        returned = response.json()
        if returned['status_code'] == 200:
            contactedDomainCount = 1
            for value in returned['results']['http_traffic']:
                contactedDomain = value['domain']
                print("Contacted Domain #" + str(contactedDomainCount) + ": " + contactedDomain)
                contactedDomainCount += 1
        else:
            text.printRed("  * No HTTP traffic records were found.")
    
    # Get Associated Hosts
    params = {'q': filehash, 'rt': '3'}
    response = requests.get(url=url, params=params)
    if response.status_code == 200:
        returned = response.json()
        if returned['status_code'] == 200:
            contactedDomainCount = 1
            for value in returned['results']['domains']:
                contactedDomain = value['domain']
                resolvedDomain = value['ip']
                print("Contacted Domain #" + str(contactedDomainCount) + ": " + contactedDomain + "at IP " + str(resolvedDomain))
                contactedDomainCount += 1
            contactedIPsCount = 1
            for value in returned['results']['hosts']:
                print("Contacted IP #" + str(contactedIPsCount) + ": " + value)
        else:
            text.printRed("  * No Associated Domains or IPs Found.")