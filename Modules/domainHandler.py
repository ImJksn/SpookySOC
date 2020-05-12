"""
    domainHandler.py
    Purpose: Perform domain reputation checks against several services.
    Author: Jackson Nestler
    Version: 0.0.1
    Source: https://gitlab.com/jksn/spookySOC
"""
import requests
import time
import shodan
from nslookup import Nslookup
from Modules import text
from Modules import ipHandler
import spooky

def getDNSARecords(domain):
    # CONFIGURE DNS RESOLVER
    # Modify the following line. Defaults to Cloudflare and Google. Multiple are included for redundancy, but only one is required.
    dns_query = Nslookup(dns_servers=["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"])
    a_records = dns_query.dns_lookup(domain)
    return a_records.answer

def virusTotalDomain(domain, apikey):

    text.printGreen("VIRUSTOTAL: https://www.virustotal.com/gui/")
    headers = {'x-apikey': apikey}
    url = 'https://www.virustotal.com/api/v3/domains/%s' %domain
    response = requests.get(url=url, headers=headers)
    if response.status_code == 200:
        returned = response.json()
        print("Domain: " + str(returned['data']['id']))
        print("Reputation: " + str(returned['data']['attributes']['reputation']))
        print("Harmless Votes: " + str(returned['data']['attributes']['total_votes']['harmless']))
        print("Malicious Votes: " + str(returned['data']['attributes']['total_votes']['malicious']))
        epochRegistrationDate = int(str(returned['data']['attributes']['creation_date']))
        humanRegDate = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epochRegistrationDate))
        print("Registered at: " + humanRegDate + " UTC.")

def threatMinerDomain(domain):
    text.printGreen("THREATMINER: https://www.threatminer.org/")
    # API Documentation: https://www.threatminer.org/api.php
    # Request Type ("RT") 2: Passive DNS
    # RT 4: Related Samples (Hash Only)
    # RT 5: Subdomains
    # Get DNS information from Passive DNS collection.
    url = "https://api.threatminer.org/v2/domain.php"
    params = {'q': domain, 'rt': '2'}
    response = requests.get(url=url, params=params)
    if response.status_code == 200:
        returned = response.json()
        if returned['status_code'] == "200":
            totalAssocIP = 1
            for value in returned['results']:
                print ("Associated IP #" + str(totalAssocIP) + ": " + str(value['ip']))
                totalAssocIP += 1
        else:
            text.printRed("  * No passive DNS records found.")
    # Get associated hash values.
    params = {'q': domain, 'rt': '4'}
    response = requests.get(url=url, params=params)
    if response.status_code == 200:
        returned = response.json()
        if returned['status_code'] == 200:
            totalAssocHash = 1
            for value in returned['results']:
                print("Associated Hash #" + str(totalAssocHash) + ": " + str(value))
                totalAssocHash += 1
    # Get associated subdomains.
    params = {'q': domain, 'rt': '5'}
    response = requests.get(url=url, params=params)
    if response.status_code == 200:
        returned = response.json()
        if returned['status_code'] == 200:
            totalAssocSubdomains = 1
            for value in returned['results']:
                print("Associated subdomain #" + str(totalAssocSubdomains) + ": " + str(value))
                totalAssocSubdomains += 1
        else:
            text.printRed("  * No associated subdomains found.")
    # Get associated APTNotes.
        params = {'q': domain, 'rt': '6'}
        response = requests.get(url=url, params=params)
        if response.status_code == 200:
            returned = response.json()
            if returned['status_code'] == 200:
                text.printGreen("  * We found some APTNotes, a collection of public reports on APTs! ThreatMiner provides this through an API.")
                text.printGreen("  * APTNotes is available on GitHub: https://github.com/aptnotes - Full credit to the original authors.")
                totalAssocReports = 1
                for value in returned['results']:
                    print("Associated APTNote #" + str(totalAssocReports) + ": " + str(value['filename'] + " was published in " + str(value['year'])))
                    print("[PDF WARNING] Download available at: " + str(value['URL']))
                    totalAssocReports += 1
            else:
                text.printRed("  * No associated APTNotes found.")

def hybridAnalysisDomain(domain, apikey):
    text.printGreen("HYBRID ANALYSIS: https://www.hybrid-analysis.com/")
    text.printGreen("  * Utilizes the CrowdStrike Falcon Sandbox.")
    url = "https://www.hybrid-analysis.com/api/v2/search/terms"
    payload = 'domain=%s' % domain
    headers = {
        'api-key': apikey,
        'User-Agent': 'CrowdStrike Falcon',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    response = requests.request("POST", url=url, headers=headers, data=payload)
    if response.status_code == 200:
        returned = response.json()
        if returned['count'] > 0:
            text.printGreen("  * Showing results whose threat score is above 10.")
            threatDict = {}
            for eachresult in returned['result']:
                if eachresult['threat_score'] > 10:
                    jobID = eachresult['job_id']
                    threatScore = eachresult['threat_score']
                    threatDict[jobID] = threatScore
                    sortedThreatDict = sorted(threatDict.items(), key=lambda item: item[1])
                    for key, value in sortedThreatDict:
                        print ("Job ID: " + str(key) + " with threat score of " + str(value) + " and SHA256 hash of " + str(eachresult['sha256']))
        if returned['count'] == 0:
            text.printRed("  * No results for that IP address on Hybrid-Analysis.")

def shodanDomain(domain, apikey):
    api = shodan.Shodan(apikey)
    text.printGreen("SHODAN: https://www.shodan.io/")
    text.printGreen("  * Maximum associated IPs returned is 100.")
    try:
        # Search Shodan
        results = api.search(domain)
        # Show the results
        print('Results found: {}'.format(results['total']))
        totalAssocIP = 1
        for result in results['matches']:
                print('IP #{}: {}'.format(totalAssocIP, result['ip_str']))
                totalAssocIP += 1
    except shodan.APIError as e:
        print('Error: {}'.format(e))

def checkAssociatedIP(addr):
            API_KEYS_LIST = spooky.readAPIKeys()
            ipHandler.checkPrivate(addr)

            #ipHandler.abuseIPDB(addr, API_KEYS_LIST['ABUSEIPDB'])
            # We don't need to check Abuse a second time, as it's already performed by this point.
            ipHandler.virusTotalIP(addr, API_KEYS_LIST['VT'])
            ipHandler.threatMinerIP(addr)
            ipHandler.hybridAnalysisIP(addr, API_KEYS_LIST['HYBRID'])
            ipHandler.urlhausIP(addr)
            ipHandler.shodanIP(addr, API_KEYS_LIST['SHODAN'])
            ipHandler.proxyCheck(addr)
