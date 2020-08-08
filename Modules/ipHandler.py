"""
    ipHandler.py
    Purpose: Perform IP reputation checks against several services.
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

import requests
import ipaddress
import IP2Proxy
import shodan
from Modules import text



def checkPrivate(ipaddr):

    addr = ipaddress.ip_address(ipaddr)
    if addr.is_private:
        text.printRed("The IP address specified is a private address, defined in RFC1918. \n" +
        "Your results would be invalid, as each private network is different and threat intelligence cannot inspect each. \n"
        "  * Stopping execution with exit code 1.")
        exit(1)
    if addr.is_multicast:
        text.printRed ("The address specified is a multicast address. We'll continue, but be aware that errors may occur.")

def abuseIPDB(ipaddr, apikey):

    text.printGreen("ABUSE IP DATABASE: https://www.abuseipdb.com/")
    params = {'ipAddress': ipaddr, 'maxAgeInDays': 90}
    headers = {'Accept': 'application/json', 'Key': apikey}
    url = 'https://api.abuseipdb.com/api/v2/check'
    response = requests.get(url=url, headers=headers, params=params)
    if response.status_code == 200:
        returned = response.json()
        #print("IP: " + str(returned['data']['ipAddress']))
        print("Reports in 90d: " + str(returned['data']['totalReports']))
        print("Last Report: " + str(returned['data']['lastReportedAt']))
        print("Confidence of Abuse: " + str(returned['data']['abuseConfidenceScore']) + "%")

def virusTotalIP(ipaddr, apikey):

    text.printGreen("VIRUSTOTAL: https://www.virustotal.com/gui/")
    headers = {'x-apikey': apikey}
    url = 'https://virustotal.com/api/v3/ip_addresses/%s' %ipaddr
    response = requests.get(url=url, headers=headers)
    if response.status_code == 200:
        returned = response.json()
        print("IP: " + str(returned['data']['id']))
        print("Reputation: " + str(returned['data']['attributes']['reputation']))
        print("Harmless Votes: " + str(returned['data']['attributes']['total_votes']['harmless']))
        print("Malicious Votes: " + str(returned['data']['attributes']['total_votes']['malicious']))

def threatMinerIP(ipaddr):
    text.printGreen("THREATMINER: https://www.threatminer.org/")
    # API Documentation: https://www.threatminer.org/api.php
    # Request types ("RT") are different between domains, IPs, and hashes!
    # RT 1: WHOIS
    # RT 2: Passive DNS
    # RT 4: Related Samples (Hash Only)
    url = "https://api.threatminer.org/v2/host.php"
    # Get WHOIS.
    params = {'q': ipaddr, 'rt': '1'}
    response = requests.get(url=url, params=params)
    if response.status_code == 200:
        returned = response.json()
        if returned['status_code'] == 200:
            for value in returned['results']:
                print ("ORG Name: " + str(value['org_name']))
                print ("Registrar: " + str(value['register']))
        else:
            text.printRed("  * No WHOIS information was found.")
    # Get Passive DNS.
    params = {'q': ipaddr, 'rt': '2'}
    response = requests.get(url=url, params=params)
    if response.status_code == 200:
        returned = response.json()
        if returned['status_code'] == 200:
            totalAssoc = 1
            for value in returned['results']:
                assocDomain = value['domain']
                print("Associated Domain #" + str(totalAssoc) + ": " + assocDomain)
                totalAssoc += 1
        else:
            text.printRed("  * No passive DNS records were found.")
    # Get related samples (hash only)
    params = {'q': ipaddr, 'rt': '4'}
    response = requests.get(url=url, params=params)
    if response.status_code == 200:
        returned = response.json()
        if returned['status_code'] == 200:
                totalAssoc = 1
                for assocHash in returned['results']:
                    print ("Associated Hash #" + str(totalAssoc) + ": " + assocHash)
                    totalAssoc += 1
        else:
            text.printRed("  * No related samples were found.")

def hybridAnalysisIP(ipaddr, apikey):
    text.printGreen("HYBRID ANALYSIS: https://www.hybrid-analysis.com/")
    text.printGreen("  * Utilizes the CrowdStrike Falcon Sandbox.")
    url = "https://www.hybrid-analysis.com/api/v2/search/terms"
    payload = 'host=%s' % ipaddr
    headers = {
        'api-key': apikey,
        'User-Agent': 'CrowdStrike Falcon',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    response = requests.request("POST", url=url, headers=headers, data=payload)
    if response.status_code == 200:
        returned = response.json()
        if returned['count'] > 0:
            text.printGreen("Showing results whose threat score is above 10.")
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

def urlhausIP(ipaddr):
    text.printGreen("URLHAUS: https://urlhaus.abuse.ch/ \n" +
    "  * Getting the URLHAUS list. This is large and can take a moment to download based on your connection.")
    response = requests.get("https://urlhaus.abuse.ch/downloads/text/")
    if response.status_code == 200:
        returned = response.text
        tryFind = returned.find(ipaddr)
        if tryFind == -1:
            text.printRed("Did not find any results in URLHaus.")
        if tryFind > -1:
            text.printGreen("Found the IP beginning at character #" + str(tryFind) + ". Search the full site for the IP here: https://urlhaus.abuse.ch/browse/ \n"
            + "No further searching against URLHaus is done to respect the team's wishes.")

def shodanIP(ipaddr, apikey):
    api = shodan.Shodan(apikey)
    text.printGreen("SHODAN: https://www.shodan.io/")
    text.printGreen("  * Maximum associated IPs returned is 100.")
    try:
        print (api.host(ipaddr))
    except:
        text.printRed("No information is available for the IP address.")

def proxyCheck(ipaddr):
    text.printGreen("IP2Proxy: https://github.com/ip2location/ip2proxy-python")
    try:
        db = IP2Proxy.IP2Proxy()
        db.open("IP2PROXY-LITE-PX8.BIN")
        record = db.get_all(ipaddr)
        if str(record['is_proxy']) == "1":
            print ("  * Determined this is a proxy based on the IP2Proxy database.")
            print ('Proxy Type: ' + record['proxy_type'])
            print ('Country Code: ' + record['country_short'])
            print ('Country Name: ' + record['country_long'])
            print ('Region Name: ' + record['region'])
            print ('City Name: ' + record['city'])
            print ('ISP: ' + record['isp'])
            print ('Domain: ' + record['domain'])
            print ('Usage Type: ' + record['usage_type'])
            print ('ASN: ' + record['asn'])
            print ('AS Name: ' + record['as_name'])
            print ('Last Seen: ' + record['last_seen'])
        elif str(record['is_proxy']) != "1":
            text.printRed ("  * Determined this is not a proxy based on the reputation .BIN file referenced.")
        else:
            text.printRed ("  * Encountered an error while checking if the IP was a proxy.")
    except Exception as e:
        print(e)
        return
    
