"""
    ipHandler.py
    Purpose: Module to handle IP lookups and parsing.
    Author: Jackson Nestler
"""

import requests
import ipaddress
import IP2Proxy
from shodan import Shodan
from colorama import Fore, Back, Style

def checkPrivate(ipaddr):

    addr = ipaddress.ip_address(ipaddr)
    if addr.is_private:
        print (Fore.RED + "The IP address specified is a private address, defined in RFC1918. \n" +
        "Your results would be invalid, as each private network is different and threat intelligence cannot inspect each. \n"
        "  * Stopping execution with exit code 1." + Style.RESET_ALL)
        exit(1)
    if addr.is_multicast:
        print (Fore.RED + "The address specified is a multicast address. We'll continue, but be aware that errors may occur." + Style.RESET_ALL)

def abuseIPDB(ipaddr, apikey):

    print(Fore.GREEN + "ABUSE IP DATABASE: https://www.abuseipdb.com/" + Style.RESET_ALL)
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

    print(Fore.GREEN + "VIRUSTOTAL: https://www.virustotal.com/gui/" + Style.RESET_ALL)
    headers = {'x-apikey': '4246257a6c12b545695df7213f3d21509753b5c560732b08d9a56b75a231bfda'}
    url = 'https://virustotal.com/api/v3/ip_addresses/%s' %ipaddr
    response = requests.get(url=url, headers=headers)
    if response.status_code == 200:
        returned = response.json()
        #print("IP: " + str(returned['data']['id']))
        print("Reputation: " + str(returned['data']['attributes']['reputation']))
        print("Harmless Votes: " + str(returned['data']['attributes']['total_votes']['harmless']))
        print("Malicious Votes: " + str(returned['data']['attributes']['total_votes']['malicious']))

def threatMinerIP(ipaddr):

    print(Fore.GREEN + "THREATMINER: https://www.threatminer.org/" + Style.RESET_ALL)
    print(Fore.GREEN + "  * If this section is empty, ThreatMiner does not have data for this IP." + Style.RESET_ALL)
    url = "https://api.threatminer.org/v2/host.php"
    params = {'q': ipaddr, 'rt': '1'}
    response = requests.get(url=url, params=params)
    if response.status_code == 200:
        returned = response.json()
        for value in returned['results']:
            print ("ORG Name: " + str(value['org_name']))
            print ("Registrar: " + str(value['register']))
    params = {'q': ipaddr, 'rt': '2'}
    response = requests.get(url=url, params=params)
    if response.status_code == 200:
        returned = response.json()
        totalAssoc = 1
        for value in returned['results']:
            assocDomain = value['domain']
            print("Associated Domain #" + str(totalAssoc) + ": " + assocDomain)
            totalAssoc += 1
    url = "https://api.threatminer.org/v2/host.php"
    params = {'q': ipaddr, 'rt': '4'}
    response = requests.get(url=url, params=params)
    if response.status_code == 200:
        returned = response.json()
        totalAssoc = 1
        for assocHash in returned['results']:
            print ("Associated Hash #" + str(totalAssoc) + ": " + assocHash)
            totalAssoc += 1

def hybridAnalysisIP(ipaddr, apikey):
    print(Fore.GREEN + "HYBRID ANALYSIS: https://www.hybrid-analysis.com/" + Style.RESET_ALL)
    print(Fore.GREEN + "  * Utilizes the CrowdStrike Falcon Sandbox." + Style.RESET_ALL)
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
            print(Fore.GREEN + "Showing results whose threat score is above 10." + Style.RESET_ALL)
            threatDict = {}
            for eachresult in returned['result']:
                if eachresult['threat_score'] > 10:
                    jobID = eachresult['job_id']
                    threatScore = eachresult['threat_score']
                    threatDict[jobID] = threatScore
                    sha256Hash = str(eachresult['sha256'])
                    #print ("Job ID " + str(jobID) + " with threat score of " + str(threatScore) + " and SHA256 of " + str(sha256Hash))
                    sortedThreatDict = sorted(threatDict.items(), key=lambda item: item[1])
                    for key, value in sortedThreatDict:
                        print ("Job ID: " + str(key) + " with threat score of " + str(value) + " and SHA256 hash of " + str(eachresult['sha256']))
        if returned['count'] == 0:
            print(Fore.RED + "  * No results for that IP address on Hybrid-Analysis." + Style.RESET_ALL)

def urlhausIP(ipaddr):
    print(Fore.GREEN + "URLHAUS: https://urlhaus.abuse.ch/ \n" +
    "  * Getting the URLHAUS list. This is large and can take a moment to download based on your connection." + Style.RESET_ALL)
    response = requests.get("https://urlhaus.abuse.ch/downloads/text/")
    if response.status_code == 200:
        returned = response.text
        tryFind = returned.find(ipaddr)
        if tryFind == -1:
            print ("Not found.")
        if tryFind > -1:
            print ("Found the IP beginning at character #" + str(tryFind) + ". Search the full site for the IP here: https://urlhaus.abuse.ch/browse/ \n"
            + "No further searching against URLHaus is done to respect the team's wishes.")

def shodanIP(ipaddr, apikey):

    print(Fore.GREEN + "SHODAN: https://www.shodan.io/" + Style.RESET_ALL)
    api = Shodan(apikey)
    try:
        print (api.host(ipaddr))

    except Exception as e:
        print (Fore.RED + "No information is available for the IP address." + Style.RESET_ALL)

def proxyCheck(ipaddr):
    print(Fore.GREEN + "IP2Proxy: https://github.com/ip2location/ip2proxy-python" + Style.RESET_ALL)
    db = IP2Proxy.IP2Proxy()
    db.open("IP2PROXY-LITE-PX8.BIN")
    record = db.get_all(ipaddr)
    if str(record['is_proxy']) is "1":
        print ("  * Determined this is a proxy based on the IP2Proxy database.")
    print ('Is Proxy: ' + str(record['is_proxy']))
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

