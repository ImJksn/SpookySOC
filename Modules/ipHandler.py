"""
    ipHandler.py
    Purpose: Perform IP reputation checks against several services.
    Author: Jackson Nestler
    Version: 0.0.1
    Source: https://gitlab.com/jksn/spookySOC
"""

import requests
import ipaddress
import IP2Proxy
from Modules import text
from shodan import Shodan
from colorama import Fore, Back, Style

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

    text.printGreen("THREATMINER: https://www.threatminer.org/")
    text.printGreen("  * If this section is empty, ThreatMiner does not have data for this IP.")
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
                    sha256Hash = str(eachresult['sha256'])
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

    text.printGreen("SHODAN: https://www.shodan.io/")
    api = Shodan(apikey)
    try:
        print (api.host(ipaddr))

    except Exception as e:
        text.printRed("No information is available for the IP address.")

def proxyCheck(ipaddr):
    text.printGreen("IP2Proxy: https://github.com/ip2location/ip2proxy-python")
    #print(Fore.GREEN + "IP2Proxy: https://github.com/ip2location/ip2proxy-python" + Style.RESET_ALL)
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

