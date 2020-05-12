"""
    Spooky.py
    Purpose: Speed up tasks for security analysts and practitioners primarily revolving around OSINT.
    Author: Jackson Nestler
    Version: 0.0.1
    Source: https://gitlab.com/jksn/spookySOC
"""

# General imports
import argparse
import os
import yaml
from colorama import Fore, Back, Style
# Module imports
from Modules import SayHello
#from Modules import MenuHandler
from Modules import ipHandler
from Modules import domainHandler
from Modules import text

def readAPIKeys():
    try:
        with open("apiconfig.yaml") as apifile:
            provider_list = yaml.load(apifile, Loader=yaml.FullLoader)
            return provider_list
    except:
        text.printRed("Unable to open apiconfig.yaml. Have you created the file? Copy api_config_example.yaml if you need help.")
        exit(1)

if __name__ == '__main__':
    progDesc = "SpookySOC aims to speed up tasks for security analysts and practitioners, primarily revolving around OSINT."
    parser = argparse.ArgumentParser(description=progDesc)
    parser.add_argument("--ip", action='extend', nargs='+', help="an IP address to perform lookups on.")
    parser.add_argument("--domain", action='extend', nargs='+', help="a domain to perform lookups on.")
    # For an unknown reason, action='append' doesn't work, you need 'extend'.
    # Reference: https://docs.python.org/3/library/argparse.html#action
    parser.add_argument('--associatedips', help="Including this flag will check IPs associated with a domain. Exclude this flag to not check.", action='store_true')
    args = parser.parse_args()
    ASSOCIATEDIPCHECK = args.associatedips
    if ASSOCIATEDIPCHECK == True:
        text.printGreen("Associated IPs will be checked.")
    elif ASSOCIATEDIPCHECK == False:
        text.printRed("Associated IPs will NOT be checked.")
    else:
        text.printRed("Could not determine the boolean value of ASSOCIATEDIPCHECK.")

    API_KEYS_LIST = readAPIKeys()
    if args.ip:
        for addr in args.ip:
            ipHandler.checkPrivate(addr)
            text.printGreen("Looking up IP " + str(addr))
            ipHandler.abuseIPDB(addr, API_KEYS_LIST['ABUSEIPDB'])
            ipHandler.virusTotalIP(addr, API_KEYS_LIST['VT'])
            ipHandler.threatMinerIP(addr)
            ipHandler.hybridAnalysisIP(addr, API_KEYS_LIST['HYBRID'])
            ipHandler.urlhausIP(addr)

            # TO DO:
            # Somehow handle cases where Shodan spits out enormous amounts of data.

            ipHandler.shodanIP(addr, API_KEYS_LIST['SHODAN'])
            ipHandler.proxyCheck(addr)

    if args.domain:
        for domain in args.domain:
            text.printGreen("Looking up IP " + str(domain))
            domainHandler.virusTotalDomain(domain, API_KEYS_LIST['VT'])
            domainHandler.threatMinerDomain(domain)
            domainHandler.hybridAnalysisDomain(domain, API_KEYS_LIST['HYBRID'])
            domainHandler.shodanDomain(domain, API_KEYS_LIST['SHODAN'])
