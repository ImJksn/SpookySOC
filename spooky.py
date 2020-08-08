"""
    Spooky.py
    Purpose: Speed up tasks for security analysts and practitioners primarily revolving around OSINT.
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

import argparse
import os
import yaml
from colorama import Fore, Back, Style
from Modules import ipHandler
from Modules import domainHandler
from Modules import hashHandler
from Modules import text

def readAPIKeys():
    """Opens apiconfig.yaml and reads the API keys into a list. Does not attempt to check formatting or key validity.

    Returns:
        provider_dict [Dictionary] -- A simple dictionary containing the API keys.
    """
    try:
        with open("apiconfig.yaml") as apifile:
            provider_dict = yaml.load(apifile, Loader=yaml.FullLoader)
            return provider_dict
    except:
        text.printRed("Unable to open apiconfig.yaml. Have you created the file? Copy api_config_example.yaml if you need help.")
        exit(1)

if __name__ == '__main__':
    """Initial setup of argparse. Then, API keys are read, and processing begins.
    """
    progDesc = "SpookySOC aims to speed up tasks for security analysts and practitioners, primarily revolving around OSINT. Source: https://gitlab.com/jksn/spookySOC"
    parser = argparse.ArgumentParser(description=progDesc)
    parser.add_argument("--ip", action='extend', nargs='+', help="an IP address to perform lookups on.")
    parser.add_argument("--domain", action='extend', nargs='+', help="a domain to perform lookups on.")
    parser.add_argument("--hash", action='extend', nargs='+', help="a MD5, SHA256, or SHA512 hash.")
    # For an unknown reason, action='append' doesn't work, you need 'extend'.
    # Reference: https://docs.python.org/3/library/argparse.html#action
    parser.add_argument('--associatedips', help="[INACTIVE] Including this flag will check IPs associated with a domain. Exclude this flag to not check.", action='store_true')
    args = parser.parse_args()
    ASSOCIATEDIPCHECK = args.associatedips
    """
    # Will be used for association checking logic. Not currently in use.
    if ASSOCIATEDIPCHECK == True:
        text.printGreen("Associated IPs will be checked.")
    elif ASSOCIATEDIPCHECK == False:
        text.printRed("Associated IPs will NOT be checked.")
    else:
        text.printRed("Could not determine the boolean value of ASSOCIATEDIPCHECK.")
    """

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
    if args.hash:
        for filehash in args.hash:
            text.printGreen("Looking up hash " + str(filehash))
            #hashHandler.virusTotalHash(filehash, API_KEYS_LIST['VT'])
            hashHandler.threatMinerHash(filehash)

