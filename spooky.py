"""
    Spooky.py
    Purpose: Speed up tasks for security analysts and practitioners primarily revolving around OSINT.
    Author: Jackson Nestler
    Version: 0.0.1
    Source: PENDING
"""

# General imports
import os
import yaml
from colorama import Fore, Back, Style
# Module imports
from Modules import SayHello
#from Modules import MenuHandler
from Modules import ipHandler

def readAPIKeys():
    try:
        with open("apiconfig.yaml") as apifile:
            provider_list = yaml.load(apifile, Loader=yaml.FullLoader)
            return provider_list
    except:
        print (Fore.RED + "Unable to open apiconfig.yaml. Have you created the file? Copy api_config_example.yaml if you need help." + Style.RESET_ALL)
        exit(1)

if __name__ == '__main__':
    import argparse
    progDesc = "SpookySOC aims to speed up tasks for security analysts and practitioners, primarily revolving around OSINT."
    parser = argparse.ArgumentParser(description=progDesc)
    parser.add_argument("-ip", help="an IP address to perform lookups on.")
    parser.add_argument("-domain", help="a domain to perform lookups on.")
    args = parser.parse_args()

    API_KEYS_LIST = readAPIKeys()

    if args.ip:
        ipHandler.checkPrivate(args.ip)
        print(Fore.GREEN + "Looking up IP " + str(args.ip) + Style.RESET_ALL)
        ipHandler.abuseIPDB(args.ip, API_KEYS_LIST['ABUSEIPDB'])
        ipHandler.virusTotalIP(args.ip, API_KEYS_LIST['VT'])
        ipHandler.threatMinerIP(args.ip)
        ipHandler.hybridAnalysisIP(args.ip, API_KEYS_LIST['HYBRID'])
        ipHandler.urlhausIP(args.ip)
        #ipHandler.shodanIP(args.ip, API_KEYS_LIST['SHODAN'])
        #ipHandler.proxyCheck(args.ip)

    #SayHello.greetUser()
    #MenuHandler.mainMenu()
