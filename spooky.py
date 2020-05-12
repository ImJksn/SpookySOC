"""
    Spooky.py
    Purpose: Speed up tasks for security analysts and practitioners primarily revolving around OSINT.
    Author: Jackson Nestler
    Version: 0.0.1
    Source: https://gitlab.com/jksn/spookySOC
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
    parser.add_argument("-ip", action='extend', nargs='+', help="an IP address to perform lookups on.")
    parser.add_argument("-domain", action='append', nargs='+', help="a domain to perform lookups on.")
    args = parser.parse_args()
    API_KEYS_LIST = readAPIKeys()

    if args.ip:
        for addr in args.ip:
            ipHandler.checkPrivate(addr)
            print(Fore.GREEN + "Looking up IP " + str(addr) + Style.RESET_ALL)
            ipHandler.abuseIPDB(addr, API_KEYS_LIST['ABUSEIPDB'])
            ipHandler.virusTotalIP(addr, API_KEYS_LIST['VT'])
            ipHandler.threatMinerIP(addr)
            ipHandler.hybridAnalysisIP(addr, API_KEYS_LIST['HYBRID'])
            ipHandler.urlhausIP(addr)

            # TO DO:
            # Somehow handle cases where Shodan spits out enormous amounts of data.

            ipHandler.shodanIP(addr, API_KEYS_LIST['SHODAN'])
            ipHandler.proxyCheck(addr)

    #SayHello.greetUser()
    #MenuHandler.mainMenu()
