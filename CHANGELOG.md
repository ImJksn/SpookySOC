# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Clean the data provided for IP checks by Shodan, similar to domains.
- Check IPs associated with domains.
- Check domains associated with IPs.
- Resolve domains to A records for AbuseIPDB searches.
- Save query output to a file that's usable and neat.
  - Text file should have the current day and time as the name, or something unique? 
  
## 11 May 2020

- Introduced domain lookup functionality.
  - Checks Shodan, VirusTotal, ThreatMiner, and HybridAnalysis.
  - AbuseIPDB only accepts IPs via their API. The plan is to resolve the domain's A records and have those checked.
- Laid framework for checking IPs associated with domains. Checking domains associated with IPs is a to-do item.
- Added the ability to specify multiple IPs or domains within a single argument. You may also specify both domains and IPs now.
  - Multiple IPs: `spooky.py --ip 1.1.1.1 8.8.8.8`
  - Multiple domains: `spooky.py --domain google.com msn.com`
  - One of each: `spooky.py --domain google.com --ip 1.1.1.1`
  - Multiple of each: `spooky.py --domain google.com msn.com --ip 1.1.1.1 8.8.8.8`
- Cleaned up `spooky.py` for consistency of text coloring.

## 10 May 2020

- Switched from GitHub to GitLab for personal preference.
  - Nothing against GitHub, just find the GitLab UI a bit more intuitive.
- Did some cleaning.