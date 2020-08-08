# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Clean the data provided for IP checks by Shodan, similar to domains.
- Check IPs associated with domains. (Beta testing indicates this may not be a desired feature)
- Check domains associated with IPs. (Beta testing indicates this may not be a desired feature)
- Resolve domains to A records for AbuseIPDB searches.
- Save query output to a file that's usable and neat.
  - Text file should have the current day and time as the name, or something unique?
- Allow a custom file name for `apiconfig.yaml`
- Allow a custom file name for the IP2Proxy DB.
  
## 8 August 2020

It's been a while since there was a (public) update! I've been working on a lot behind-the-scenes, including a complete rewrite with GUI.
This won't be ready in time for the university's SIP presentation though, so I'm adding some minor changes here pre-presentation.

- Added the ability to look up file hashes against VirusTotal and ThreatMiner (more coming soon!)
- Worked with beta testers to more clearly outline functionality, and have updated the [unreleased](#unreleased) section accordingly.
- Researched how to best handle text output and we have a few options. For right now, it's recommended that users copy and paste the data as plaintext (`ctrl + shift + v`)
- Removed a hard coded VirusTotal API key and revoked the key. Learning experiences! Thanks to the tester who found this.
- Working on a code reformat.

## 15 May 2020

- Preparing for the beta testing release!
- Cleaned up `ipHandler.py` to check for the ThreatMiner results' status code, and print that there were no results found if none were.
- Added "beta tester" information to `spooky.py`, `iphandler.py`, and `domainHandler.py`.
- Began constructing the [Wiki](https://gitlab.com/jksn/spookySOC/-/wikis/home).
- Updated `README.md` with some more project information.
  
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
