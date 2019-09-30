# WaySubs
## Subdomain enumeration from these sources:
* crtsh
* dns.bufferover.run
* certspotter
* threatcrowd
* hackertarget

## Wayback machine and Commoncrawl index support

# Usage
Specify domain to enumerate subdomains. Will output results to *output* folder.

`python3 -d yahoo.com`

Search wayback machine and commoncrawl index as well:

`python3 -d yahoo.com -w -c`

Search wayback and commoncrawl but filter subdomains. For when you want to target a single domain/subdomain.

`python3 -d yahoo.com --nosubs -w -c`
