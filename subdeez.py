# http: // web.archive.org/cdx/search/cdx?url = %s % s/* & output = json & collapse = urlkey
# http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=%s%s/*&output=json

import multiprocessing as mp
import json
import requests
import argparse
import pathlib
#import http.client
#import utils.colors as c

# Todo: add multiprocessing to run against a domains.txt list.
# Add httprobe function to determine if url is reachable.
# Also try to add aquatone? with a --path flag in argparse.

# 8/20 added index extraction for all indexes... need to add multiprocessing for urlextraction on all indexes....

argparser = argparse.ArgumentParser("OSINT Pounder")
argparser.add_argument("-d", "--domain", type=str,
                       help='Domain to scan', required=True, dest="domain")
argparser.add_argument("-n", "--no-subs",
                       help="Specify no subdomains", required=False, action='store_true', dest="noSubs")
args = argparser.parse_args()
domain = args.domain
noSubs = args.noSubs


def print_banner(arg = ""):
    banner_top = '''
    #insert ascii art here
    '''
    banner  = '''#.... more ascii art if necessary
    '''
    print("\n\n")
    print(c.fg.red + c.bold + banner_top + banner + c.reset + "\n\n\n")


def getCrtsh(domain):
    #https://crt.sh/?q=%%25.%s&output=json
    url = requests.get("https://crt.sh/?q=%%25.%s&output=json".format() % (domain)).text
    data = json.loads(url)
    try:
        results = [ sub['name_value'] for sub in data]
        # Write results to dictionary to remove duplicates. Dictionaries can't have duplicates.
        results = list(dict.fromkeys(results))
        # Eventually instead of writing all files, I want to put all subdomains in the same array and convert to
        # dictionary to remove duplicates. So I would be returning the results array to other functions.
        writeSubdomain(results, 'crtsh.txt')
    except:
        pass


def getDnsBufferoverrun(domain):
    url = requests.get("https://dns.bufferover.run/dns?q=.%s".format() % (domain))
    data = url.json()["FDNS_A"]
    try:
        # split by comma and take 2nd value, which is the subdomain.
        results = [ sub.split(',')[1] for sub in data ]
        results = list(dict.fromkeys(results))
        #print(results)
        writeSubdomain(results, 'DnsBuffer.txt')
    except:
        pass


def getCertspotter(domain):
    # https://certspotter.com/api/v0/certs?domain=%s
    # or maybe through api https://api.certspotter.com/v1/issuances?domain=tevora.com&include_subdomains=true&expand=dns_names
    # 1000 queries / hr with free api key.
    url = requests.get("https://certspotter.com/api/v0/certs?domain=%s".format() % (domain))
    arrayData = json.loads(url.text)
    try:
        results = [ sub['dns_names'][0] for sub in arrayData]
        # conversion to dict removes duplicates.
        results = list(dict.fromkeys(results))
        # Still has some wildcard entries... need to clean these up in the last subdomain dict.
        writeSubdomain(results, 'certspotter.txt')
    except Exception as e:
        print(e)


def getThreatcrowd(domain):
    # https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s
    url = requests.get("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s".format() % (domain))
    data = url.json()['subdomains']
    try:
        results = [ sub.split(',')[0] for sub in data]
        results = list(dict.fromkeys(results))
        writeSubdomain(results, 'threatcrowd.txt')
    except Exception as e:
        print(e)



def getSubdomains(domain):
    # make this call all subdomain request functions.
    #getCrtsh(domain)
    #getDnsBufferoverrun(domain)
    #getCertspotter(domain)
    url = ""


def getStatusCode():
    # This will print only the status code (200) of requests. Make an if statement to only print a range of acceptable
    # status codes. Add these codes to another list for reachable urls. Maybe add an option to specify what ports to request.
    # Take input from waybackurls and ccrawl. Parse only the domains/subdomains of the results. Get request http/https those entries.
    # For now, request the URLs found as is. We can add functionality for only requesting subdomains later.

    #conn = http.client.HTTPConnection(site, timeout=2)
    #conn.request("Get", "/")
    #response = conn.getresponse()
    myFile = open("waybackurls.txt")
    for line in myFile:
        try:
#            pool = mp.Pool(mp.cpu_count())
#            threads = []
#            proc = pool.apply_async(requests.head(line))
#            threads.append(proc)
#            for proc in threads:
#               proc.get()
######  Need to figure out multithreading here. Maybe make a class/function for multithreading?
            proc = requests.head(line)
            print(proc.status_code)
            if proc.status_code != 404:
                print("This site works: " + line)
                # add site to an array and check if its empty at the end of the requests.
        except:
            pass


def urlExtraction(ccEntries):
    ccurls = []
    for line in ccEntries:
        for url in line:
            try:
                url = json.loads(url)["url"]
                url = url.strip()
                ccurls.append(url + '\n')
            except ValueError as e:
                # When server fails and no valid json response?
                pass

    return list(set(ccurls))
    # Dict didn't matter to clean dupes because its processed on multiple workers. Still need to use cleanDupes().
    # return list(dict.fromkeys(ccurls))


def ccIndexesMP():
    indexUrl = "https://index.commoncrawl.org/collinfo.json"
    data = requests.get(indexUrl).text
    indexes = json.loads(data)
    indexList = []
    for p in indexes:
        indexList.append(p['id'])
    #print(indexList)
    print("Let's see.. you have %s CPUs... Use them all? Okay..." % mp.cpu_count())
    pool = mp.Pool(mp.cpu_count())
    threads = []
    for entry in indexList:
        proc = pool.apply_async(commonCrawlURLS, (domain, noSubs, entry))
        threads.append(proc)
    for proc in threads:
        proc.get()


def commonCrawlURLS(host, noSubs, index):
    ccEntries = []
    wildcard = "*."
    if noSubs:
        wildcard = ""
        url = 'http://index.commoncrawl.org/%s-index?url=%s%s/*&output=json'.format() % (index, wildcard, host)
    else:
        url = 'http://index.commoncrawl.org/%s-index?url=%s%s/*&output=json'.format() % (index, wildcard, host)
    r = requests.get(url)
    blah = r.text.split('\n')[:-1]
    ccEntries.append(blah)
    links = urlExtraction(ccEntries)
    writeCCrawl(links, 'ccrawl.txt', index)

    #print(ccEntries)


def waybackurls(host, noSubs):
    if noSubs:
        url = 'http://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original&collapse=urlkey'.format() % host
    else:
        url = 'http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey'.format() % host
    r = requests.get(url)
    results = r.json()
    # Return everything except the 'original' first string.
    results = results[1:]
    # No need to clean wayback output because it's already uniq with no duplicates.
    writeWaybackurls(results, 'waybackurls.txt')


def writeWaybackurls(content, filename):
    file = open(filename, 'w')
    for i in content[:]:
        print(*i, sep='[]', file=file)
    file.close()


def writeCCrawl(links, filename, index):
    file = open(filename, 'a+')
    for link in links:
        file.write(link)
    print("Completed {0}".format(index))


def writeSubdomain(content, filename):
    file = open(filename, 'w')
    for i in content:
        file.write(i + '\n')
    file.close()


def cleanDupes(filename, newFilename):
    with open(filename) as result:
        uniqlines = set(result.readlines())
        with open(newFilename, 'w') as rmdup:
            rmdup.writelines(set(uniqlines))
    path = pathlib.Path(filename)
    path.unlink()


def main():
    # Find subdomains
    #getCrtsh(domain)
    #getDnsBufferoverrun(domain)
    #getCertspotter(domain)
    getThreatcrowd(domain)

    # Send to Wayback
    '''waybackurls(domain, noSubs)
    ccIndexesMP()
    cleanDupes('ccrawl.txt','ccrawl-uniq.txt')'''

    #getStatusCode()


if __name__ == '__main__':
    main()
