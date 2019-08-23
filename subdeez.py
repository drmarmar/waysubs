# http: // web.archive.org/cdx/search/cdx?url = %s % s/* & output = json & collapse = urlkey
# http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=%s%s/*&output=json

import multiprocessing as mp
import sys
import json
import requests
import argparse
import os.path
from os import path

# Todo: add multiprocessing to run against a domains.txt list.
# Add commoncrawl and otxurls function.
# Add httprobe function to determine if url is reachable.
# Also try to add aquatone? with a --path flag in argparse.

# 8/20 added index extraction for all indexes... need to add multiprocessing for urlextraction on all indexes....

argparser = argparse.ArgumentParser("OSINT Pounder")
argparser.add_argument("-d", type=str,
                       help='Domain to scan', required=True, dest="domain")
argparser.add_argument("-n",
                       help="Specify no subdomains", required=False, action='store_true', dest="noSubs")
args = argparser.parse_args()
domain = args.domain
noSubs = args.noSubs


def ccindexes():
    indexUrl = "https://index.commoncrawl.org/collinfo.json"
    data = requests.get(indexUrl).text
    indexes = json.loads(data)
    # print(indexes)
    indexList = []
    for p in indexes:
        indexList.append(p['id'])
    return list(set(indexList))


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
    #if len(ccurls) == 0:
    #    print("No URLs found.. Git good.")
    #    sys.exit()
    return list(set(ccurls))


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
    #print("Working {0}".format(index))

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


def waybackurls(host, noSubs):
    if noSubs:
        url = 'http://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original&collapse=urlkey'.format() % host
    else:
        url = 'http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey'.format() % host
    r = requests.get(url)
    results = r.json()
    # Return everything except the 'original' first string.
    results = results[1:]
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

def cleanDupes(filename, newFilename):
    with open(filename) as result:
        uniqlines = set(result.readlines())
        with open(newFilename, 'w') as rmdup:
            rmdup.writelines(set(uniqlines))

def main():
    # Send to Wayback
    waybackurls(domain, noSubs)
    #commonCrawlURLS(domain, noSubs)
    #print(ccindexes())
    ccIndexesMP()
    cleanDupes('ccrawl.txt','ccrawl-uniq.txt')
    #cleanDupes('waybackurls.txt', 'wayback-uniq.txt')

if __name__ == '__main__':
    main()
