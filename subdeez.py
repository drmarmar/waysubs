# http: // web.archive.org/cdx/search/cdx?url = %s % s/* & output = json & collapse = urlkey
# http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=%s%s/*&output=json

from multiprocessing import process
import sys
import json
import requests
import argparse

# Todo: add multiprocessing to run against a domains.txt list.
# Add commoncrawl and otxurls function.
# Add httprobe function to determine if url is reachable.
# Also try to add aquatone? with a --path flag in argparse.

# 8/15 added commomcrawl for only 1 index... need to add multiprocessing for multiple indexes...

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
    if len(ccurls) == 0:
        print("No URLs found.. Git good.")
        sys.exit()
    return list(set(ccurls))


# def multiCommonCrawlURLS(host, noSubs):


def commonCrawlURLS(host, noSubs):
    ccEntries = []
    # I want to crawl up to like 2016 and get uniq results only...for loop for year with forloop for month inside?
    wildcard = "*."
    if noSubs:
        wildcard = ""
        url = 'http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=%s%s/*&output=json'.format() % (wildcard, host)
    else:
        url = 'http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=%s%s/*&output=json'.format() % (wildcard, host)
    r = requests.get(url)

    blah = r.text.split('\n')[:-1]
    ccEntries.append(blah)
    links = urlExtraction(ccEntries)

    # print(len(links))
    writeCCrawl(links, 'ccrawl.txt')


def waybackurls(host, noSubs):
    if noSubs:
        url = 'http://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original&collapse=urlkey' % host
    else:
        url = 'http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey' % host
    r = requests.get(url)
    results = r.json()
    # Return everything except the 'original' first string.
    # return results[1:]
    results = results[1:]
    writeFile(results, 'waybackurls.txt')


def writeFile(content, filename):
    file = open(filename, 'w')
    for i in content[:]:
        print(*i, sep='[]', file=file)
    file.close()


def writeCCrawl(links, filename):
    file = open(filename, 'w')
    for link in links:
        file.write(link)


def main():
    # Send to Wayback
    waybackurls(domain, noSubs)
    commonCrawlURLS(domain, noSubs)
    print(ccindexes())


if __name__ == '__main__':
    main()
