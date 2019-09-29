# http: // web.archive.org/cdx/search/cdx?url = %s % s/* & output = json & collapse = urlkey
# http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=%s%s/*&output=json

import multiprocessing as mp
import json
import requests
import argparse
import pathlib
#import http.client
#import utils.colors as c


argparser = argparse.ArgumentParser("OSINT Pounder")
argparser.add_argument("-d", "--domain", type=str,
                       help='Domain to scan', required=True, dest="domain")
argparser.add_argument("-n", "--no-subs",
                       help="Specify no subdomains", required=False, action='store_true', dest="noSubs")
argparser.add_argument("-w", "--wayback", help="Search waybackurls for specified domain", required=False, action="store_true")
argparser.add_argument("-c", "--crawl", help="Search through CcrawlUrls for specified domain", required=False, action="store_true")

args = argparser.parse_args()
domain = args.domain
noSubs = args.noSubs
wayback = args.wayback
ccrawl = args.crawl

subdomains = set()

def print_banner(arg = ""):
    # todo...
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
        results = set(results)
        for i in results:
            subdomains.add(i)
    except:
        pass


def getDnsBufferoverrun(domain):
    url = requests.get("https://dns.bufferover.run/dns?q=.%s".format() % (domain))
    data = url.json()["FDNS_A"]
    try:
        # split by comma and take 2nd value, which is the subdomain.
        results = [ sub.split(',')[1] for sub in data ]
        results = set(results)
        for i in results:
            subdomains.add(i)
    except:
        pass


def getCertspotter(domain):
    # https://certspotter.com/api/v0/certs?domain=%s
    url = requests.get("https://certspotter.com/api/v0/certs?domain=%s".format() % (domain))
    arrayData = json.loads(url.text)
    try:
        results = [ sub['dns_names'][0] for sub in arrayData]
        results = set(results)
        for i in results:
            subdomains.add(i)
    except Exception as e:
        print(e)


def getThreatcrowd(domain):
    # https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s
    url = requests.get("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s".format() % (domain))
    data = url.json()['subdomains']
    try:
        results = [ sub.split(',')[0] for sub in data]
        results = set(results)
        for i in results:
            subdomains.add(i)
    except Exception as e:
        print(e)


def getHackertarget(domain):
    url = requests.get("https://api.hackertarget.com/hostsearch/?q=%s".format() % (domain)).text.splitlines()
    try:
        results = [ sub.split(',')[0] for sub in url]
        results = set(results)
        for i in results:
            subdomains.add(i)
        #print(subdomains)
    except Exception as e:
        print(e)


def getSubdomains(domain):
    # make this call all subdomain request functions.
    getCrtsh(domain)
    getDnsBufferoverrun(domain)
    getCertspotter(domain)
    getThreatcrowd(domain)
    getHackertarget(domain)

    # Remove dupes from subdomains global set. This set will be used for wayback and ccurls.
    global subdomains
    subdomains = set(subdomains)
    for sub in subdomains:
        print(sub)
    writeSubdomain(subdomains, 'output/' + domain + '-subdomains.txt')


def urlExtraction(ccEntries):
    ccurls = []
    for line in ccEntries:
        for url in line:
            try:
                url = json.loads(url)["url"]
                url = url.strip()
                ccurls.append(url + '\n')
            except ValueError as e:
                pass

    return list(set(ccurls))


def ccIndexesMP(ccrawl):
    if ccrawl == True:
        indexUrl = "https://index.commoncrawl.org/collinfo.json"
        data = requests.get(indexUrl).text
        indexes = json.loads(data)
        indexList = []
        for p in indexes:
            indexList.append(p['id'])
        print("Let's see.. you have %s CPUs... Use them all? Okay..." % mp.cpu_count())
        pool = mp.Pool(mp.cpu_count())
        threads = []
        for entry in indexList:
            proc = pool.apply_async(commonCrawlURLS, (domain, noSubs, entry))
            threads.append(proc)
        for proc in threads:
            proc.get()
        cleanDupes('output/' + domain + '-ccrawl.txt', 'output/' + domain + '-ccrawl-uniq.txt')
    else:
        pass


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
    writeCCrawl(links, 'output/' + domain + '-ccrawl.txt', index)


def waybackurls(host, noSubs, wayback):
    if wayback == True:
        if noSubs:
            url = 'http://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original&collapse=urlkey'.format() % host
        else:
            url = 'http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey'.format() % host
        r = requests.get(url)
        results = r.json()
        # Return everything except the 'original' first string.
        results = results[1:]
        # No need to clean wayback output because it's already uniq with no duplicates.
        writeWaybackurls(results, 'output/' + domain + '-waybackurls.txt')
    else:
        pass


def writeWaybackurls(content, filename):
    pathlib.Path('./output').mkdir(parents=False, exist_ok=True)
    file = open(filename, 'w')
    for i in content[:]:
        print(*i, sep='[]', file=file)
    file.close()


def writeCCrawl(links, filename, index):
    pathlib.Path('./output').mkdir(parents=False, exist_ok=True)
    file = open(filename, 'a+')
    for link in links:
        file.write(link)
    print("Completed {0}".format(index))


def writeSubdomain(content, filename):
    pathlib.Path('./output').mkdir(parents=False, exist_ok=True)
    file = open(filename, 'w')
    for i in content:
        file.write(i + '\n')
    file.close()


def cleanDupes(filename, newFilename):
    pathlib.Path('./output').mkdir(parents=False, exist_ok=True)
    with open(filename) as result:
        uniqlines = set(result.readlines())
        with open(newFilename, 'w') as rmdup:
            rmdup.writelines(set(uniqlines))
    path = pathlib.Path(filename)
    path.unlink()


def main():
    # Find subdomains
    getSubdomains(domain)

    # Send to Wayback
    waybackurls(domain, noSubs, wayback)
    ccIndexesMP(ccrawl)


if __name__ == '__main__':
    main()
