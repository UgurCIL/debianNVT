import craw4py as cw
import re
import json
import os
import sys

class debian:

    prefix = 'include("revisions-lib.inc");\ninclude("pkg-lib-deb.inc");\n\nrelease = get_kb_item("ssh/login/release");\nres = "";\nreport = "";\n'
    postfix = '\nif (report != "") {\n\tsecurity_message(data:report);\n} else if (__pkg_match) {\n\texit(99); # Not vulnerable.\n}'
    arch = {'jessie':'DEB8\.[0-9]+', 'stretch': 'DEB9\.[0-9]+', 'buster':'DEB10\.[0-9]+'}

    def __init__(self):
        self.name = 'test-debian'

    '''
    Retrieve the depended binaries

    Return a list
    '''
    def getbinaries(self, package, release):
        packagelist = list()
        url = 'https://packages.debian.org/source/' + str(release) + '/' + str(package)
        soup = cw.getwebpage(url)

        try:
            div_tag = soup.findAll('div', id='pbinaries')[0]
            a_tags = div_tag.find_all('a')
        except:
            return None

        for a_tag in a_tags:
            # Exception for linux package to remove debian image packages
            if package == 'linux' and str(a_tag.string).endswith('di'):
                continue
            packagelist.append(a_tag.string)

        return packagelist

    '''
    Generate new, arbitrary, and larger version number
    for packages that doesn't have a fixed version yet

    Return a string
    '''
    def genpackvers(self, version):
        end = re.findall('.(\d+)$', version)[0]
        beg = version[:-len(end)]
        newversion = beg + str(int(end) + 1)

        return newversion

    '''
    Read the json file downloaded from debian-security
    and return a dict of all possible CVEs for a
    specific/all package(s)

    Return a dictionary
    '''
    def readjson(self, package):
        if not os.path.exists('cves.json'):
            url = 'https://security-tracker.debian.org/tracker/data/json'
            cw.downloadfile(url, 'cves.json')
        with open('cves.json', 'r') as jsonfile:
            data = json.load(jsonfile)
        if package == 'all':
            return data
        else:
            return data[package]

    '''
    Call th readjson func to get all CVEs and return a
    dict of a specific cve else return None

    Return a dictionary
    '''
    def readjsonbycve(self, cve):
        data = self.readjson('all')
        for pack, cves in data.items():
            if cve in cves.keys():
                return (pack, data[pack][cve])

        return (None, None)

    '''
    Return the IF statement for package version check

    Return a string
    '''
    def getif(self, package, version, distro):
        str1 = 'if ((res = isdpkgvuln(pkg:\"{0}\", ver:\"{1}\", rls_regex:\"{2}\", remove_arch:TRUE)) != NULL) {{\n\treport += res;\n}}'

        return str1.format(package, version, distro)

    '''
    Generate a NASL script (just for package control part)
    of a given debian package
    '''
    def genbypack(self, package):
        binaries = {}
        cves = self.readjson(package)

        for r in self.arch.keys():
            tmprepo = self.getbinaries(package, r)
            if tmprepo:
                binaries[r] = tmprepo

        for cvek, cvev in cves.items():
            self.genbycve(cvek, cvev, package, binaries)

    '''
    Generate a NASL script (just for package control part)
    of a given CVE
    '''
    def genbycve(self, cve, vulninfo = None, package = None, binaries = {}):
        if not vulninfo and not package and not binaries:
            package, vulninfo = self.readjsonbycve(cve)
            for r in self.arch.keys():
                tmprepo = self.getbinaries(package, r)
                if tmprepo:
                    binaries[r] = tmprepo
        if not vulninfo:
            print('There is no record for', cve)
            sys.exit()

        with open(cve + '.nasl', 'w') as nasl:
            nasl.write(self.prefix)
            for releasek, releasev in vulninfo['releases'].items():
                for repok, repov in releasev['repositories'].items():
                    if repok not in self.arch.keys():
                        continue
                    if releasev['status'] == 'resolved' and releasev['fixed_version'] != '0':
                        fixedversion = releasev['fixed_version']
                    elif releasev['status'] == 'resolved' and releasev['fixed_version'] == '0':
                        fixedversion = repov
                    else:
                        fixedversion = self.genpackvers(repov)
                    for binary in binaries[repok]:
                        nasl.write(self.getif(binary, fixedversion, self.arch[repok]))
            nasl.write(self.postfix)
        print('For', package, '&', cve, '->', cve + '.nasl is OK...')
