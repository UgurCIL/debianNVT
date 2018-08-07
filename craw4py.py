import ssl
import urllib.request, urllib.parse, urllib.error
from bs4 import BeautifulSoup

'''
This function disables the ssl certificate check
to speed up the process and get rid off unnecessary
task in terms of crawling
'''
def disablessl():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    return ctx

'''
Generate a soup object to parse the web page on
given url address
'''
def getwebpage(url):
    ctx = disablessl()
    try:
        html = urllib.request.urlopen(url, context=ctx).read()
        soup = BeautifulSoup(html, 'html.parser')
    except:
        print(url, 'is not accessable!')
        return None

    return soup

'''
Download a file from given url and save it to path
'''
def downloadfile(url, path):
    print('Downloading started...')
    ctx = disablessl()
    with urllib.request.urlopen(url, context=ctx) as u, open(path, 'wb') as file:
        file.write(u.read())
    print('Download completed...')
