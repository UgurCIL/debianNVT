import py4deb as DEB

deb = DEB.debian()
#deb.genbypack('heimdal')
deb.genbycve('CVE-2013-2902')
