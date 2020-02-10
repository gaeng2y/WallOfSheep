import sniff
import xml.etree.ElementTree as ET
import re

pkt, ip = sniff.sniff()
pkt = pkt.find(b'<xml')
print(pkt)