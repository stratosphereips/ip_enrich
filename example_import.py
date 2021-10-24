#!/usr/bin/env python3
import ip_enrich

ip = '1.1.1.1'

ipobj = ip_enrich.IP(ip, 10)
ipobj.getAll()
print(ipobj)
