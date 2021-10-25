#!/usr/bin/env python3
import ip_enrich

ip = '1.1.1.1'

ipobj = ip_enrich.IP(ip, verbose=0)
ipobj.getAll()

# If you want to print the object
#print(ipobj)

print(f'IP address: {ip}')
# To extract specific info
country = ipobj.processedvtdata['country']
print(f'\tCountry: {country}')
as_owner = ipobj.processedvtdata['as_owner']
print(f'\tAS Owner: {as_owner}')
rdns = ipobj.reversedns
print(f'\tRDNS: {rdns}')


# To extract all the data from VT
"""
if ipobj.processedvtdata:
    for key in ipobj.processedvtdata:
        print(f'Key: {key}:')
        print(ipobj.processedvtdata[key])
"""

# To extract all the data from PT
"""
if ipobj.processedptdata:
    for key in ipobj.processedptdata:
        print(f'Key: {key}:')
        print(ipobj.processedptdata[key])
"""

# To extract only the data from PT results
"""
if ipobj.processedptdata_results:
    print(ipobj.processedptdata_results)
"""
