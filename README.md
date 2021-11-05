# Stratosphere IP enrich
Get an IP address and enrich it with metadata and IoC

You need API keys for VirusTotal and PassiveTotal (RiskIQ)


## Features

- Extract VirusTotal data
- Extract PassiveTotal data
- Extract GeoIP data

## How to use from your python

```
#!/usr/bin/env python3
import ip_enrich

ip = '1.1.1.1'

ipobj = ip_enrich.IP(ip, 10)
ipobj.getAll()
print(ipobj)
```

## Example run in command line

```
./ip_enrich.py -i 1.1.1.1
[+] Getting the VirusTotal data
[+] Processing the VirusTotal data
[+] Getting the reverse DNS data
[+] Getting the PassiveTotal data
[+] Getting the Geolocation data
[+] Getting the Shodan data

IP: 1.1.1.1. Country: AU. AS Org: CLOUDFLARENET. RDNS: one.one.one.one.
GeoIP Data
	Country: Australia (AU)
	RegionName: Queensland QLD
	City: South Brisbane
	Lat: -27.4766
	Lon: 153.0166
	TZ: Australia/Brisbane
	isp: Cloudflare, Inc
	Org: APNIC and Cloudflare DNS Resolver project
	AS: AS13335 Cloudflare, Inc.
VT Resolutions (top 10, sorted by datetime):
	2021-11-02 14:00:51: 0002049.xyz
	2021-11-02 06:33:27: 055353.com
	2021-10-28 00:52:26: 0.0www.breadapp.com
	2021-10-28 00:52:25: 0.0.0www.breadapp.com
	2021-10-22 10:14:54: 01eeda8e7e38183e5676cbabe5b8b11e.19f7f31a1a944816d5f44d89024aff48.h.i.ydscan.net
	2021-10-18 13:55:09: 0-v-0.xyz
	2021-10-15 17:32:42: 0.0token.breadapp.com
	2021-10-15 17:32:41: 0.0.0token.breadapp.com
	2021-10-14 23:20:50: 0000jb.com
	2021-10-12 07:54:09: 0.0stage.breadapp.com
VT URLs (top 10, sorted by datetime):
	2021-11-05 17:33:05: http://www.besthotel360.com:1219/001/puppet.Txt?77142. Positives: 1/93
	2021-11-05 16:40:17: http://shenzhengyunde.com/wp-content/plugins/Citrus. Positives: 9/93
	2021-11-05 15:43:12: http://fabianomeroete.gettrials.com/. Positives: 6/93
	2021-11-05 15:10:52: http://korberpie8p6f.servebeer.com/us.html?2Nf8zJ4oH8vPvwUyzhQhY1mO30thIH7MBanBtDZCBtbkNl979971JntUZqTSO6czexqILCwJ2bfvAVECgtX7aNEeQpjIsWc8FF5K_4_2Nf8zJ4oH8vPvwUyzhQhY1mO30thIH7MBanBtDZCBtbkNl979971JntUZqTSO6czexqILCwJ2bfvAVECgtX7aNEeQpjIsWc8FF5K_4. Positives: 4/93
	2021-11-05 14:22:16: http://www.besthotel360.com:1219/001/puppet.Txt?80044. Positives: 1/93
	2021-11-05 14:02:45: http://1.1.1.1/positron/discovery. Positives: 1/93
	2021-11-05 13:04:53: http://thee.network/. Positives: 12/93
	2021-11-05 10:11:49: http://www.besthotel360.com:1219/001/puppet.Txt?82118. Positives: 1/92
	2021-11-05 08:22:00: http://chetverg.xyz/. Positives: 7/92
	2021-11-05 06:09:04: http://www.besthotel360.com:1219/001/puppet.Txt?97687. Positives: 1/92
VT Detected Communicating Samples (top 10, sorted by datetime):
	2021-11-05 18:11:24: Positives: 0, Total: 0, SHA256: f6390d83e5684b3dd5d4b6db71bfd7573a8eb0edcacf548cfb4715ae74eb0ac6
	2021-11-05 18:06:05: Positives: 0, Total: 0, SHA256: e9cbf160213511551b8af68f47e30a7bbca16ef707abb790ee7673cce1a786a4
	2021-11-05 17:57:04: Positives: 0, Total: 0, SHA256: d713e22c9bab1cc73d79f4ea7131ef8cc6ede776b9192474997c50000706b392
	2021-11-05 17:56:14: Positives: 0, Total: 0, SHA256: d4f684092f42598823dc6f9c1a4cf68576924c1700b5d05ae302d0604bd5e21c
	2021-11-05 17:48:25: Positives: 0, Total: 0, SHA256: c39706d752096fa39c44d7f438477721e6ff2cefec04b76ee88808c897d3a4d9
	2021-11-05 17:39:28: Positives: 0, Total: 0, SHA256: adf74bfffcc53e48b4cf4d89839daeb63a6dfefe06c19298f653b3af8bcff5a3
	2021-11-05 17:33:42: Positives: 0, Total: 0, SHA256: 9f48278ecaff72c29f49eb8daa39d99c45369edaae6326da594af7097737a01c
	2021-11-05 17:26:55: Positives: 0, Total: 0, SHA256: 8f0847c175118ed8b533bb5669a90f51c41905e11ec2e04e96741ab2d75f1ce7
	2021-11-05 17:25:59: Positives: 0, Total: 0, SHA256: 8cf24462e9dfdd1aa558c51ee3d91b0da913caf2929debad1d3559a854fc2e61
	2021-11-05 17:19:06: Positives: 0, Total: 0, SHA256: 7da6df949060f6825614f2a08ae687889f2764391b2e8d0941ed68ce26199cff
VT Detected Downloaded Samples (top 10, sorted by datetime):
	2021-09-20 09:51:51: Positives: 1, Total: 72, SHA256: 2c141c06f7df57f11ef2c62f2a96093484a65df47065b1a475c53784af0e2664
	2021-06-26 17:08:59: Positives: 7, Total: 74, SHA256: 8ad3794b215df1a4eaf1325a90a4357ad93476c9308b4e820e325d50eba50280
	2021-04-15 03:35:40: Positives: 1, Total: 73, SHA256: 337dffc1333f286f559c052c45c97f48ac8136cbf6327c24739f058407f45d7d
	2021-04-08 11:30:25: Positives: 1, Total: 74, SHA256: 72ec27bd0d959a1e6713d96b4e55c5a9b92ac6d1b5b5a4a8d5d1211422fcee57
	2021-03-30 15:12:44: Positives: 11, Total: 74, SHA256: 92e9cf96de35f3f9b86c77ded463a4abb7c394a78ea9c14524996de96c920fe9
	2020-10-18 08:17:53: Positives: 18, Total: 75, SHA256: 5a9007b9bcaf5a0a4685a55c2b477fc2b5072e03f98f3f2a310898b27d63d5f1
	2020-06-09 05:28:01: Positives: 4, Total: 74, SHA256: 54b6ce478977f5242698ab1bac90fe11133d2339d1f24fc9d96649099128cd23
	2020-03-14 06:31:57: Positives: 1, Total: 71, SHA256: 1c6c32f969e7f5d9bd7a3361388643db8955b8d3bf72c5fb73ea1b989702ab3e
	2019-09-18 22:43:06: Positives: 1, Total: 72, SHA256: 9f89814b48fc3249bf67a8a6e4439d97391b10b99f02b3da9e38345be1f1ed3f
	2018-04-16 02:49:06: Positives: 23, Total: 62, SHA256: 0773b94a2e3239eeda0d02f32d8beea116783b48172c116c9b6b382338f8be13
VT Detected Referrer Samples (top 10, sorted by sha):
	fe76c029c702ab5f7f6f26e58d56d7dc5a7419947e4b747ef20433c43b456252: Positives: 0, Total: 53
	f7b72d219e80830fab064ef3190811b022680a0aba4614d7e0e95e90a6268c6b: Positives: 0, Total: 56
	ed333742b1d328e83a2eb2610d94b1ac70b6f88a40b978d0683502b819d45285: Positives: 0, Total: 53
	ec904beca8b268a4a26ec09d32614e4064698b59dc2df848b22eac4f5a49f0c9: Positives: 0, Total: 55
	eb9ca996df33909ab25b98e033d820cf0b687d7d833d38e4948749163ed60c10: Positives: 0, Total: 53
	e953ac3b639202cfc647a0ab36599f45a678161be47789c7cf3c2132177e5f44: Positives: 0, Total: 55
	e6755e04f472f478684e6fec9226f7fc82fe0576b6e0ae7504ffcbb41832cb5c: Positives: 0, Total: 54
	e220b8b5afe2745bd3a92d1d961fe5bb7bc06b02a0046c7a9e3bde06b8e2ad02: Positives: 0, Total: 53
	e1f818767ba2c60a77d172da8bb31fd6e46a7291331568c00fe59877012b55cb: Positives: 0, Total: 54
	e17a0261a12397547696519d748e0756d95c2fe694fa8399179a3aaad4f075cb: Positives: 0, Total: 53
PassiveTotal Data (top 10, sorted by lastSeen). 	First Seen: 2011-02-12 13:38:44. Last Seen: 2021-11-05 09:52:46. Records: 55
	LastSeen: 2021-11-05 09:52:46. FirstSeen: 2021-05-25 11:31:39. Hostname: sentri360.ai.
	LastSeen: 2021-11-05 08:07:03. FirstSeen: 2021-06-11 04:15:47. Hostname: yunxuetang.ai.
	LastSeen: 2021-11-05 08:05:51. FirstSeen: 2020-01-08 20:33:20. Hostname: tant.al.
	LastSeen: 2021-11-05 07:57:48. FirstSeen: 2020-11-02 07:10:20. Hostname: salgado.com.ar.
	LastSeen: 2021-11-05 07:43:27. FirstSeen: 2016-03-08 21:26:03. Hostname: lewicki.com.ar.
	LastSeen: 2021-11-05 07:25:37. FirstSeen: 2020-12-06 20:19:25. Hostname: azmedia.com.ar.
	LastSeen: 2021-11-05 07:24:52. FirstSeen: 2021-06-30 18:20:49. Hostname: prueba.cammesa.com.ar.
	LastSeen: 2021-11-05 07:20:14. FirstSeen: 2016-02-09 17:22:21. Hostname: df.eaglemobile.al.
	LastSeen: 2021-11-05 07:12:50. FirstSeen: 2021-06-13 12:42:09. Hostname: test.trovo.ai.
	LastSeen: 2021-11-05 07:06:27. FirstSeen: 2018-05-20 00:00:50. Hostname: links.rakbank.ae.
	LastSeen: 2021-11-05 06:43:54. FirstSeen: 2021-02-17 01:16:25. Hostname: kgs.am.
Shodan Data. 	Tags: []
	Domains: ['one.one']
	Hostnames ['one.one.one.one']
	Org APNIC and Cloudflare DNS Resolver project
	Last update 2021-11-05T17:58:53.742055
	Ports [80, 443, 53]

```



## TODO

- Implement https://api.riskiq.net/api/ssl/
- Implement https://api.riskiq.net/api/blacklist/
