![image](https://user-images.githubusercontent.com/2458879/152699747-f5ebfe48-662b-4fd0-b4d5-424111984452.png)

# Stratosphere IP Enrich

IP_Enrich is a tool that given a IP address, it will query multiple security threat intelligence services and enrich the information of the IP with metadata and all the available information on it.

*Note: certain services require adding API keys, like VirusTotal and PassiveTotal (RiskIQ).*


## Features

- Extract VirusTotal data
- Extract PassiveTotal data
- Extract GeoIP data
- Extract Shodan data
- Outputs in a JSON format
- Outputs a nice printed summary
- Can be imported as a module


## Roadmap

The following are a list of features that we aim to incorporate to IP Enrich in the future:

- Implement https://api.riskiq.net/api/ssl/
- Implement https://api.riskiq.net/api/blacklist/

## How to Run

### As a module from another Python

IP Enrich can be imported from another Python as a module. An example of how to do it is shown below:

```
#!/usr/bin/env python3
import ip_enrich

ip = '1.1.1.1'

ipobj = ip_enrich.IP(ip, 10)
ipobj.getAll()
print(ipobj)
```

### Standalone from the command line

IP Enrich can be used directly from the command line as an independent tool. An example is shown below:

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

### Example with JSON output

```
✗ ./ip_enrich.py -i 1.1.1.1 -o 1.1.1.1.json
[+] Getting the VirusTotal data
[+] Processing the VirusTotal data
[+] Getting the reverse DNS data
[+] Getting the PassiveTotal data
[+] Getting the Geolocation data
[+] Getting the Shodan data

✗ cat 1.1.1.1.json|jq .

{
  "ip": "1.1.1.1",
  "country": "AU",
  "as": "CLOUDFLARENET",
  "rdns": "None",
  "geodata": {
    "status": "success",
    "country": "Australia",
    "countryCode": "AU",
    "region": "QLD",
    "regionName": "Queensland",
    "city": "South Brisbane",
    "zip": "4101",
    "lat": -27.4766,
    "lon": 153.0166,
    "timezone": "Australia/Brisbane",
    "isp": "Cloudflare, Inc",
    "org": "APNIC and Cloudflare DNS Resolver project",
    "as": "AS13335 Cloudflare, Inc.",
    "query": "1.1.1.1"
  },
  "vt": {
    "resolutions": [
      {
        "date": "2021-11-02 14:00:51",
        "domain": "0002049.xyz"
      },
      {
        "date": "2021-11-02 06:33:27",
        "domain": "055353.com"
      },
      {
        "date": "2021-10-28 00:52:26",
        "domain": "0.0www.breadapp.com"
      },
      {
        "date": "2021-10-28 00:52:25",
        "domain": "0.0.0www.breadapp.com"
      },
      {
        "date": "2021-10-22 10:14:54",
        "domain": "01eeda8e7e38183e5676cbabe5b8b11e.19f7f31a1a944816d5f44d89024aff48.h.i.ydscan.net"
      },
      {
        "date": "2021-10-18 13:55:09",
        "domain": "0-v-0.xyz"
      },
      {
        "date": "2021-10-15 17:32:42",
        "domain": "0.0token.breadapp.com"
      },
      {
        "date": "2021-10-15 17:32:41",
        "domain": "0.0.0token.breadapp.com"
      },
      {
        "date": "2021-10-14 23:20:50",
        "domain": "0000jb.com"
      },
      {
        "date": "2021-10-12 07:54:09",
        "domain": "0.0stage.breadapp.com"
      }
    ],
    "detected_urls": [
      {
        "date": "2021-11-05 17:33:05",
        "url": "http://www.besthotel360.com:1219/001/puppet.Txt?77142",
        "detections": "1/93"
      },
      {
        "date": "2021-11-05 16:40:17",
        "url": "http://shenzhengyunde.com/wp-content/plugins/Citrus",
        "detections": "9/93"
      },
      {
        "date": "2021-11-05 15:43:12",
        "url": "http://fabianomeroete.gettrials.com/",
        "detections": "6/93"
      },
      {
        "date": "2021-11-05 15:10:52",
        "url": "http://korberpie8p6f.servebeer.com/us.html?2Nf8zJ4oH8vPvwUyzhQhY1mO30thIH7MBanBtDZCBtbkNl979971JntUZqTSO6czexqILCwJ2bfvAVECgtX7aNEeQpjIsWc8FF5K_4_2Nf8zJ4oH8vPvwUyzhQhY1mO30thIH7MBanBtDZCBtbkNl979971JntUZqTSO6czexqILCwJ2bfvAVECgtX7aNEeQpjIsWc8FF5K_4",
        "detections": "4/93"
      },
      {
        "date": "2021-11-05 14:22:16",
        "url": "http://www.besthotel360.com:1219/001/puppet.Txt?80044",
        "detections": "1/93"
      },
      {
        "date": "2021-11-05 14:02:45",
        "url": "http://1.1.1.1/positron/discovery",
        "detections": "1/93"
      },
      {
        "date": "2021-11-05 13:04:53",
        "url": "http://thee.network/",
        "detections": "12/93"
      },
      {
        "date": "2021-11-05 10:11:49",
        "url": "http://www.besthotel360.com:1219/001/puppet.Txt?82118",
        "detections": "1/92"
      },
      {
        "date": "2021-11-05 08:22:00",
        "url": "http://chetverg.xyz/",
        "detections": "7/92"
      },
      {
        "date": "2021-11-05 06:09:04",
        "url": "http://www.besthotel360.com:1219/001/puppet.Txt?97687",
        "detections": "1/92"
      }
    ],
    "detected_communicating_samples": [
      {
        "date": "2021-11-05 18:11:24",
        "detections": "0/0",
        "sha256": "f6390d83e5684b3dd5d4b6db71bfd7573a8eb0edcacf548cfb4715ae74eb0ac6"
      },
      {
        "date": "2021-11-05 18:06:05",
        "detections": "0/0",
        "sha256": "e9cbf160213511551b8af68f47e30a7bbca16ef707abb790ee7673cce1a786a4"
      },
      {
        "date": "2021-11-05 17:57:04",
        "detections": "0/0",
        "sha256": "d713e22c9bab1cc73d79f4ea7131ef8cc6ede776b9192474997c50000706b392"
      },
      {
        "date": "2021-11-05 17:56:14",
        "detections": "0/0",
        "sha256": "d4f684092f42598823dc6f9c1a4cf68576924c1700b5d05ae302d0604bd5e21c"
      },
      {
        "date": "2021-11-05 17:48:25",
        "detections": "0/0",
        "sha256": "c39706d752096fa39c44d7f438477721e6ff2cefec04b76ee88808c897d3a4d9"
      },
      {
        "date": "2021-11-05 17:39:28",
        "detections": "0/0",
        "sha256": "adf74bfffcc53e48b4cf4d89839daeb63a6dfefe06c19298f653b3af8bcff5a3"
      },
      {
        "date": "2021-11-05 17:33:42",
        "detections": "0/0",
        "sha256": "9f48278ecaff72c29f49eb8daa39d99c45369edaae6326da594af7097737a01c"
      },
      {
        "date": "2021-11-05 17:26:55",
        "detections": "0/0",
        "sha256": "8f0847c175118ed8b533bb5669a90f51c41905e11ec2e04e96741ab2d75f1ce7"
      },
      {
        "date": "2021-11-05 17:25:59",
        "detections": "0/0",
        "sha256": "8cf24462e9dfdd1aa558c51ee3d91b0da913caf2929debad1d3559a854fc2e61"
      },
      {
        "date": "2021-11-05 17:19:06",
        "detections": "0/0",
        "sha256": "7da6df949060f6825614f2a08ae687889f2764391b2e8d0941ed68ce26199cff"
      }
    ],
    "detected_downloaded_samples": [
      {
        "date": "2021-09-20 09:51:51",
        "detections": "1/72",
        "sha256": "2c141c06f7df57f11ef2c62f2a96093484a65df47065b1a475c53784af0e2664"
      },
      {
        "date": "2021-06-26 17:08:59",
        "detections": "7/74",
        "sha256": "8ad3794b215df1a4eaf1325a90a4357ad93476c9308b4e820e325d50eba50280"
      },
      {
        "date": "2021-04-15 03:35:40",
        "detections": "1/73",
        "sha256": "337dffc1333f286f559c052c45c97f48ac8136cbf6327c24739f058407f45d7d"
      },
      {
        "date": "2021-04-08 11:30:25",
        "detections": "1/74",
        "sha256": "72ec27bd0d959a1e6713d96b4e55c5a9b92ac6d1b5b5a4a8d5d1211422fcee57"
      },
      {
        "date": "2021-03-30 15:12:44",
        "detections": "11/74",
        "sha256": "92e9cf96de35f3f9b86c77ded463a4abb7c394a78ea9c14524996de96c920fe9"
      },
      {
        "date": "2020-10-18 08:17:53",
        "detections": "18/75",
        "sha256": "5a9007b9bcaf5a0a4685a55c2b477fc2b5072e03f98f3f2a310898b27d63d5f1"
      },
      {
        "date": "2020-06-09 05:28:01",
        "detections": "4/74",
        "sha256": "54b6ce478977f5242698ab1bac90fe11133d2339d1f24fc9d96649099128cd23"
      },
      {
        "date": "2020-03-14 06:31:57",
        "detections": "1/71",
        "sha256": "1c6c32f969e7f5d9bd7a3361388643db8955b8d3bf72c5fb73ea1b989702ab3e"
      },
      {
        "date": "2019-09-18 22:43:06",
        "detections": "1/72",
        "sha256": "9f89814b48fc3249bf67a8a6e4439d97391b10b99f02b3da9e38345be1f1ed3f"
      },
      {
        "date": "2018-04-16 02:49:06",
        "detections": "23/62",
        "sha256": "0773b94a2e3239eeda0d02f32d8beea116783b48172c116c9b6b382338f8be13"
      }
    ],
    "detected_referrer_samples": [
      {
        "sha256": "fe76c029c702ab5f7f6f26e58d56d7dc5a7419947e4b747ef20433c43b456252",
        "detections": "0/53"
      },
      {
        "sha256": "f7b72d219e80830fab064ef3190811b022680a0aba4614d7e0e95e90a6268c6b",
        "detections": "0/56"
      },
      {
        "sha256": "ed333742b1d328e83a2eb2610d94b1ac70b6f88a40b978d0683502b819d45285",
        "detections": "0/53"
      },
      {
        "sha256": "ec904beca8b268a4a26ec09d32614e4064698b59dc2df848b22eac4f5a49f0c9",
        "detections": "0/55"
      },
      {
        "sha256": "eb9ca996df33909ab25b98e033d820cf0b687d7d833d38e4948749163ed60c10",
        "detections": "0/53"
      },
      {
        "sha256": "e953ac3b639202cfc647a0ab36599f45a678161be47789c7cf3c2132177e5f44",
        "detections": "0/55"
      },
      {
        "sha256": "e6755e04f472f478684e6fec9226f7fc82fe0576b6e0ae7504ffcbb41832cb5c",
        "detections": "0/54"
      },
      {
        "sha256": "e220b8b5afe2745bd3a92d1d961fe5bb7bc06b02a0046c7a9e3bde06b8e2ad02",
        "detections": "0/53"
      },
      {
        "sha256": "e1f818767ba2c60a77d172da8bb31fd6e46a7291331568c00fe59877012b55cb",
        "detections": "0/54"
      },
      {
        "sha256": "e17a0261a12397547696519d748e0756d95c2fe694fa8399179a3aaad4f075cb",
        "detections": "0/53"
      }
    ]
  },
  "pt": {
    "passive_dns": [
      {
        "lastseen": "2021-11-05 09:52:46",
        "firstseen": "2021-05-25 11:31:39",
        "hostname": "sentri360.ai"
      },
      {
        "lastseen": "2021-11-05 08:07:03",
        "firstseen": "2021-06-11 04:15:47",
        "hostname": "yunxuetang.ai"
      },
      {
        "lastseen": "2021-11-05 08:05:51",
        "firstseen": "2020-01-08 20:33:20",
        "hostname": "tant.al"
      },
      {
        "lastseen": "2021-11-05 07:57:48",
        "firstseen": "2020-11-02 07:10:20",
        "hostname": "salgado.com.ar"
      },
      {
        "lastseen": "2021-11-05 07:43:27",
        "firstseen": "2016-03-08 21:26:03",
        "hostname": "lewicki.com.ar"
      },
      {
        "lastseen": "2021-11-05 07:25:37",
        "firstseen": "2020-12-06 20:19:25",
        "hostname": "azmedia.com.ar"
      },
      {
        "lastseen": "2021-11-05 07:24:52",
        "firstseen": "2021-06-30 18:20:49",
        "hostname": "prueba.cammesa.com.ar"
      },
      {
        "lastseen": "2021-11-05 07:20:14",
        "firstseen": "2016-02-09 17:22:21",
        "hostname": "df.eaglemobile.al"
      },
      {
        "lastseen": "2021-11-05 07:12:50",
        "firstseen": "2021-06-13 12:42:09",
        "hostname": "test.trovo.ai"
      },
      {
        "lastseen": "2021-11-05 07:06:27",
        "firstseen": "2018-05-20 00:00:50",
        "hostname": "links.rakbank.ae"
      }
    ]
  },
  "shodan": {
    "region_code": "CA",
    "ip": 16843009,
    "postal_code": null,
    "country_code": "US",
    "city": "San Francisco",
    "dma_code": null,
    "last_update": "2021-11-05T17:58:53.742055",
    "latitude": 37.7621,
    "tags": [],
    "area_code": null,
    "country_name": "United States",
    "hostnames": [
      "one.one.one.one"
    ],
    "org": "APNIC and Cloudflare DNS Resolver project",
    "data": [
      {
        "_shodan": {
          "id": "1a942a10-c194-41c7-918f-532adb7d9f39",
          "options": {},
          "ptr": true,
          "module": "dns-udp",
          "crawler": "d905ab419aeb10e9c57a336c7e1aa9629ae4a733"
        },
        "hash": 1592421393,
        "os": null,
        "opts": {
          "raw": "34ef818500010000000000000776657273696f6e0462696e640000100003"
        },
        "timestamp": "2021-11-05T17:58:53.742055",
        "isp": "Cloudflare, Inc.",
        "port": 53,
        "hostnames": [
          "one.one.one.one"
        ],
        "location": {
          "city": "San Francisco",
          "region_code": "CA",
          "area_code": null,
          "longitude": -122.3971,
          "country_code3": null,
          "country_name": "United States",
          "postal_code": null,
          "dma_code": null,
          "country_code": "US",
          "latitude": 37.7621
        },
        "dns": {
          "resolver_hostname": null,
          "recursive": true,
          "resolver_id": "AMS",
          "software": null
        },
        "ip": 16843009,
        "domains": [
          "one.one"
        ],
        "org": "APNIC and Cloudflare DNS Resolver project",
        "data": "\nRecursion: enabled\nResolver ID: AMS",
        "asn": "AS13335",
        "transport": "udp",
        "ip_str": "1.1.1.1"
      },
      {
        "hash": 344608050,
        "_shodan": {
          "id": "c209bbd0-fa7d-4aff-b5cd-e04825ef4e3b",
          "options": {
            "hostname": "mail.finanzcheckonline.de"
          },
          "ptr": true,
          "module": "http",
          "crawler": "bf213bc419cc8491376c12af31e32623c1b6f467"
        },
        "http": {
          "robots_hash": null,
          "redirects": [],
          "securitytxt": null,
          "title": "Origin DNS error | mail.finanzcheckonline.de | Cloudflare",
          "sitemap_hash": null,
          "robots": null,
          "server": "cloudflare",
          "host": "mail.finanzcheckonline.de",
          "html": "<!DOCTYPE html>\n<!--[if lt IE 7]> <html class=\"no-js ie6 oldie\" lang=\"en-US\"> <![endif]-->\n<!--[if IE 7]>    <html class=\"no-js ie7 oldie\" lang=\"en-US\"> <![endif]-->\n<!--[if IE 8]>    <html class=\"no-js ie8 oldie\" lang=\"en-US\"> <![endif]-->\n<!--[if gt IE 8]><!--> <html class=\"no-js\" lang=\"en-US\"> <!--<![endif]-->\n<head>\n<title>Origin DNS error | mail.finanzcheckonline.de | Cloudflare</title>\n<meta charset=\"UTF-8\" />\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />\n<meta http-equiv=\"X-UA-Compatible\" content=\"IE=Edge,chrome=1\" />\n<meta name=\"robots\" content=\"noindex, nofollow\" />\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />\n<link rel=\"stylesheet\" id=\"cf_styles-css\" href=\"/cdn-cgi/styles/main.css\" type=\"text/css\" media=\"screen,projection\" />\n\n\n<script defer src=\"https://api.radar.cloudflare.com/beacon.js\"></script>\n</head>\n<body>\n  <div id=\"cf-wrapper\">\n    <div class=\"cf-alert cf-alert-error cf-cookie-error hidden\" id=\"cookie-alert\" data-translate=\"enable_cookies\">Please enable cookies.</div>\n    <div id=\"cf-error-details\" class=\"p-0\">\n      <header class=\"mx-auto pt-10 lg:pt-6 lg:px-8 w-240 lg:w-full mb-15 antialiased\">\n         <h1 class=\"inline-block md:block mr-2 md:mb-2 font-light text-60 md:text-3xl text-black-dark leading-tight\">\n           <span data-translate=\"error\">Error</span>\n           <span>1016</span>\n         </h1>\n         <span class=\"inline-block md:block heading-ray-id font-mono text-15 lg:text-sm lg:leading-relaxed\">Ray ID: 6a9104826d0b4200 &bull;</span>\n         <span class=\"inline-block md:block heading-ray-id font-mono text-15 lg:text-sm lg:leading-relaxed\">2021-11-04 21:43:23 UTC</span>\n        <h2 class=\"text-gray-600 leading-1.3 text-3xl lg:text-2xl font-light\">Origin DNS error</h2>\n      </header>\n\n      <section class=\"w-240 lg:w-full mx-auto mb-8 lg:px-8\">\n          <div id=\"what-happened-section\" class=\"w-1/2 md:w-full\">\n            <h2 class=\"text-3xl leading-tight font-normal mb-4 text-black-dark antialiased\" data-translate=\"what_happened\">What happened?</h2>\n            <p>You've requested a page on a website (mail.finanzcheckonline.de) that is on the <a data-orig-proto=\"https\" data-orig-ref=\"www.cloudflare.com/5xx-error-landing/\" target=\"_blank\">Cloudflare</a> network. Cloudflare is currently unable to resolve your requested domain (mail.finanzcheckonline.de).\n            \n          </div>\n\n          \n          <div id=\"resolution-copy-section\" class=\"w-1/2 mt-6 text-15 leading-normal\">\n            <h2 class=\"text-3xl leading-tight font-normal mb-4 text-black-dark antialiased\" data-translate=\"what_can_i_do\">What can I do?</h2>\n            <p><strong>If you are a visitor of this website:</strong><br />Please try again in a few minutes.</p><p><strong>If you are the owner of this website:</strong><br />Check your DNS settings. If you are using a CNAME origin record, make sure it is valid and resolvable. <a rel=\"noopener noreferrer\" href=\"https://support.cloudflare.com/hc/en-us/articles/234979888-Error-1016-Origin-DNS-error\">Additional troubleshooting information here.</a></p>\n          </div>\n          \n      </section>\n\n      <div class=\"cf-error-footer cf-wrapper w-240 lg:w-full py-10 sm:py-4 sm:px-8 mx-auto text-center sm:text-left border-solid border-0 border-t border-gray-300\">\n  <p class=\"text-13\">\n    <span class=\"cf-footer-item sm:block sm:mb-1\">Cloudflare Ray ID: <strong class=\"font-semibold\">6a9104826d0b4200</strong></span>\n    <span class=\"cf-footer-separator sm:hidden\">&bull;</span>\n    <span class=\"cf-footer-item sm:block sm:mb-1\"><span>Your IP</span>: 164.106.13.235</span>\n    <span class=\"cf-footer-separator sm:hidden\">&bull;</span>\n    <span class=\"cf-footer-item sm:block sm:mb-1\"><span>Performance &amp; security by</span> <a rel=\"noopener noreferrer\" href=\"https://www.cloudflare.com/5xx-error-landing\" id=\"brand_link\" target=\"_blank\">Cloudflare</a></span>\n    \n  </p>\n</div><!-- /.error-footer -->\n\n\n    </div><!-- /#cf-error-details -->\n  </div><!-- /#cf-wrapper -->\n\n  <script type=\"text/javascript\">\n  window._cf_translation = {};\n  \n  \n</script>\n\n</body>\n</html>\n\n",
          "location": "/",
          "components": {},
          "html_hash": -845836375,
          "sitemap": null,
          "securitytxt_hash": null
        },
        "os": null,
        "opts": {},
        "timestamp": "2021-11-04T21:43:23.444247",
        "isp": "Cloudflare, Inc.",
        "port": 80,
        "hostnames": [
          "one.one.one.one"
        ],
        "location": {
          "city": "San Francisco",
          "region_code": "CA",
          "area_code": null,
          "longitude": -122.3971,
          "country_code3": null,
          "country_name": "United States",
          "postal_code": null,
          "dma_code": null,
          "country_code": "US",
          "latitude": 37.7621
        },
        "ip": 16843009,
        "domains": [
          "one.one"
        ],
        "org": "APNIC and Cloudflare DNS Resolver project",
        "data": "HTTP/1.1 530 \r\nDate: Thu, 04 Nov 2021 21:43:23 GMT\r\nContent-Type: text/html; charset=UTF-8\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nX-Frame-Options: SAMEORIGIN\r\nReferrer-Policy: same-origin\r\nCache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nExpires: Thu, 01 Jan 1970 00:00:01 GMT\r\nCF-RAY: 6a9104826d0b4200-AMS\r\nServer: cloudflare\r\n\r\n",
        "asn": "AS13335",
        "transport": "tcp",
        "ip_str": "1.1.1.1"
      },
      {
        "hash": -627329527,
        "_shodan": {
          "id": "8edca201-57f7-4695-9b71-5999ec20f404",
          "options": {
            "hostname": "sopwriter.com"
          },
          "ptr": true,
          "module": "https",
          "crawler": "bf213bc419cc8491376c12af31e32623c1b6f467"
        },
        "http": {
          "robots_hash": null,
          "redirects": [],
          "securitytxt": null,
          "title": null,
          "sitemap_hash": null,
          "robots": null,
          "server": "cloudflare",
          "host": "sopwriter.com",
          "html": "",
          "location": "/",
          "html_hash": 0,
          "sitemap": null,
          "securitytxt_hash": null
        },
        "os": null,
        "opts": {
          "vulns": [],
          "heartbleed": "2021/11/05 16:54:42 1.1.1.1:443 - SAFE\n"
        },
        "timestamp": "2021-11-05T16:53:17.462372",
        "isp": "Cloudflare, Inc.",
        "port": 443,
        "ssl": {
          "chain_sha256": [
            "25cda58e9c1dc24e2d197a3bb0862852cdd6e4b5619edb65f11adf0ef4beef3b",
            "3abbe63daf756c5016b6b85f52015fd8e8acbe277c5087b127a60563a841ed8a",
            "16af57a9f676b0ab126095aa5ebadef22ab31119d644ac95cd4b93dbf3f26aeb"
          ],
          "jarm": "27d3ed3ed0003ed1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c",
          "chain": [
            "-----BEGIN CERTIFICATE-----\nMIIFODCCBN6gAwIBAgIQDrwcvg9MESxap+jnJ/nwpDAKBggqhkjOPQQDAjBKMQsw\nCQYDVQQGEwJVUzEZMBcGA1UEChMQQ2xvdWRmbGFyZSwgSW5jLjEgMB4GA1UEAxMX\nQ2xvdWRmbGFyZSBJbmMgRUNDIENBLTMwHhcNMjEwNjI0MDAwMDAwWhcNMjIwNjIz\nMjM1OTU5WjB1MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQG\nA1UEBxMNU2FuIEZyYW5jaXNjbzEZMBcGA1UEChMQQ2xvdWRmbGFyZSwgSW5jLjEe\nMBwGA1UEAxMVc25pLmNsb3VkZmxhcmVzc2wuY29tMFkwEwYHKoZIzj0CAQYIKoZI\nzj0DAQcDQgAE0nYM3acVhvFEKxCiPMVitKXFUNqW/eBjeM2Vys/cAGcsv7dcN0bK\nec0S25PWCUgMXxiWlRbYgu0/3fpBkOr1RqOCA3kwggN1MB8GA1UdIwQYMBaAFKXO\nN+rrsHUOlGeItEX62SQQh5YfMB0GA1UdDgQWBBRG2vO4qXtlMpGaiglKq8ah54nz\n2jBABgNVHREEOTA3ghVzbmkuY2xvdWRmbGFyZXNzbC5jb22CDyouc29wd3JpdGVy\nLmNvbYINc29wd3JpdGVyLmNvbTAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYI\nKwYBBQUHAwEGCCsGAQUFBwMCMHsGA1UdHwR0MHIwN6A1oDOGMWh0dHA6Ly9jcmwz\nLmRpZ2ljZXJ0LmNvbS9DbG91ZGZsYXJlSW5jRUNDQ0EtMy5jcmwwN6A1oDOGMWh0\ndHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9DbG91ZGZsYXJlSW5jRUNDQ0EtMy5jcmww\nPgYDVR0gBDcwNTAzBgZngQwBAgIwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5k\naWdpY2VydC5jb20vQ1BTMHYGCCsGAQUFBwEBBGowaDAkBggrBgEFBQcwAYYYaHR0\ncDovL29jc3AuZGlnaWNlcnQuY29tMEAGCCsGAQUFBzAChjRodHRwOi8vY2FjZXJ0\ncy5kaWdpY2VydC5jb20vQ2xvdWRmbGFyZUluY0VDQ0NBLTMuY3J0MAwGA1UdEwEB\n/wQCMAAwggF9BgorBgEEAdZ5AgQCBIIBbQSCAWkBZwB2ACl5vvCeOTkh8FZzn2Ol\nd+W+V32cYAr4+U1dJlwlXceEAAABej4olF8AAAQDAEcwRQIgFiVMUgQ013HdMnj7\nLZl2JSrdUxVVf8ZJm+XUU3Vl5OACIQDm0qqJu9y98+DdrIz9gdjkZrwoXGWD5AtE\n+kJkcDGy3QB2ACJFRQdZVSRWlj+hL/H3bYbgIyZjrcBLf13Gg1xu4g8CAAABej4o\nlIcAAAQDAEcwRQIgcn26CTRu1+4ngG1Zh6+/lUZwkGxNZrIBMXq7cj6fMG8CIQCx\nr7tgSWBSnQrZ/8kCh/lc5qg+ex7hRprb2fosvQKJ6gB1AFGjsPX9AXmcVm24N3iP\nDKR6zBsny/eeiEKaDf7UiwXlAAABej4olLAAAAQDAEYwRAIgCbDCgwcgIW/LcSei\nQopb5A7Q8drI0iXDcJiDwFfozVoCIAM6dd87fhjkyIXUruaDYh9st5QPjTo5yK35\nO7WULb+HMAoGCCqGSM49BAMCA0gAMEUCIFhkYkqv/skYN9fswVuca/9Pcf9PfXEW\nvQURXA5zFZ5gAiEA7TGB06Xc7LcGX349DiytQc24gMpgaso11/xoJKOcmg4=\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nMIIDzTCCArWgAwIBAgIQCjeHZF5ftIwiTv0b7RQMPDANBgkqhkiG9w0BAQsFADBa\nMQswCQYDVQQGEwJJRTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJl\nclRydXN0MSIwIAYDVQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTIw\nMDEyNzEyNDgwOFoXDTI0MTIzMTIzNTk1OVowSjELMAkGA1UEBhMCVVMxGTAXBgNV\nBAoTEENsb3VkZmxhcmUsIEluYy4xIDAeBgNVBAMTF0Nsb3VkZmxhcmUgSW5jIEVD\nQyBDQS0zMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEua1NZpkUC0bsH4HRKlAe\nnQMVLzQSfS2WuIg4m4Vfj7+7Te9hRsTJc9QkT+DuHM5ss1FxL2ruTAUJd9NyYqSb\n16OCAWgwggFkMB0GA1UdDgQWBBSlzjfq67B1DpRniLRF+tkkEIeWHzAfBgNVHSME\nGDAWgBTlnVkwgkdYzKz6CFQ2hns6tQRN8DAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0l\nBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQAwNAYI\nKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j\nb20wOgYDVR0fBDMwMTAvoC2gK4YpaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL09t\nbmlyb290MjAyNS5jcmwwbQYDVR0gBGYwZDA3BglghkgBhv1sAQEwKjAoBggrBgEF\nBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzALBglghkgBhv1sAQIw\nCAYGZ4EMAQIBMAgGBmeBDAECAjAIBgZngQwBAgMwDQYJKoZIhvcNAQELBQADggEB\nAAUkHd0bsCrrmNaF4zlNXmtXnYJX/OvoMaJXkGUFvhZEOFp3ArnPEELG4ZKk40Un\n+ABHLGioVplTVI+tnkDB0A+21w0LOEhsUCxJkAZbZB2LzEgwLt4I4ptJIsCSDBFe\nlpKU1fwg3FZs5ZKTv3ocwDfjhUkV+ivhdDkYD7fa86JXWGBPzI6UAPxGezQxPk1H\ngoE6y/SJXQ7vTQ1unBuCJN0yJV0ReFEQPaA1IwQvZW+cwdFD19Ae8zFnWSfda9J1\nCZMRJCQUzym+5iPDuI9yP+kHyCREU3qzuWFloUwOxkgAyXVjBYdwRVKD05WdRerw\n6DEdfgkfCv4+3ao8XnTSrLE=\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ\nRTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD\nVQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTAwMDUxMjE4NDYwMFoX\nDTI1MDUxMjIzNTkwMFowWjELMAkGA1UEBhMCSUUxEjAQBgNVBAoTCUJhbHRpbW9y\nZTETMBEGA1UECxMKQ3liZXJUcnVzdDEiMCAGA1UEAxMZQmFsdGltb3JlIEN5YmVy\nVHJ1c3QgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMEuyKr\nmD1X6CZymrV51Cni4eiVgLGw41uOKymaZN+hXe2wCQVt2yguzmKiYv60iNoS6zjr\nIZ3AQSsBUnuId9Mcj8e6uYi1agnnc+gRQKfRzMpijS3ljwumUNKoUMMo6vWrJYeK\nmpYcqWe4PwzV9/lSEy/CG9VwcPCPwBLKBsua4dnKM3p31vjsufFoREJIE9LAwqSu\nXmD+tqYF/LTdB1kC1FkYmGP1pWPgkAx9XbIGevOF6uvUA65ehD5f/xXtabz5OTZy\ndc93Uk3zyZAsuT3lySNTPx8kmCFcB5kpvcY67Oduhjprl3RjM71oGDHweI12v/ye\njl0qhqdNkNwnGjkCAwEAAaNFMEMwHQYDVR0OBBYEFOWdWTCCR1jMrPoIVDaGezq1\nBE3wMBIGA1UdEwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3\nDQEBBQUAA4IBAQCFDF2O5G9RaEIFoN27TyclhAO992T9Ldcw46QQF+vaKSm2eT92\n9hkTI7gQCvlYpNRhcL0EYWoSihfVCr3FvDB81ukMJY2GQE/szKN+OMY3EU/t3Wgx\njkzSswF07r51XgdIGn9w/xZchMB5hbgF/X++ZRGjD8ACtPhSNzkE1akxehi/oCr0\nEpn3o0WC4zxe9Z2etciefC7IpJ5OCBRLbf1wbWsaY71k5h+3zvDyny67G7fyUIhz\nksLi4xaNmjICq44Y3ekQEe5+NauQrz4wlHrQMz2nZQ/1/I6eYs9HRCwBXbsdtTLS\nR9I4LtD+gdwyah617jzV/OeBHRnDJELqYzmp\n-----END CERTIFICATE-----\n"
          ],
          "dhparams": null,
          "versions": [
            "TLSv1",
            "-SSLv2",
            "-SSLv3",
            "TLSv1.1",
            "TLSv1.2",
            "TLSv1.3"
          ],
          "acceptable_cas": [],
          "tlsext": [
            {
              "id": 65281,
              "name": "renegotiation_info"
            },
            {
              "id": 11,
              "name": "ec_point_formats"
            },
            {
              "id": 35,
              "name": "session_ticket"
            },
            {
              "id": 5,
              "name": "status_request"
            }
          ],
          "ja3s": "3e550ebb68779faf39d733b83fd38332",
          "cert": {
            "sig_alg": "ecdsa-with-SHA256",
            "issued": "20210624000000Z",
            "expires": "20220623235959Z",
            "expired": false,
            "version": 2,
            "extensions": [
              {
                "data": "0\\x16\\x80\\x14\\xa5\\xce7\\xea\\xeb\\xb0u\\x0e\\x94g\\x88\\xb4E\\xfa\\xd9$\\x10\\x87\\x96\\x1f",
                "name": "authorityKeyIdentifier"
              },
              {
                "data": "\\x04\\x14F\\xda\\xf3\\xb8\\xa9{e2\\x91\\x9a\\x8a\\tJ\\xab\\xc6\\xa1\\xe7\\x89\\xf3\\xda",
                "name": "subjectKeyIdentifier"
              },
              {
                "data": "07\\x82\\x15sni.cloudflaressl.com\\x82\\x0f*.sopwriter.com\\x82\\rsopwriter.com",
                "name": "subjectAltName"
              },
              {
                "critical": true,
                "data": "\\x03\\x02\\x07\\x80",
                "name": "keyUsage"
              },
              {
                "data": "0\\x14\\x06\\x08+\\x06\\x01\\x05\\x05\\x07\\x03\\x01\\x06\\x08+\\x06\\x01\\x05\\x05\\x07\\x03\\x02",
                "name": "extendedKeyUsage"
              },
              {
                "data": "0r07\\xa05\\xa03\\x861http://crl3.digicert.com/CloudflareIncECCCA-3.crl07\\xa05\\xa03\\x861http://crl4.digicert.com/CloudflareIncECCCA-3.crl",
                "name": "crlDistributionPoints"
              },
              {
                "data": "0503\\x06\\x06g\\x81\\x0c\\x01\\x02\\x020)0\\'\\x06\\x08+\\x06\\x01\\x05\\x05\\x07\\x02\\x01\\x16\\x1bhttp://www.digicert.com/CPS",
                "name": "certificatePolicies"
              },
              {
                "data": "0h0$\\x06\\x08+\\x06\\x01\\x05\\x05\\x070\\x01\\x86\\x18http://ocsp.digicert.com0@\\x06\\x08+\\x06\\x01\\x05\\x05\\x070\\x02\\x864http://cacerts.digicert.com/CloudflareIncECCCA-3.crt",
                "name": "authorityInfoAccess"
              },
              {
                "critical": true,
                "data": "0\\x00",
                "name": "basicConstraints"
              },
              {
                "data": "\\x04\\x82\\x01i\\x01g\\x00v\\x00)y\\xbe\\xf0\\x9e99!\\xf0Vs\\x9fc\\xa5w\\xe5\\xbeW}\\x9c`\\n\\xf8\\xf9M]&\\\\%]\\xc7\\x84\\x00\\x00\\x01z>(\\x94_\\x00\\x00\\x04\\x03\\x00G0E\\x02 \\x16%LR\\x044\\xd7q\\xdd2x\\xfb-\\x99v%*\\xddS\\x15U\\x7f\\xc6I\\x9b\\xe5\\xd4Sue\\xe4\\xe0\\x02!\\x00\\xe6\\xd2\\xaa\\x89\\xbb\\xdc\\xbd\\xf3\\xe0\\xdd\\xac\\x8c\\xfd\\x81\\xd8\\xe4f\\xbc(\\\\e\\x83\\xe4\\x0bD\\xfaBdp1\\xb2\\xdd\\x00v\\x00\"EE\\x07YU$V\\x96?\\xa1/\\xf1\\xf7m\\x86\\xe0#&c\\xad\\xc0K\\x7f]\\xc6\\x83\\\\n\\xe2\\x0f\\x02\\x00\\x00\\x01z>(\\x94\\x87\\x00\\x00\\x04\\x03\\x00G0E\\x02 r}\\xba\\t4n\\xd7\\xee\\'\\x80mY\\x87\\xaf\\xbf\\x95Fp\\x90lMf\\xb2\\x011z\\xbbr>\\x9f0o\\x02!\\x00\\xb1\\xaf\\xbb`I`R\\x9d\\n\\xd9\\xff\\xc9\\x02\\x87\\xf9\\\\\\xe6\\xa8>{\\x1e\\xe1F\\x9a\\xdb\\xd9\\xfa,\\xbd\\x02\\x89\\xea\\x00u\\x00Q\\xa3\\xb0\\xf5\\xfd\\x01y\\x9cVm\\xb87x\\x8f\\x0c\\xa4z\\xcc\\x1b\\'\\xcb\\xf7\\x9e\\x88B\\x9a\\r\\xfe\\xd4\\x8b\\x05\\xe5\\x00\\x00\\x01z>(\\x94\\xb0\\x00\\x00\\x04\\x03\\x00F0D\\x02 \\t\\xb0\\xc2\\x83\\x07 !o\\xcbq\\'\\xa2B\\x8a[\\xe4\\x0e\\xd0\\xf1\\xda\\xc8\\xd2%\\xc3p\\x98\\x83\\xc0W\\xe8\\xcdZ\\x02 \\x03:u\\xdf;~\\x18\\xe4\\xc8\\x85\\xd4\\xae\\xe6\\x83b\\x1fl\\xb7\\x94\\x0f\\x8d:9\\xc8\\xad\\xf9;\\xb5\\x94-\\xbf\\x87",
                "name": "ct_precert_scts"
              }
            ],
            "fingerprint": {
              "sha256": "25cda58e9c1dc24e2d197a3bb0862852cdd6e4b5619edb65f11adf0ef4beef3b",
              "sha1": "25fe59e48faec79e168b94f68c509dfad8851e6d"
            },
            "serial": 1.9585926715947384e+37,
            "subject": {
              "C": "US",
              "L": "San Francisco",
              "CN": "sni.cloudflaressl.com",
              "O": "Cloudflare, Inc.",
              "ST": "California"
            },
            "pubkey": {
              "type": "dsa",
              "bits": 256
            },
            "issuer": {
              "C": "US",
              "CN": "Cloudflare Inc ECC CA-3",
              "O": "Cloudflare, Inc."
            }
          },
          "cipher": {
            "version": "TLSv1/SSLv3",
            "bits": 128,
            "name": "ECDHE-ECDSA-AES128-GCM-SHA256"
          },
          "trust": {
            "revoked": false,
            "browser": {
              "mozilla": true,
              "apple": true,
              "microsoft": true
            }
          },
          "handshake_states": [
            "before/connect initialization",
            "SSLv2/v3 write client hello",
            "SSLv2/v3 read server hello",
            "SSLv3/TLS read server hello",
            "SSLv3/TLS read server certificate",
            "SSLv3/TLS read server key exchange",
            "SSLv3/TLS read server done",
            "SSLv3/TLS write client key exchange",
            "SSLv3/TLS write change cipher spec",
            "SSLv3/TLS write finished",
            "SSLv3/TLS flush data",
            "SSLv3/TLS read server session ticket",
            "SSLv3/TLS read finished",
            "SSL negotiation finished successfully"
          ],
          "alpn": [
            "h2",
            "http/1.1"
          ],
          "ocsp": {
            "version": "1",
            "response_status": "successful",
            "responder_id": "0ABC0829178CA5396D7A0ECE33C72EB3EDFBC37A",
            "cert_status": "good",
            "produced_at": "2021-11-02 05:06:31",
            "signature_algorithm": "ecdsa-with-SHA384",
            "next_update": "2021-11-09 04:06:02",
            "this_update": "2021-11-02 04:51:02",
            "certificate_id": {
              "hash_algorithm": "sha1",
              "issuer_name_hash": "2B1D1E98CCF37604D6C1C8BD15A224C804130038",
              "issuer_name_key": "0ABC0829178CA5396D7A0ECE33C72EB3EDFBC37A",
              "serial_number": "0F75A36D32C16B03C7CA5F5F714A0370"
            }
          }
        },
        "hostnames": [
          "one.one.one.one"
        ],
        "location": {
          "city": "San Francisco",
          "region_code": "CA",
          "area_code": null,
          "longitude": -122.3971,
          "country_code3": null,
          "country_name": "United States",
          "postal_code": null,
          "dma_code": null,
          "country_code": "US",
          "latitude": 37.7621
        },
        "ip": 16843009,
        "domains": [
          "one.one"
        ],
        "org": "APNIC and Cloudflare DNS Resolver project",
        "data": "HTTP/1.1 301 Moved Permanently\r\nDate: Fri, 05 Nov 2021 16:53:16 GMT\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nCache-Control: max-age=3600\r\nExpires: Fri, 05 Nov 2021 17:53:16 GMT\r\nLocation: https://www.sopwriting.org\r\nExpect-CT: max-age=604800, report-uri=\"https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct\"\r\nReport-To: {\"endpoints\":[{\"url\":\"https:\\/\\/a.nel.cloudflare.com\\/report\\/v3?s=ods0cFfLJMHXKUSOYSFYGWnMX1PZx%2FAhs7giV2ybh6%2BFwgHeW1cDTkuDgGfjp5BcpM2Z4byvdleMiY0rpywMiBzQNAuLVePyuZ3QGvhmsTaWBygICDr05%2BxxjA4soYHV\"}],\"group\":\"cf-nel\",\"max_age\":604800}\r\nNEL: {\"success_fraction\":0,\"report_to\":\"cf-nel\",\"max_age\":604800}\r\nVary: Accept-Encoding\r\nServer: cloudflare\r\nCF-RAY: 6a9798ecfeda41c8-AMS\r\nalt-svc: h3=\":443\"; ma=86400, h3-29=\":443\"; ma=86400, h3-28=\":443\"; ma=86400, h3-27=\":443\"; ma=86400\r\n\r\n",
        "asn": "AS13335",
        "transport": "tcp",
        "ip_str": "1.1.1.1"
      }
    ],
    "asn": "AS13335",
    "isp": "Cloudflare, Inc.",
    "longitude": -122.3971,
    "country_code3": null,
    "domains": [
      "one.one"
    ],
    "ip_str": "1.1.1.1",
    "os": null,
    "ports": [
      80,
      443,
      53
    ]
  }
}

```
