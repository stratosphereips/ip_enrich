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
[+] Getting the PassiveTotal Blacklist

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
	2021-11-05 14:22:16: http://www.besthotel360.com:1219/001/puppet.Txt?80044. Positives: 1/93
	2021-11-05 14:02:45: http://1.1.1.1/positron/discovery. Positives: 1/93
	2021-11-05 13:04:53: http://thee.network/. Positives: 12/93
	2021-11-05 12:22:22: http://shenzhengyunde.com/wp-content/plugins/Citrus. Positives: 9/92
	2021-11-05 11:26:00: http://fabianomeroete.gettrials.com/. Positives: 7/92
	2021-11-05 10:11:49: http://www.besthotel360.com:1219/001/puppet.Txt?82118. Positives: 1/92
	2021-11-05 08:22:00: http://chetverg.xyz/. Positives: 7/92
	2021-11-05 06:09:04: http://www.besthotel360.com:1219/001/puppet.Txt?97687. Positives: 1/92
	2021-11-05 04:22:23: http://shenzhengyunde.com/. Positives: 7/92
	2021-11-05 03:20:50: http://kingslanddomain.ddns.net/. Positives: 9/93
VT Detected Communicating Samples (top 10, sorted by datetime):
	2021-11-05 14:13:24: Positives: 0, Total: 0, SHA256: 9c18ab3a341e5978c37293254fac5a42ed4eaf0e77ab6ebf7da794a82af36c03
	2021-11-05 13:59:27: Positives: 0, Total: 73, SHA256: 4443209ffc27fb07aa1f982aa6ddb2158b248ae60df614cd6aea5fbcba6ef3d7
	2021-11-05 12:49:00: Positives: 0, Total: 0, SHA256: 19ea8212533ba082d8aeca408c4bce9d267162386498d511c763592ba1015244
	2021-11-05 11:42:28: Positives: 0, Total: 0, SHA256: e7f5db6bd5309656c7c62f2f5f6acb1e6d93fec4c589392bd66ffd9e8516519b
	2021-11-05 10:54:38: Positives: 0, Total: 0, SHA256: 925f0c4e06d5c95b3123ad1c725e962f31e34b5a3adacb175cc0e8ed30c31b8b
	2021-11-05 10:54:03: Positives: 0, Total: 0, SHA256: a73317ad3671e11a070a8b4d1bb9ce9400c5de4108d83d430e89f53cc2a4a3b4
	2021-11-05 10:24:54: Positives: 0, Total: 0, SHA256: 932c649d2db5c298dad64fa1f4d98c76e3e0e6951a3d475a9a7adf45399eec3f
	2021-11-05 09:43:57: Positives: 0, Total: 72, SHA256: 9caa88c6ccec642fa388c9b2b690270f638b5b7a09bf07464cb7575f987c860b
	2021-11-05 08:45:21: Positives: 0, Total: 0, SHA256: 752a51fa289044cd82af6cdc52ff30a7f39f5cfc8b9edd103b4c4e2dbbeb7e53
	2021-11-05 08:35:38: Positives: 0, Total: 0, SHA256: 25aa50c23d173bd732860d1793931b4d08d7f63f6dc7bb8c963da18acfbdb2ab
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
PassiveTotal Data (top 10, sorted by lastSeen). 	First Seen: 2011-02-12 13:38:44. Last Seen: 2021-11-05 05:51:50. Records: 55
	LastSeen: 2021-11-05 05:51:50. FirstSeen: 2021-05-25 11:31:39. Hostname: sentri360.ai.
	LastSeen: 2021-11-05 04:46:44. FirstSeen: 2019-09-23 18:55:18. Hostname: go.eye4.ai.
	LastSeen: 2021-11-05 04:42:02. FirstSeen: 2018-03-15 07:31:10. Hostname: malettigroup.am.
	LastSeen: 2021-11-05 04:41:29. FirstSeen: 2020-04-08 09:12:44. Hostname: test.prod.einstein.ai.
	LastSeen: 2021-11-05 04:41:02. FirstSeen: 2020-04-02 14:27:02. Hostname: fullstory.ai.
	LastSeen: 2021-11-05 04:36:37. FirstSeen: 2021-05-04 05:21:03. Hostname: dev.connected-fleet.ai.
	LastSeen: 2021-11-05 04:03:49. FirstSeen: 2019-05-08 22:30:26. Hostname: ns3.ui.am.
	LastSeen: 2021-11-05 04:00:46. FirstSeen: 2021-05-25 17:21:36. Hostname: auth.sentri360.ai.
	LastSeen: 2021-11-05 03:54:18. FirstSeen: 2021-05-31 20:54:08. Hostname: stg.connected-fleet.ai.
	LastSeen: 2021-11-05 03:48:30. FirstSeen: 2011-02-12 13:38:44. Hostname: ns1.dot.ad.
	LastSeen: 2021-11-05 03:45:40. FirstSeen: 2021-04-04 10:29:45. Hostname: zimbra.softamer.com.ar.
```



## TODO

- Implement https://api.riskiq.net/api/ssl/
- Implement https://api.riskiq.net/api/blacklist/
