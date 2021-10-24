# Stratosphere IP enrich
Get an IP address and enrich it with metadata and IoC


## Example run

```
./ip_enrich.py -i 1.1.1.1
IP: 1.1.1.1. Country: AU. AS Org: CLOUDFLARENET
VT Resolutions (top 10, sorted by datetime):
2021-10-22 10:14:54: 01eeda8e7e38183e5676cbabe5b8b11e.19f7f31a1a944816d5f44d89024aff48.h.i.ydscan.net
2021-10-18 13:55:09: 0-v-0.xyz
2021-10-15 17:32:42: 0.0token.breadapp.com
2021-10-15 17:32:41: 0.0.0token.breadapp.com
2021-10-14 23:20:50: 0000jb.com
2021-10-12 07:54:09: 0.0stage.breadapp.com
2021-10-12 07:54:08: 0.0.0stage.breadapp.com
2021-10-12 07:54:07: 0.0.0.0stage.breadapp.com
2021-09-26 08:05:51: 0214.tech
2021-09-22 18:25:03: 0.s.cf
VT URLs (top 10, sorted by datetime):
2021-10-24 09:43:14: http://www.besthotel360.com:1219/001/puppet.Txt?82664. Positives: 1/91
2021-10-24 08:37:40: http://willbshots.com/images. Positives: 11/91
2021-10-24 06:51:07: https://i7saan.com/. Positives: 2/91
2021-10-24 06:02:04: http://www.besthotel360.com:1219/001/puppet.Txt?83054. Positives: 1/91
2021-10-24 04:10:06: http://doormouse.net/ldlkdsd/mweb/mweb.php?email=andyyorke@mweb.co.za. Positives: 16/91
2021-10-24 03:58:37: http://korberpie8p6f.servebeer.com/fb.png. Positives: 3/91
2021-10-23 23:30:17: http://thee.network/. Positives: 12/92
2021-10-23 22:40:39: http://www.besthotel360.com:1219/001/puppet.Txt?84240. Positives: 1/91
2021-10-23 22:15:48: http://1.1.1.1/. Positives: 2/91
2021-10-23 21:42:30: http://laurenlevinemovement.com/. Positives: 1/91
VT Detected Communicating Samples (top 10, sorted by datetime):
2021-10-24 08:39:51: Positives: 0, Total: 0, SHA256: 4be104f3d27c7df1f3bb228fecf65e4f5a1a26f2cabe155d8999c773f5b5412b
2021-10-24 07:51:25: Positives: 0, Total: 74, SHA256: 3efc4eaf71ba84c4bd64ad1272dfd56e197915b68382911a9afe1b6fb2cb6616
2021-10-24 06:39:47: Positives: 0, Total: 0, SHA256: f503f6fbe90d11ebe350fb0fd339573012c9fe14517f8dd210b127ab3ca77fbc
2021-10-24 06:01:17: Positives: 0, Total: 0, SHA256: 1e73b10c8787d4c5555cbfc6047e35ffe561a8f77d0ddcdd1e4987f5500df66e
2021-10-24 05:02:57: Positives: 0, Total: 0, SHA256: 1097e1dec420c608afbe1b557c5844df93c24716adeadd163ac0772bed38079e
2021-10-24 03:25:55: Positives: 0, Total: 0, SHA256: d2bbbc73bb120ca79fab610e066d83d42c00f27338b92dfdae780eda10a082e1
2021-10-24 02:58:02: Positives: 0, Total: 0, SHA256: 43cee038ef89081980d12b1b12b310ef2f6a31041a4e919aa4692320248ecf13
2021-10-24 02:22:18: Positives: 0, Total: 0, SHA256: c37e2483d0e5d7e9d2ba8ca79a89972dc1697371c53926a9fe07be6703c3ea48
2021-10-24 01:39:34: Positives: 0, Total: 0, SHA256: 43ee846a5f385e49eedd6a144c2b88b9dc69ad6b22f358295fc36f3839bb98bb
2021-10-23 23:55:39: Positives: 0, Total: 0, SHA256: 357c3ea2cd118e104b1869f5c1baf513938e2d857dd8a103e260b5ef67f7a343
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
```
