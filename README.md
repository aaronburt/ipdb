# ipdb

**Per-country IP lists for allowlists and geoblocking, updated automatically.**

[![Update country lists](https://github.com/aaronburt/ipdb/actions/workflows/update.yml/badge.svg)](https://github.com/aaronburt/ipdb/actions/workflows/update.yml)
[![Latest release](https://img.shields.io/github/v/release/aaronburt/ipdb?label=data)](https://github.com/aaronburt/ipdb/releases/latest)
[![Data: CC BY 4.0](https://img.shields.io/badge/data-CC%20BY%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)

Ready-to-use CIDR lists for every country, in formats for **nginx**, **Traefik**, **CrowdSec**, **ipset** and **nftables**. Built from the free [DB-IP](https://db-ip.com) country database and refreshed whenever DB-IP publishes a new release.

---

## Download

The files live on the [`data` branch](https://github.com/aaronburt/ipdb/tree/data). Swap `GB` for any [ISO country code](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2).

| What | URL |
|---|---|
| IPv4 + IPv6 | `https://raw.githubusercontent.com/aaronburt/ipdb/data/lists/all/GB.txt` |
| IPv4 only | `https://raw.githubusercontent.com/aaronburt/ipdb/data/lists/v4/GB.txt` |
| IPv6 only | `https://raw.githubusercontent.com/aaronburt/ipdb/data/lists/v6/GB.txt` |
| Everything (zip) | `https://github.com/aaronburt/ipdb/releases/latest/download/country-lists.zip` |

## Formats

| Folder | Use it for |
|---|---|
| `lists/` | Plain CIDRs, one per line. Works with almost anything. |
| `nginx/` | `geo-country.conf` map, plus `allow/` and `deny/` includes |
| `traefik/` | `ipAllowList` middleware, one file per country |
| `ipset/` | `ipset restore` files (`hash:net`) |
| `nft/` | nftables sets |
| `manifest.json` | Source version, checksum and counts per country |

## Quick start

<details>
<summary><b>nginx</b>: block countries</summary>

```nginx
http {
    include /etc/nginx/geo-country.conf;

    map $geo_country $blocked {
        default 0;
        CN 1;
        RU 1;
    }

    server {
        if ($blocked) { return 403; }
    }
}
```
</details>

<details>
<summary><b>Traefik</b>: allow one country</summary>

Put `traefik/GB.yml` in your file provider's directory, then attach the middleware:

```yaml
labels:
  - "traefik.http.routers.myapp.middlewares=geo-allow-gb@file"
```
</details>

<details>
<summary><b>CrowdSec</b>: ban a country</summary>

```sh
curl -sSLO https://raw.githubusercontent.com/aaronburt/ipdb/data/lists/all/CN.txt
cscli decisions import -i CN.txt --format values --duration 168h --reason geoblock
```
</details>

<details>
<summary><b>ipset / iptables</b></summary>

```sh
ipset restore < GB.v4.ipset
iptables -I INPUT -m set ! --match-set geo-gb-v4 src -j DROP
```
</details>

<details>
<summary><b>nftables</b></summary>

```sh
nft -f GB.v4.nft
```

Then use `@gb_v4` in your rules, e.g. `ip saddr != @gb_v4 drop`.
</details>

> Big countries have tens of thousands of ranges. In nginx, prefer the `geo` map over large `allow`/`deny` files.

## How it works

Every Monday a [GitHub Actions workflow](.github/workflows/update.yml) downloads the latest DB-IP file and compares its checksum to the last build. If nothing changed, it stops. If there's a new release, it merges the ranges into minimal CIDR blocks, regenerates every format, and publishes them to the `data` branch and a new [release](https://github.com/aaronburt/ipdb/releases).

To run it locally (Python 3.9+, no dependencies):

```sh
python scripts/generate.py --input dbip-country-lite-YYYY-MM.csv.gz --out out
python tests/test_generate.py
```

## Accuracy

DB-IP Lite is a free, reduced-accuracy version of DB-IP's commercial data. Some ranges will be wrong or missing, so use these lists as a filter, not as proof of location.

## Attribution and license

<a href='https://db-ip.com'>IP Geolocation by DB-IP</a>

The lists are derived from [IP to Country Lite](https://db-ip.com/db/download/ip-to-country-lite) by [DB-IP.com](https://db-ip.com), licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Changes: ranges merged, converted to CIDR and grouped by country. The generated data is shared under the same license, so if you redistribute it, keep this attribution. This project is not affiliated with or endorsed by DB-IP.
