# ipdb

Per-country IP/CIDR lists, regenerated automatically from the free
[DB-IP IP to Country Lite](https://db-ip.com/db/download/ip-to-country-lite)
database, for use in allowlists and geoblocking with Traefik, CrowdSec, nginx,
ipset/nftables and similar tools.

> **Status: first version, not yet run against the live DB-IP file.** The
> generator is tested on synthetic data. The first workflow run against the
> real download is the real check of the CSV format.

## Attribution

This repository contains data derived from the **IP to Country Lite** database
by **[DB-IP.com](https://db-ip.com)**, licensed under the
[Creative Commons Attribution 4.0 International License (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).

<a href='https://db-ip.com'>IP Geolocation by DB-IP</a>

- **Source:** DB-IP IP to Country Lite, <https://db-ip.com/db/download/ip-to-country-lite>
- **Licensor:** DB-IP.com
- **License:** CC BY 4.0, <https://creativecommons.org/licenses/by/4.0/>
- **Changes made:** the original IP ranges were merged and converted into CIDR
  blocks, grouped by country (and by continent / EU membership where the source
  provides it), and written out in several plain-text and configuration
  formats. No other changes were made to the underlying country assignments.
- **No endorsement:** this repository is independent. It is not affiliated
  with, or endorsed by, DB-IP.com.

Every generated file carries the same attribution in its header (or, for
formats that cannot hold comments, in `manifest.json`).

## Licensing of this repository

- **Generated data** (everything under `lists/`, `nginx/`, `traefik/`,
  `ipset/`, `nft/` and `manifest.json`) is a derivative of the
  DB-IP data and is shared under **CC BY 4.0**, with the attribution above.
  If you reuse or redistribute it, you must keep the attribution and indicate
  any further changes you make.
- **Code** (the generator script and GitHub Actions workflow) is covered by the
  `LICENSE` file in this repository.

## Accuracy

DB-IP Lite is a free subset of DB-IP's commercial data and has reduced coverage
and accuracy. IP geolocation is never exact: some ranges will be assigned to
the wrong country or be missing. Treat these lists as a best-effort filter,
not as proof of where a user is located, and don't rely on them alone for
security-critical decisions.

## How it works

1. A scheduled GitHub Actions workflow checks weekly whether DB-IP has published
   a new monthly release.
2. If the release is new (different file / checksum from the one recorded in
   `manifest.json`), it downloads and extracts the CSV.
3. IP ranges are grouped by country, merged, and converted to the minimal set
   of CIDR blocks, for IPv4 and IPv6.
4. Per-country and per-tool files are generated, and the data is published.
   If nothing changed, the workflow exits without writing anything.

DB-IP updates the database monthly, so most weekly runs find nothing new.

## Layout

The workflow publishes generated files to the **`data` branch** (a single
commit, force-pushed on each update, so history never grows) and as assets on
each **GitHub Release**. The `main` branch holds only the code.

```
lists/v4/<CC>.txt        IPv4 CIDRs for one country (ISO 3166-1 alpha-2, e.g. GB.txt)
lists/v6/<CC>.txt        IPv6 CIDRs for one country
lists/all/<CC>.txt       IPv4 + IPv6 combined, one CIDR per line (also what CrowdSec imports)
nginx/geo-country.conf   one `geo $geo_country { ... }` map covering every country
nginx/allow/<CC>.conf    `allow <cidr>;` lines
nginx/deny/<CC>.conf     `deny <cidr>;` lines
traefik/<CC>.yml         file-provider snippet: ipAllowList middleware `geo-allow-<cc>`
ipset/<CC>.v4.ipset      `ipset restore` files (hash:net), also .v6
nft/<CC>.v4.nft          nftables set files (`nft -f`), also .v6
manifest.json            source file, sha256, build date, CIDR counts per country
ATTRIBUTION.txt          DB-IP attribution (also repeated in headers where comments are allowed)
```

Plain `lists/` files contain no comment lines so they can be fed to any tool;
their attribution is in `ATTRIBUTION.txt` and `manifest.json`. Files that
allow comments carry a header.

Large countries have tens of thousands of CIDRs. For nginx prefer the single
`geo` map over thousands of `allow`/`deny` lines, and expect big Traefik
`sourceRange` lists to make config reloads slower.

## Using the lists

Once the first release exists, fetch a stable URL on a schedule and reload your
service:

```
https://raw.githubusercontent.com/aaronburt/ipdb/data/lists/all/GB.txt
https://github.com/aaronburt/ipdb/releases/latest/download/country-lists.zip
```

## Running it yourself

```
python -I tests/test_generate.py
python -I scripts/generate.py --input dbip-country-lite-YYYY-MM.csv.gz --out out
```

Python 3.9+, standard library only. The GitHub Actions workflow
(`.github/workflows/update.yml`) runs weekly and on demand. It downloads this
or last month's file, compares its SHA-256 to `manifest.json` on the `data`
branch, and stops if nothing changed.

## Contributing

Issues and pull requests are welcome, especially for new output formats.
Please do not commit generated data by hand: it is produced by the workflow.
