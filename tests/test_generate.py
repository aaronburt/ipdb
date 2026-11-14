import gzip
import ipaddress
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import generate

THREE_COL = '''"1.0.0.0","1.0.0.255","AU"
"1.0.1.0","1.0.1.255","AU"
"1.0.2.0","1.0.2.255","CN"
"2001:db8::","2001:db8::ffff","DE"
"10.0.0.0","10.0.0.9","ZZ"
'''

SEVEN_COL = '''"1.0.0.0","1.0.0.255","OC","Oceania","AU","0","Australia"
"1.0.1.0","1.0.1.255","OC","Oceania","AU","0","Australia"
'''


def write(tmp, text, name="in.csv", gz=False):
    p = Path(tmp) / name
    if gz:
        with gzip.open(p, "wt") as f:
            f.write(text)
    else:
        p.write_text(text)
    return p


class GenerateTests(unittest.TestCase):
    def test_merge_and_cidr(self):
        with tempfile.TemporaryDirectory() as t:
            data, stats = generate.build(write(t, THREE_COL))
        self.assertEqual([str(n) for n in data["AU"][4]], ["1.0.0.0/23"])
        self.assertEqual([str(n) for n in data["CN"][4]], ["1.0.2.0/24"])
        self.assertEqual([str(n) for n in data["DE"][6]], ["2001:db8::/112"])
        self.assertNotIn("ZZ", data)
        self.assertEqual(stats["rows"], 5)

    def test_non_aligned_range(self):
        with tempfile.TemporaryDirectory() as t:
            p = write(t, '"1.0.0.1","1.0.0.6","AU"\n')
            data, _ = generate.build(p)
        self.assertEqual([str(n) for n in data["AU"][4]],
                         ["1.0.0.1/32", "1.0.0.2/31", "1.0.0.4/31", "1.0.0.6/32"])

    def test_address_count_preserved(self):
        with tempfile.TemporaryDirectory() as t:
            data, _ = generate.build(write(t, THREE_COL))
        total = sum(n.num_addresses for n in data["AU"][4])
        self.assertEqual(total, 512)

    def test_seven_column_and_gzip(self):
        with tempfile.TemporaryDirectory() as t:
            data, _ = generate.build(write(t, SEVEN_COL, "in.csv.gz", gz=True))
        self.assertEqual([str(n) for n in data["AU"][4]], ["1.0.0.0/23"])

    def test_header_row(self):
        with tempfile.TemporaryDirectory() as t:
            text = "ip_start,ip_end,continent,country_code\n1.0.0.0,1.0.0.255,OC,AU\n"
            data, _ = generate.build(write(t, text))
        self.assertIn("AU", data)

    def test_overlap_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            p = write(t, '"1.0.0.0","1.0.0.255","AU"\n"1.0.0.128","1.0.1.0","CN"\n')
            with self.assertRaises(ValueError):
                generate.build(p)
            data, stats = generate.build(p, allow_overlap=True)
        self.assertEqual(stats["overlaps"], 1)

    def test_same_country_overlap_allowed(self):
        with tempfile.TemporaryDirectory() as t:
            p = write(t, '"1.0.0.0","1.0.0.255","AU"\n"1.0.0.0","1.0.0.255","AU"\n')
            data, stats = generate.build(p)
        self.assertEqual(stats["overlaps"], 0)
        self.assertEqual([str(n) for n in data["AU"][4]], ["1.0.0.0/24"])

    def test_nft_elements(self):
        with tempfile.TemporaryDirectory() as t:
            src = write(t, '"1.0.0.0","1.0.0.255","AU"\n"1.0.2.0","1.0.2.255","AU"\n')
            out = Path(t) / "out"
            generate.main(["--input", str(src), "--out", str(out), "--min-countries", "1"])
            text = (out / "nft/AU.v4.nft").read_text()
        self.assertIn("add element inet geo au_v4 {\n  1.0.0.0/24,\n  1.0.2.0/24\n}", text)

    def test_bad_input(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(ValueError):
                generate.build(write(t, '"1.0.0.0","1.0.0.255","Australia"\n'))
            with self.assertRaises(ValueError):
                generate.build(write(t, ""))

    def test_outputs_and_manifest(self):
        with tempfile.TemporaryDirectory() as t:
            src = write(t, THREE_COL)
            out = Path(t) / "out"
            rc = generate.main(["--input", str(src), "--out", str(out), "--min-countries", "1",
                                "--generated-at", "2026-11-14T00:00:00Z"])
            self.assertEqual(rc, 0)
            self.assertEqual((out / "lists/v4/AU.txt").read_text(), "1.0.0.0/23\n")
            self.assertEqual((out / "lists/all/DE.txt").read_text(), "2001:db8::/112\n")
            self.assertIn("allow 1.0.0.0/23;", (out / "nginx/allow/AU.conf").read_text())
            self.assertIn("1.0.0.0/23 AU;", (out / "nginx/geo-country.conf").read_text())
            self.assertIn('- "1.0.0.0/23"', (out / "traefik/AU.yml").read_text())
            self.assertIn("add geo-au-v4 1.0.0.0/23 -exist", (out / "ipset/AU.v4.ipset").read_text())
            self.assertIn("1.0.0.0/23", (out / "nft/AU.v4.nft").read_text())
            self.assertTrue((out / "ATTRIBUTION.txt").exists())
            m = json.loads((out / "manifest.json").read_text())
            self.assertEqual(m["countries"]["AU"]["v4_cidrs"], 1)
            self.assertEqual(len(m["source"]["sha256"]), 64)
            self.assertIn("DB-IP", m["attribution"])

    def test_checksums(self):
        import hashlib
        with tempfile.TemporaryDirectory() as t:
            out = Path(t) / "out"
            generate.main(["--input", str(write(t, THREE_COL)), "--out", str(out), "--min-countries", "1"])
            digest = hashlib.sha256((out / "traefik/AU.yml").read_bytes()).hexdigest()
            self.assertEqual((out / "traefik/AU.yml.sha256").read_text(), f"{digest}  AU.yml\n")
            sums = (out / "SHA256SUMS").read_text()
            self.assertIn(f"{digest}  traefik/AU.yml\n", sums)
            self.assertIn("  manifest.json\n", sums)
            self.assertNotIn(".sha256", sums)
            m = json.loads((out / "manifest.json").read_text())
            self.assertEqual(m["files"]["traefik/AU.yml"], digest)
            self.assertNotIn("manifest.json", m["files"])
            import subprocess
            r = subprocess.run(["sha256sum", "-c", "--quiet", "SHA256SUMS"], cwd=out, capture_output=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_min_countries_guard(self):
        with tempfile.TemporaryDirectory() as t:
            rc = generate.main(["--input", str(write(t, THREE_COL)), "--out", str(Path(t) / "o")])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
