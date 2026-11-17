# CTI Portfolio Tools

Little tools that go with the [CTI portfolio series](https://ctijen.com/blog/show-your-work-building-a-cti-portfolio) on ctijen.com. Free, beginner-friendly, and nothing to install beyond Python.

## pivot_out.py (Part 3: Script It)

Start from one domain and automate the boring half of the [Part 2 lab](https://ctijen.com/blog/cti-portfolio-part-2-from-one-domain):

1. **Registration** from RDAP (the modern, JSON version of WHOIS)
2. **Certificates and their SANs** from [crt.sh](https://crt.sh/), looping through any new domains it finds
3. **Passive DNS** from VirusTotal (optional), plus "what else lived on that IP around the same time?"

It writes everything to a CSV and a JSON file in `output/`, with every domain and IP defanged and every row tagged with where it came from and when.

### Everything is PASSIVE

The script NEVER touches the domain's own servers. No DNS lookups, no visiting, no scanning. Every request goes to a third party that already collected the data (a domain registry, crt.sh, VirusTotal). Please keep it that way if you change it!

### Setup

You need Python 3.9 or newer. Macs and most Linux machines already have it (check with `python3 --version`). No `pip install` needed, it only uses Python's standard library.

```bash
git clone https://github.com/CTIJen/cti-portfolio-tools.git
cd cti-portfolio-tools
```

**Optional: a free VirusTotal key** for passive DNS. Sign up at [virustotal.com](https://www.virustotal.com/), then go to your profile > API Key. Put it in your environment, NOT in the code:

```bash
export VT_API_KEY=your-key-here
```

(To keep it between sessions, add that line to `~/.zshrc` or `~/.bashrc` by opening the file in an editor, so the key doesn't end up in your shell history.)

No key? The script still runs RDAP and crt.sh and tells you it skipped passive DNS.

### Run it

```bash
python3 pivot_out.py evil.example
python3 pivot_out.py 'evil[.]example'          # defanged input works too
python3 pivot_out.py evil.example --rounds 2   # loop through new SANs twice
python3 pivot_out.py evil.example --skip-neighbors   # save VT quota
```

| Option | What it does | Default |
| --- | --- | --- |
| `--rounds` | How many times to loop through newly found SANs | 1 |
| `--max-domains` | Stop adding new domains after this many | 25 |
| `--window` | Days apart that still count as "same time" for IP neighbors | 7 |
| `--skip-neighbors` | Don't ask VT what else lived on each IP | off |
| `--out` | Folder for the results | `output` |

### The traps it knows about

Real lesson from building this: half the work is knowing what NOT to pivot on.

- **Cloudflare IPs** get recorded but never pivoted on. Millions of unrelated sites share them.
- **Busy IPs** (30+ domains) get flagged as probably shared hosting instead of listing every neighbor.
- **Giant certs** (more than 50 SANs) are probably a CDN or shared hosting, so their SANs don't get looped through.
- **IP neighbors are leads**, not findings. They're recorded with how many days apart they were, but never looped through.
- **Attacker-controlled data gets checked.** SANs and passive DNS hostnames come from the attacker, so anything that isn't a clean domain is dropped before it goes into a URL, and CSV cells are protected against spreadsheet formula injection.

### Free tier limits

- **VirusTotal:** 4 lookups a minute and 500 a day. The script waits 16 seconds between VT calls, so it's slow on purpose.
- **crt.sh:** a free community service that times out a LOT. The script retries with backoff. If it still gives up, wait a bit and try again (it's not you, it's crt.sh).

### Tests

```bash
python3 -m unittest
```

The tests use fake data, so they don't hit any real service.

### Never commit your keys

`.env` and `output/` are in `.gitignore`. If you ever DO push a key by accident, regenerate it right away in your VirusTotal profile. Deleting the commit isn't enough, bots scrape GitHub for keys within minutes.

## License

MIT, see [LICENSE](LICENSE). Use it, change it, learn from it, just keep the copyright line.

## Resolution age filter

Use `--days` to limit passive DNS resolutions to recent UTC calendar dates:

```powershell
py .\pivot_out.py 'cdn-gstat[.]com' --days 90
```

Resolutions dated today through 90 days ago are included. Older resolutions
are excluded before being saved or used for IP-neighbor lookups.

- Omitting `--days` preserves the original behavior.
- `--days 0` includes only today's resolutions.
- Negative values are rejected.
- Missing, invalid, and future dates are excluded when filtering is enabled.
- Registration and certificate records are not filtered.
- Neighbor dates are still evaluated separately using `--window`.
- The filter does not establish current ownership or malicious activity.

The date-filter tests use a fixed reference date and require no API access.
Run the full suite with:

```powershell
py -m unittest
```
