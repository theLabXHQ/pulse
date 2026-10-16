<p align="center">
  <img src="images/pulse-banner.jpg" alt="Pulse" width="100%">
</p>

<p align="center">
<a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-e5484d?style=flat-square"></a>
<a href="go.mod"><img src="https://img.shields.io/badge/go-1.25%2B-e5484d?style=flat-square&logo=go&logoColor=white"></a>
<a href="https://github.com/theLabXHQ/pulse/releases"><img src="https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-e5484d?style=flat-square"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#recipes">Recipes</a> •
  <a href="#output">Output</a> •
  <a href="#notes">Notes</a>
</p>

<p align="center"><b>Find what's alive. Know what it runs.</b></p>

`pulse` is a fast, lightweight HTTP prober for reconnaissance. Give it hosts, URLs or CIDR ranges and it
tells you which ones serve HTTP(S), what they answer with — status, title, server, TLS, timing,
technologies — and, for the ones that don't, exactly why. It is built to stay fast and light on long
lists.

```console
$ cat hosts.txt | pulse -sc -title -server -td
https://example.com/ [200] [Example Domain] [cloudflare] [Cloudflare,HTTP/3]
https://httpbin.org/ [200] [httpbin.org] [gunicorn/19.9.0] [Python,React,Swagger UI,gunicorn:19.9.0,jQuery]
http://scanme.nmap.org/ [200] [Go ahead and ScanMe!] [Apache/2.4.7 (Ubuntu)] [Apache HTTP Server:2.4.7,Ubuntu]
```

# Features

 - **Any input** — hosts, URLs, CIDR ranges, files, stdin, Burp Suite exports, raw HTTP requests.
 - **Bounded memory** — queues, response bodies, DNS cache and error tracking all have hard limits; gzip bombs are harmless.
 - **Fast path first** — plain probing never waits on heavy work; technology and favicon detection run in their own workers.
 - **Reliable under load** — lost DNS packets are resent, hosts with several IPs are raced, and requests look like a real browser's.
 - **Smart scheme choice** — HTTPS first, HTTP only when it can still help; when it tries both, the `attempts` field shows why.
 - **Clear failures** — a stable error class and phase for every target that didn't answer.
 - **No API keys** — CDN, WAF and cloud detection fully offline; ASN over DNS, or offline from a local database (`-asn-db`).
 - **Polite by design** — global and per-host concurrency and rate limits, plus `-adaptive` back-off on 429/503 with `Retry-After`.
 - **Scoped discovery** — new hostnames from TLS certificates and CSP headers, kept inside the domain you started from.
 - **Long runs** — live stats, graceful Ctrl+C and `-resume` without losing results.
 - **One static binary** — Linux, macOS and Windows, amd64 and arm64, reproducible builds.

### What it can show

| Field | Flag | Field | Flag |
|---|---|---|---|
| Status code | `-sc` | IP address | `-ip` |
| Page title | `-title` | CNAME chain | `-cname` |
| Web server | `-server` | CDN / WAF / cloud | `-cdn` |
| Content type | `-ct` | ASN | `-asn` |
| Content length | `-cl` | TLS version | `-tls` |
| Line / word count | `-lc` / `-wc` | HTTP version | `-hv` |
| Redirect location | `-location` | Response time | `-rt` |
| Technologies | `-td` | Favicon hash (mmh3) | `-favicon` |
| Body hash | `-hash` | Body preview | `-bp` |
| Regex / preset extracts | `-er` / `-ep` | Virtual host | `-vhost` |
| HTTP pipelining | `-pipeline` | Failed targets and why | `-probe` |

JSON output (`-j`) always carries every core field — status, title, server, IP, CDN, TLS
certificate, timing and more — so text flags only decide what is printed on screen.

# Installation

**Binary** — download the file for your system and `SHA256SUMS` from the
[releases page](https://github.com/theLabXHQ/pulse/releases):

```sh
sha256sum -c SHA256SUMS --ignore-missing
mkdir -p ~/.local/bin && chmod +x pulse_*_linux_amd64 && mv pulse_*_linux_amd64 ~/.local/bin/pulse
```

**Go** — requires Go 1.25 or newer:

```sh
go install github.com/theLabXHQ/pulse/cmd/pulse@latest
```

The binary goes to `$(go env GOPATH)/bin` (usually `~/go/bin`); add it to your `PATH` if `pulse` is
not found.

**Source**:

```sh
git clone https://github.com/theLabXHQ/pulse.git
cd pulse
make build    # builds ./pulse for this machine
./pulse -h
```

To run it as plain `pulse` from anywhere, put it on your `PATH`:

```sh
sudo mv pulse /usr/local/bin/
```

On Windows, without `make`: `go build -trimpath -o pulse.exe ./cmd/pulse`, then move `pulse.exe` to a
folder on your `PATH`.

`make dist` is only for releases: it cross-compiles all six platforms into `dist/`.

# Usage

```sh
pulse -h
```

The everyday flags:

```console
USAGE
  pulse [flags] [-u target | -l file | < stdin]

TARGETS
  -u           target(s) to probe (repeatable, comma separated)
  -l           file with targets, one per line; '-' for stdin
  -p           ports, e.g. 80,443,8000-8010,https:8443
  -path        path(s) to probe: comma list or file

SHOW
  fields in text output; JSON (-j) always has them all
  -sc       status code     -title    page title      -server   Server header
  -td       technologies    -cl       content length  -ct       content type
  -ip       connected IP    -cdn      CDN/WAF/cloud   -location redirect target
  -tls      TLS version     -hv       HTTP version    -rt       response time
  -probe       also show failed targets, with their error class

MATCH / FILTER
  -mc / -fc    status codes, e.g. 200,301-303
  -ms / -fs    string in headers or body
  -mdc / -fdc  DSL, e.g. 'status_code == 200 && contains(body, "admin")'

REQUEST
  -fr          follow redirects
  -H           custom header 'Name: value' (repeatable)
  -x           request method(s)
  -r           DNS resolvers (default: system, then 1.1.1.1/8.8.8.8)

SPEED
  -t           concurrent probes (default 50)
  -rl          requests per second, all hosts; 0 = unlimited (default 150)
  -ch          concurrent probes per host; 0 = unlimited (default 8)
  -timeout     per attempt (default 10s)
  -adaptive    back off per host on 429/503/timeouts

OUTPUT
  -j           JSON Lines (schema pulse.v1)
  -o           also write results to this file
  -csv         CSV
  -silent      results only: no banner, no summary
  -resume      save progress to a file and continue from it
```

All 111 flags, grouped by input, probes, matchers, filters, request, discovery, rate limit, timeouts
and output: `pulse -hh`.

# Recipes

### Scanning

**A whole network range**

```sh
pulse -u 10.0.0.0/24 -p 80,443,8080 -sc -title
```

**Many ports, saved as JSON Lines**

```sh
pulse -l hosts.txt -p 80,443,8000-8010,https:8443 -j -o results.jsonl
```

**Many paths, gently — 2 requests at a time and 5 per second per host**

```sh
pulse -l hosts.txt -path /admin,/login -ch 2 -rlh 5 -mc 200,401
```

**What didn't answer, and why**

```console
$ printf 'nonexistent.invalid\nexample.com\n' | pulse -probe
https://nonexistent.invalid/ [FAILED] [dns_nxdomain]
https://example.com/ [SUCCESS]
```

### Well-known files

**security.txt**

```sh
echo target.com | pulse -path '/.well-known/security.txt,/security.txt' -mc 200 \
  -mdc 'contains(content_type, "text/plain") && contains(body, "Contact:")'
```

**robots.txt and sitemap.xml**

```sh
echo target.com | pulse -path /robots.txt -fr -mc 200 -mdc 'contains(content_type, "text/plain")'
echo target.com | pulse -path /sitemap.xml -fr -mc 200 -mdc 'contains_any(content_type, "application/xml", "text/xml")'
```

**OpenID Connect discovery**

```sh
echo target.com | pulse -path /.well-known/openid-configuration -mc 200 \
  -mdc 'contains(content_type, "application/json") && contains(body, "\"issuer\"")'
```

### Fingerprinting

**Only WordPress sites**

```sh
pulse -l hosts.txt -td -mdc 'contains(tech, "WordPress")' -sc -title
```

**Skip anything behind a WAF, or keep only cloud-hosted IPs**

```sh
pulse -l hosts.txt -cdn -fcdn waf
pulse -l hosts.txt -cdn -mcdn cloud
```

**Favicon hash (Shodan-compatible mmh3)**

```console
$ echo github.com | pulse -favicon
https://github.com/ [1126989341]
```

**Expired TLS certificates**

```sh
pulse -l hosts.txt -j -silent | jq -r 'select(.tls.expired) | .url'
```

### Workflows

**A long run you can stop and continue**

```sh
pulse -l huge.txt -j -o out.jsonl -stats -resume pulse.resume
```

**Burp Suite**

```sh
pulse -l export.xml -im burp -sc -title -td               # URLs from a Burp XML export
pulse -l hosts.txt -request req.txt -sc -mc 200           # send a saved request to many hosts
pulse -u https://app.example.com -request raw.txt -unsafe # byte for byte, untouched
```

### Expressions

`-mdc` keeps results that match, `-fdc` drops them. Several `-mdc` match when any one is true;
several `-fdc` drop a result when any one is true.

```sh
pulse -l hosts.txt -mdc 'status_code == 200 && contains(to_lower(title), "admin")'
pulse -l hosts.txt -td -mdc 'contains(tech, "WordPress")' -fdc 'cdn_type == "waf"'
```

| Variables | Functions |
|---|---|
| `status_code` `content_length` `body_bytes` `words` `lines` `title` `body` `header` `webserver`/`server` `content_type` `location` `url` `final_url` `input` `host` `port` `scheme` `path` `method` `ip` `http_version` `response_time` (ms) `tech` (list) `cdn` `cdn_name` `cdn_type` `tls_version` `favicon` `asn` | `contains` `contains_any` `contains_all` `starts_with` `ends_with` `regex(pattern, s)` `len` `to_lower` `to_upper` `trim` |

# Output

With `-j`, every result is one JSON object per line (schema `pulse.v1`):

```json
{
  "url": "https://example.com/",
  "status_code": 200,
  "title": "Example Domain",
  "webserver": "cloudflare",
  "ip": "172.66.147.243",
  "cdn_name": "cloudflare",
  "cdn_type": "waf",
  "http_version": "HTTP/2.0",
  "tls": { "version": "tls13", "subject_cn": "example.com" },
  "timing": { "dns_ms": 1.3, "connect_ms": 71.5, "tls_ms": 252.3, "ttfb_ms": 615.0, "total_ms": 615.1 }
}
```

A target that didn't answer, with `-probe`:

```json
{ "input": "nonexistent.invalid", "failed": true,
  "error": { "class": "dns_nxdomain", "phase": "dns", "message": "lookup nonexistent.invalid: no such host" } }
```

Shortened for reading — every field, every error class and the compatibility rules are in
[docs/SCHEMA.md](docs/SCHEMA.md). CSV is available with `-csv`.

# Notes

- HTTPS is tried first; HTTP only when it can still help. `-nf` probes and reports both.
- A scheme can be set per port: `-p http:8080,https:8443`.
- Without `-r`, the system resolver is used, with automatic fallback to 1.1.1.1 / 8.8.8.8 if it stops answering (`-no-dns-fallback` turns this off).
- `-exclude-private` and `-deny CIDR` are checked after DNS, so a public name that points inside your network is skipped.
- Defaults: `-t 50`, `-ch 8`, `-rl 150`, `-timeout 10s`, `-rstr 1m` (max body size read per response).
- JSON fields are only ever added, never changed, within `pulse.v1`.
- Exit codes: `0` done, `1` runtime error, `2` usage error, `130` interrupted.
- Input is deduplicated (about 40 bytes per unique target); for lists of 100M+ lines use `-sd` with `sort -u`.
- Not included: JARM and screenshots.

# License

`pulse` is released under the [MIT License](LICENSE). Third-party components are listed in [NOTICE](NOTICE).

<p align="center">
  Made by <b>theLabX</b> — by the community, for the community.
</p>
