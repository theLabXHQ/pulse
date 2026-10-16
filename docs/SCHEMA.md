# JSONL schema `pulse.v1`

Each line is one JSON object. The `schema` field is always `"pulse.v1"`. New optional fields may be
added (consumers should ignore fields they don't know); removing a field or changing its meaning only
happens with `pulse.v2`.

| Field | Type | Description |
|---|---|---|
| `schema` | string | `pulse.v1` |
| `timestamp` | RFC3339 UTC | when the result was produced |
| `input` | string | the input line (for a CIDR, the CIDR itself) |
| `discovered_from` | string? | source of a target found by `-tls-probe`/`-csp-probe`: `tls:<host>` or `csp:<host>` |
| `url` | string | URL of the first request (default ports are omitted) |
| `final_url` | string? | last URL when redirects are followed |
| `host`, `method` | string | probe parameters |
| `scheme`, `port`, `path` | ? | probe parameters (may be missing on a failed probe) |
| `ip` | string? | connected IP (absent when going through a proxy) |
| `status_code` | int | status of the last response |
| `content_length` | int | header value, or the length of the body read if there is none |
| `body_bytes` | int | bytes actually read (after decoding) |
| `body_truncated` | bool? | the `-rstr` limit was reached |
| `content_type` | string? | up to the `;` |
| `title` | string? | first `<title>` (not one inside an SVG), UTF-8, whitespace collapsed, ≤1 KiB |
| `webserver` | string? | `Server` header |
| `location` | string? | `Location` header |
| `http_version` | string? | `HTTP/1.1`, `HTTP/2.0` |
| `words`, `lines` | int | words: count of single spaces + 1; lines: count of `\n` + 1 (body trimmed) |
| `chain` | `[{url,status_code,location}]`? | redirect chain (when following) |
| `tls` | object? | `version, cipher, alpn, subject_cn, subject_an[], issuer_cn, issuer_org[], not_before, not_after, self_signed, expired, fingerprint_sha256` |
| `timing` | object | `dns_ms, connect_ms, tls_ms, ttfb_ms` (last hop), `total_ms` (all attempts) |
| `conn_reused` | bool? | the connection came from the pool |
| `attempts` | `[{scheme,port,status_code?,error?}]`? | present when there was more than one attempt: the evidence behind the scheme decision |
| `hash` | `{body_md5, header_md5, ...}`? | `-hash` (md5, sha1, sha256, sha512, mmh3, simhash) |
| `favicon` | `{url,mmh3,md5,error}`? | `-favicon` (mmh3 compatible with Shodan) |
| `tech` | string[]? | `-td` |
| `cdn` | bool? | `ip` is in a CDN or WAF range (always checked in JSON/CSV, offline); `false` for a cloud range, but `cdn_name`/`cdn_type` are filled in |
| `cdn_name` | string? | provider, e.g. `cloudflare`, `fastly`, `aws` |
| `cdn_type` | string? | `cdn`, `waf` or `cloud` (checked in that order) |
| `asn` | `{as_number,as_name,as_country,as_range[]}`? | `-asn`/`-asn-db`; on a lookup error, `warnings: ["asn_lookup_failed"]` |
| `vhost` | bool? | `-vhost`: a random `Host` gets a different page |
| `pipeline` | bool? | `-pipeline`: HTTP/1.1 pipelining is supported |
| `cname` | string[]? | `-cname`: CNAME chain |
| `body_preview` | string? | `-bp`: first N characters of the body (whitespace collapsed) |
| `extracts` | `{regex or preset: [matches]}`? | `-er` / `-ep` (url, ipv4, mail); from headers and body, deduplicated |
| `headers` | map? | `-irh`/`-irr` (lower-case keys) |
| `body` | string? | `-irr` |
| `stored_response_path` | string? | `-sr` |
| `warnings` | string[]? | `body_timeout`, `body_read_error`, `redirect_loop`, `too_many_redirects`, `invalid_redirect_location`, `undecoded_content_encoding`, `tls_impersonated` (the `-tls-impersonate` retry worked), `asn_lookup_failed`, `malformed_headers` (control characters in headers, parsed leniently) |
| `failed` | bool? | failed results, only output with `-probe` |
| `error` | `{class,phase,message}`? | when `failed` |

## Error classes (`error.class`)

`dns_nxdomain`, `dns_timeout`, `dns_error`, `conn_refused`, `conn_timeout`, `conn_reset`,
`conn_closed`, `net_unreachable`, `tls_handshake`, `tls_timeout`, `tls_plaintext_response`,
`response_timeout`, `protocol_error`, `redirect_loop`, `too_many_redirects`, `policy_denied`,
`host_skipped`, `cdn_port_skipped`, `proxy_error`, `canceled`, `invalid_request`, `other`.

Phases (`error.phase`): `dns`, `connect`, `tls`, `request`, `response`, `redirect`, `policy`.

## Examples

```json
{"schema":"pulse.v1","timestamp":"2026-10-14T07:42:07Z","input":"example.com","url":"https://example.com/","scheme":"https","host":"example.com","port":443,"path":"/","method":"GET","ip":"93.184.215.14","status_code":200,"content_length":1256,"body_bytes":1256,"content_type":"text/html","title":"Example Domain","http_version":"HTTP/1.1","words":118,"lines":46,"tls":{"version":"tls13","cipher":"TLS_AES_256_GCM_SHA384","subject_cn":"*.example.com","not_before":"...","not_after":"..."},"timing":{"dns_ms":12.1,"connect_ms":24.3,"tls_ms":51.0,"ttfb_ms":102.4,"total_ms":103.2}}
{"schema":"pulse.v1","timestamp":"...","input":"app.internal.example:8011","url":"http://app.internal.example:8011/","host":"app.internal.example","port":8011,"path":"/","method":"GET","content_length":0,"body_bytes":0,"words":0,"lines":0,"timing":{"dns_ms":0,"connect_ms":0,"tls_ms":0,"ttfb_ms":0,"total_ms":1.4},"failed":true,"error":{"class":"conn_refused","phase":"connect","message":"dial tcp 10.0.0.9:8011: connect: connection refused"}}
```
