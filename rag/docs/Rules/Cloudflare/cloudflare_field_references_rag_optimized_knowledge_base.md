# Cloudflare Field References Knowledge Base for WAF Rule Generation
# 1. Field Reference Overview for Cloudflare WAF Rule Generation
## 1.1 Field Definition

A Cloudflare Rules language field represents a property of an HTTP request, HTTP response, Cloudflare-computed signal, raw request value, or product-specific security signal.

A Cloudflare WAF custom rule expression evaluates fields with operators and functions to decide whether a rule matches.

General expression pattern:

```text
<field> <comparison_operator> <value>
```

Example:

```text
lower(http.request.uri.query) contains "<script"
```

Compound expression pattern:

```text
<expression> <logical_operator> <expression>
```

Example:

```text
starts_with(http.request.uri.path, "/search")
and lower(http.request.uri.query) contains "<script"
```

## 1.2 Field Categories Relevant to WAF Rule Generation

| Field category | Primary use in WAF rule generation |
|---|---|
| URI fields | Match path, query string, full URI, URI arguments, and encoded/raw URI evidence. |
| Header fields | Match User-Agent, Referer, Content-Type, custom headers, scanner headers, or spoofed payload locations. |
| Cookie fields | Match malicious payloads in cookies or build cookie-based exceptions. |
| Body fields | Match form, multipart, raw body, body size, and body truncation conditions when plan support exists. |
| IP and geolocation fields | Scope rules by source IP, country, ASN, region, or trusted networks. |
| Bot and threat fields | Challenge suspicious traffic or exclude verified bots. |
| WAF score fields | Use Cloudflare attack scores for XSS, SQLi, RCE, or aggregate WAF risk when available. |
| API Shield fields | Match API endpoint/schema/session-token violations when generating API-focused WAF rules. |
| JWT fields | Match JWT claims for API scoping and access-policy style rules when add-on support exists. |
| TLS/mTLS fields | Scope rules by client certificate, TLS version, certificate verification, or mTLS posture. |
| Raw fields | Match original unmodified request values, especially encoded or pre-normalized payloads. |
| Response fields | Use only in response phases, not in ordinary request firewall custom rules. |

## 1.3 Field Selection Principle

When generating Cloudflare WAF rules, choose the narrowest field that matches the observed attack location:

1. Use `http.request.uri.args["name"][*]` when the vulnerable query parameter is known.
2. Use `http.request.uri.query` when the attack is query-based but the parameter name is unknown.
3. Use `raw.http.request.uri.query` when encoded payload evidence must be matched as received.
4. Use `http.request.uri.path` for path-based attacks or path scoping.
5. Use `http.request.body.*` fields only when body inspection is supported and payloads are in the body.
6. Use `http.request.headers["name"][*]` for header-based payloads.
7. Use `http.cookie` or `http.request.cookies` for cookie-based payloads.
8. Use `ip.src`, `ip.src.country`, or `ip.src.asnum` for scoping, allowlists, and exceptions.
9. Use `cf.*` fields for Cloudflare security intelligence, bot posture, WAF score, API Shield, or product-specific signals.

---

# 2. Core Request URI Fields

## 2.1 `http.request.uri`

### Definition

`http.request.uri` is the URI path and query string of the request.

Example value:

```text
/articles/index?section=539061&expand=comments
```

### Rule-generation use

Use `http.request.uri` when both path and query string must be inspected together.

Example:

```text
lower(http.request.uri) contains "<script"
```

### Best practices

- Prefer `http.request.uri.path` when only the path matters.
- Prefer `http.request.uri.query` when only query parameters matter.
- Use `http.request.uri` for broad matching only when the attack may span both path and query.

---

## 2.2 `http.request.uri.path`

### Definition

`http.request.uri.path` is the URI path of the request.

Example value:

```text
/articles/index
```

### Rule-generation use

Use `http.request.uri.path` to:

- scope a WAF rule to a vulnerable endpoint
- match admin, login, API, search, upload, or CMS paths
- detect path traversal or route-based probes
- exclude safe paths from broad block rules
- place skip exceptions for known trusted endpoints

### Common expressions

Exact path:

```text
http.request.uri.path eq "/login"
```

Path prefix:

```text
starts_with(http.request.uri.path, "/api/")
```

Path contains:

```text
http.request.uri.path contains "/admin"
```

Path traversal indicator:

```text
lower(http.request.uri.path) contains "../"
or lower(http.request.uri.path) contains "..%2f"
```

### Rule-generation guidance

- Use `starts_with()` for route prefixes.
- Use `eq` for exact paths.
- Use `contains` only when the path segment may appear in multiple positions.
- Combine path scoping with attack indicators to reduce false positives.

Example:

```text
starts_with(http.request.uri.path, "/search")
and lower(http.request.uri.query) contains "<script"
```

---

## 2.3 `http.request.uri.path.extension`

### Definition

`http.request.uri.path.extension` is the lowercased file extension in the URI path without the dot character.

Example values:

```text
php
aspx
jsp
html
js
css
png
```

### Rule-generation use

Use this field to scope rules by file type or avoid scanning static assets.

Examples:

```text
http.request.uri.path.extension in {"php" "aspx" "jsp"}
```

```text
not http.request.uri.path.extension in {"js" "css" "png" "jpg" "jpeg" "gif" "svg" "ico"}
```

### Best practices

- Use extension scoping to reduce false positives.
- Do not rely on extension alone as an attack indicator.
- Combine extension with path, query, or body attack indicators.

---

## 2.4 `http.request.uri.query`

### Definition

`http.request.uri.query` is the entire query string without the `?` delimiter.

Example value:

```text
section=539061&expand=comments
```

### Rule-generation use

Use `http.request.uri.query` when the attack appears in query parameters but the vulnerable parameter name is unknown.

Good for:

- reflected XSS in query parameters
- SQL injection in URL parameters
- open redirect parameters
- scanner payloads in query strings
- broad query-string detection

### XSS query example

```text
lower(http.request.uri.query) contains "<script"
or lower(http.request.uri.query) contains "onerror="
or lower(http.request.uri.query) contains "javascript:"
```

### SQLi query example

```text
lower(http.request.uri.query) contains "union select"
or lower(http.request.uri.query) contains "or 1=1"
or lower(http.request.uri.query) contains "sleep("
```

### Regex query example

```text
lower(http.request.uri.query) matches r"(<script|onerror\s*=|javascript:|union\s+select|or\s+1\s*=\s*1)"
```

### Best practices

- Use `lower()` because string comparisons are case-sensitive by default.
- Use `matches` for variable whitespace or token variants when plan support exists.
- Use `raw.http.request.uri.query` for encoded payloads as originally received.
- Use parameter-specific fields when the vulnerable parameter is known.

---

## 2.5 `http.request.full_uri`

### Definition

`http.request.full_uri` is the full URI as received by the web server.

### Rule-generation use

Use `http.request.full_uri` when host, scheme, path, and query context must be considered together.

Example:

```text
lower(http.request.full_uri) contains "redirect=http"
```

### Best practices

- Prefer narrower fields when possible.
- Use `http.host`, `http.request.uri.path`, and `http.request.uri.query` separately for clearer expressions.
- Use `http.request.full_uri` when matching complete URL patterns or redirects.

---

# 3. Raw URI Fields for Encoded Payload Detection

## 3.1 Raw Field Definition

Raw fields are prefixed with `raw.` and preserve original request values for later evaluations. Raw fields are not affected by actions of previously matched rules.

Raw fields are useful when the rule must match encoded or unmodified payload evidence.

## 3.2 `raw.http.request.uri`

### Definition

`raw.http.request.uri` is the raw URI path and query string without transformation.

### Use cases

Use this field for:

- encoded path and query payloads
- preserving original request evidence
- matching payloads before normalization
- detecting percent-encoded XSS, SQLi, or traversal indicators

Example:

```text
lower(raw.http.request.uri) contains "%3cscript"
```

## 3.3 `raw.http.request.uri.path`

### Definition

`raw.http.request.uri.path` is the raw URI path without transformation.

### Use cases

Use for encoded path traversal or path payloads.

Examples:

```text
lower(raw.http.request.uri.path) contains "..%2f"
```

```text
lower(raw.http.request.uri.path) contains "%2e%2e%2f"
```

## 3.4 `raw.http.request.uri.query`

### Definition

`raw.http.request.uri.query` is the raw query string without the `?` delimiter and without transformation.

### Use cases

Use for encoded query-string attacks.

Encoded XSS examples:

```text
lower(raw.http.request.uri.query) contains "%3cscript"
or lower(raw.http.request.uri.query) contains "%3csvg"
or lower(raw.http.request.uri.query) contains "onerror%3d"
or lower(raw.http.request.uri.query) contains "javascript%3a"
```

Encoded SQLi examples:

```text
lower(raw.http.request.uri.query) contains "%27"
and (
  lower(raw.http.request.uri.query) contains "or"
  or lower(raw.http.request.uri.query) contains "%20or%20"
)
```

```text
lower(raw.http.request.uri.query) contains "union%20select"
```

## 3.5 Raw URI Argument Fields

### Fields

| Field | Meaning |
|---|---|
| `raw.http.request.uri.args` | Raw HTTP URI arguments as a map. |
| `raw.http.request.uri.args.names` | Raw query argument names. |
| `raw.http.request.uri.args.values` | Raw query argument values. |

### Rule-generation use

Use raw argument fields when:

- parameter-specific matching is needed
- original encoded values matter
- normalized query argument fields are not sufficient

Example:

```text
any(lower(raw.http.request.uri.args.values[*]) contains "%3cscript")
```

## 3.6 Raw Field Best Practices

- Use raw fields for encoded payload evidence.
- Combine raw encoded checks with regular field checks for better coverage.
- Do not rely only on raw encoded checks if payloads may arrive decoded.
- Mention that raw fields may still include some basic normalization by Cloudflare's HTTP server.

Recommended combined pattern:

```text
lower(http.request.uri.query) contains "<script"
or lower(raw.http.request.uri.query) contains "%3cscript"
```

---

# 4. Query Argument Map Fields

## 4.1 `http.request.uri.args`

### Definition

`http.request.uri.args` is a map from query argument name to an array of string values.

When a query argument repeats, the array contains multiple values in the order they appear in the request.

Example value:

```json
{
  "search": ["red+apples"]
}
```

Example usage:

```text
any(http.request.uri.args["search"][*] == "red+apples")
```

### Rule-generation use

Use `http.request.uri.args` when the vulnerable query parameter is known.

Good for:

- reducing false positives
- targeting specific parameters such as `q`, `search`, `id`, `redirect`, `url`, `comment`, `username`
- handling repeated query parameters
- generating precise WAF custom rules

## 4.2 `http.request.uri.args.names`

### Definition

`http.request.uri.args.names` contains the names of query arguments in the request.

### Use cases

Use to detect suspicious parameter names or require the presence of a parameter.

Example:

```text
any(lower(http.request.uri.args.names[*]) == "redirect")
```

Example suspicious parameter names:

```text
any(lower(http.request.uri.args.names[*]) in {"cmd" "exec" "url" "redirect" "next"})
```

## 4.3 `http.request.uri.args.values`

### Definition

`http.request.uri.args.values` contains the values of query arguments.

### Use cases

Use when all query argument values should be inspected without matching argument names.

Example:

```text
any(lower(http.request.uri.args.values[*]) contains "<script")
```

SQLi example:

```text
any(lower(http.request.uri.args.values[*]) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()")
```

## 4.4 Parameter-Specific XSS Expression

```text
any(lower(http.request.uri.args["q"][*]) matches r"(<script|onerror\s*=|onload\s*=|javascript:)")
```

Use when:

- the vulnerable parameter is known
- broad query-string scanning creates false positives
- repeated values must be inspected

## 4.5 Parameter-Specific SQLi Expression

```text
any(lower(http.request.uri.args["id"][*]) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()")
```

Use when:

- SQLi appears in a known parameter
- parameters such as `id`, `product`, `category`, `search`, or `q` are known inputs
- false-positive reduction is important

## 4.6 Query Argument Best Practices

- Use `http.request.uri.query` when parameter names are unknown.
- Use `http.request.uri.args["name"][*]` when parameter names are known.
- Use `http.request.uri.args.values[*]` to inspect all values.
- Use `http.request.uri.args.names[*]` to inspect parameter names.
- Use `any()` when evaluating arrays.
- Use `lower()` for case-insensitive matching.
- Use raw query argument fields for encoded payloads.

---

# 5. Host, Method, User-Agent, Referer, and Cookie String Fields

## 5.1 `http.host`

### Definition

`http.host` is the hostname used in the full request URI.

### Rule-generation use

Use `http.host` to scope rules to specific hostnames.

Examples:

```text
http.host eq "example.com"
```

```text
http.host in {"www.example.com" "api.example.com"}
```

### Best practices

- Use exact host scoping to reduce false positives.
- Use `in` for multiple hosts.
- Use `lower(http.host)` if host case handling is uncertain.

## 5.2 `http.request.method`

### Definition

`http.request.method` is the HTTP method as an uppercase string.

Examples:

```text
GET
POST
PUT
DELETE
PATCH
```

### Rule-generation use

Use method scoping when an attack only appears in a specific method.

Examples:

```text
http.request.method eq "POST"
```

```text
http.request.method in {"POST" "PUT" "PATCH"}
```

Use cases:

- apply body inspection only to POST/PUT/PATCH
- scope login protections to POST
- restrict API protections to write methods
- avoid scanning GET-only static asset requests

## 5.3 `http.user_agent`

### Definition

`http.user_agent` is the HTTP `User-Agent` request header string.

### Rule-generation use

Use `http.user_agent` to detect scanners, suspicious clients, or automation indicators.

Examples:

```text
lower(http.user_agent) contains "sqlmap"
or lower(http.user_agent) contains "nikto"
or lower(http.user_agent) contains "acunetix"
```

```text
lower(http.user_agent) contains "python-requests"
or lower(http.user_agent) contains "curl"
```

### Best practices

- Do not rely on User-Agent alone for strong security because it is spoofable.
- Combine User-Agent with path, query payloads, IP reputation, bot score, or rate limiting.
- Use `http.request.headers["user-agent"][*]` when repeated headers must be inspected.

## 5.4 `http.referer`

### Definition

`http.referer` is the HTTP `Referer` request header.

### Rule-generation use

Use `http.referer` to scope or detect suspicious referrer patterns.

Example:

```text
lower(http.referer) contains "evil.example"
```

### Best practices

- Treat Referer as spoofable.
- Use only as a supporting signal or for low-risk policy scoping.
- Do not use Referer as a trusted authentication signal.

## 5.5 `http.cookie`

### Definition

`http.cookie` is the entire `Cookie` request header represented as a string.

### Rule-generation use

Use `http.cookie` for coarse cookie matching.

Examples:

```text
lower(http.cookie) contains "<script"
```

```text
lower(http.cookie) contains "union select"
```

### Best practices

- Use `http.cookie` when cookie map fields are unavailable or a coarse match is acceptable.
- Use `http.request.cookies` for structured cookie-specific matching when available.
- Cookie values can contain encoded data; consider raw or encoded literal checks.

---

# 6. Header Map Fields

## 6.1 `http.request.headers`

### Definition

`http.request.headers` is a map of request header names to arrays of header values.

Header names are accessed in lowercase.

Example:

```text
http.request.headers["user-agent"]
```

### Rule-generation use

Use header map fields when:

- the payload appears in a specific header
- repeated header values must be inspected
- a custom application header carries user input
- Content-Type or Accept headers are needed for scoping
- scanner indicators appear in header values

## 6.2 `http.request.headers.names`

### Definition

`http.request.headers.names` contains the names of headers in the HTTP request.

### Use cases

Detect whether a header exists:

```text
any(http.request.headers.names[*] == "x-api-key")
```

Detect suspicious or unusual header names:

```text
any(lower(http.request.headers.names[*]) contains "x-forwarded")
```

## 6.3 `http.request.headers.values`

### Definition

`http.request.headers.values` contains the values of all request headers.

### Use cases

Broad inspection across all header values:

```text
any(lower(http.request.headers.values[*]) contains "<script")
```

Scanner header values:

```text
any(lower(http.request.headers.values[*]) contains "sqlmap")
```

## 6.4 `http.request.headers.truncated`

### Definition

`http.request.headers.truncated` indicates whether the HTTP request contains too many headers.

### Rule-generation use

Use this field to detect header truncation and enforce conservative handling.

Example:

```text
http.request.headers.truncated
```

Strict security example:

```text
http.request.headers.truncated
and starts_with(http.request.uri.path, "/api/")
```

### Best practices

- Mention that truncated headers can reduce inspection reliability.
- For strict security endpoints, block or challenge truncated headers.
- For broad production traffic, start with logging or scoped enforcement.

## 6.5 Header-Based XSS Expression

```text
any(lower(http.request.headers["x-search"][*]) contains "<script")
or any(lower(http.request.headers["x-search"][*]) contains "onerror=")
or any(lower(http.request.headers["x-search"][*]) contains "javascript:")
```

## 6.6 User-Agent Scanner Expression Using Header Map

```text
any(lower(http.request.headers["user-agent"][*]) contains "sqlmap")
or any(lower(http.request.headers["user-agent"][*]) contains "nikto")
or any(lower(http.request.headers["user-agent"][*]) contains "acunetix")
```

## 6.7 Content-Type Scoped Body Rule

```text
any(lower(http.request.headers["content-type"][*]) contains "application/x-www-form-urlencoded")
and any(lower(http.request.body.form.values[*]) contains "<script")
```

## 6.8 Header Field Best Practices

- Header names in `http.request.headers["name"]` must be lowercase.
- Use `any()` for arrays of repeated header values.
- Treat client-controlled headers as spoofable unless the deployment guarantees integrity.
- Use Content-Type to scope body inspection.
- Use `http.request.headers.truncated` when header inspection completeness matters.

---

# 7. Cookie Map Fields

## 7.1 `http.request.cookies`

### Definition

`http.request.cookies` represents the `Cookie` HTTP header as a map.

Availability note:

- This field requires Pro or above.

### Rule-generation use

Use `http.request.cookies` for cookie-name-specific or cookie-value-specific rules.

Example pattern:

```text
any(lower(http.request.cookies["session_hint"][*]) contains "<script")
```

Use cases:

- payload in a specific cookie
- targeted cookie exception
- session or preference cookie policy
- cookie-based false-positive tuning

## 7.2 Cookie Payload Detection

Coarse cookie string detection:

```text
lower(http.cookie) contains "<script"
or lower(http.cookie) contains "javascript:"
```

Structured cookie map detection:

```text
any(lower(http.request.cookies["tracking"][*]) contains "<script")
```

SQLi cookie detection:

```text
lower(http.cookie) contains "union select"
or lower(http.cookie) contains "or 1=1"
```

## 7.3 Cookie Field Best Practices

- Use `http.cookie` for broad cookie string matching.
- Use `http.request.cookies` for named cookie matching when available.
- Scope cookie-based attack rules by path or host to reduce false positives.
- Mention plan requirements when using `http.request.cookies`.

---

# 8. Request Body Fields

## 8.1 Body Inspection Availability

Many Cloudflare request body fields require an Enterprise add-on or specific product support. Do not assume body fields are available for every account or phase.

When generating body-based WAF expressions:

- mention plan/add-on requirements
- provide query-string fallback when appropriate
- scope by method and Content-Type
- account for body truncation
- avoid using body fields in phases where unavailable

## 8.2 `http.request.body.raw`

### Definition

`http.request.body.raw` is the unaltered HTTP request body.

Availability note:

- Enterprise add-on.

### Rule-generation use

Use `http.request.body.raw` for raw body inspection when form parsing is unavailable or body content must be matched as received.

Example XSS:

```text
lower(http.request.body.raw) contains "<script"
or lower(http.request.body.raw) contains "onerror="
```

Example SQLi:

```text
lower(http.request.body.raw) contains "union select"
or lower(http.request.body.raw) contains "or 1=1"
```

## 8.3 `http.request.body.form`

### Definition

`http.request.body.form` represents the HTTP request body of a form as a map.

Availability note:

- Enterprise add-on.

### Rule-generation use

Use `http.request.body.form` for parameter-specific form-field matching.

Example:

```text
any(lower(http.request.body.form["comment"][*]) contains "<script")
```

## 8.4 `http.request.body.form.names`

### Definition

`http.request.body.form.names` contains form field names in an HTTP request body.

Example:

```text
any(lower(http.request.body.form.names[*]) == "comment")
```

Use cases:

- detect sensitive form field names
- scope body inspection to specific form fields
- validate expected form structure

## 8.5 `http.request.body.form.values`

### Definition

`http.request.body.form.values` contains form field values in an HTTP request body.

### Rule-generation use

Use for broad inspection across all submitted form values.

XSS example:

```text
any(lower(http.request.body.form.values[*]) contains "<script")
or any(lower(http.request.body.form.values[*]) contains "onerror=")
or any(lower(http.request.body.form.values[*]) contains "javascript:")
```

SQLi example:

```text
any(lower(http.request.body.form.values[*]) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()")
```

## 8.6 `http.request.body.multipart`

### Definition

`http.request.body.multipart` represents multipart request body fields as a map.

Availability note:

- Enterprise add-on.

### Related multipart fields

| Field | Purpose |
|---|---|
| `http.request.body.multipart.names` | Names for every multipart part. |
| `http.request.body.multipart.values` | Values for multipart parts. |
| `http.request.body.multipart.filenames` | Filenames for each multipart part. |
| `http.request.body.multipart.content_types` | Content-Type headers for each part. |
| `http.request.body.multipart.content_dispositions` | Content-Disposition headers for each part. |
| `http.request.body.multipart.content_transfer_encodings` | Content-Transfer-Encoding headers for each part. |

## 8.7 Multipart Upload Rule Patterns

Suspicious file extension:

```text
any(lower(http.request.body.multipart.filenames[*]) matches r"\.(php|phtml|jsp|aspx|exe)$")
```

Suspicious multipart value XSS:

```text
any(lower(http.request.body.multipart.values[*]) contains "<script")
```

Suspicious multipart content type:

```text
any(lower(http.request.body.multipart.content_types[*]) contains "application/x-php")
```

## 8.8 `http.request.body.mime`

### Definition

`http.request.body.mime` is the MIME type of the request detected from the request body.

### Rule-generation use

Use for body parsing and content-type scoping.

Example:

```text
http.request.body.mime eq "application/json"
```

## 8.9 `http.request.body.size`

### Definition

`http.request.body.size` is the total size of the HTTP request body in bytes.

Availability note:

- Enterprise add-on.

### Rule-generation use

Use for oversized body handling and upload restrictions.

Example:

```text
http.request.body.size gt 1048576
```

Strict API example:

```text
starts_with(http.request.uri.path, "/api/")
and http.request.body.size gt 1048576
```

## 8.10 `http.request.body.truncated`

### Definition

`http.request.body.truncated` indicates whether the HTTP request body is truncated.

Availability note:

- Enterprise add-on.

### Rule-generation use

Use when a rule must handle incomplete body inspection.

Example:

```text
http.request.body.truncated
```

Strict security example:

```text
http.request.body.truncated
and starts_with(http.request.uri.path, "/api/upload")
```

### Best practices

- Treat body truncation as a security signal on high-risk endpoints.
- Use `log`, challenge, or block depending on endpoint sensitivity.
- Explain that truncation can reduce body-inspection reliability.

## 8.11 Body Field Best Practices

- Use body fields only when available for the Cloudflare plan/product.
- Scope body inspection by method and Content-Type.
- Use `http.request.body.truncated` to handle incomplete inspection.
- Use `http.request.body.size` for oversized request detection.
- Use form/multipart maps instead of raw body when structure is available.
- Start with validation before broad body blocking on production traffic.

---

# 9. IP and Geolocation Fields

## 9.1 `ip.src`

### Definition

`ip.src` is the client TCP IP address. It may be adjusted to reflect the actual client address using HTTP headers such as `X-Forwarded-For` or `X-Real-IP`, depending on Cloudflare behavior and configuration.

### Rule-generation use

Use `ip.src` for:

- allowlists
- blocklists
- skip exceptions
- trusted scanners
- office networks
- known attacker IPs
- source-specific challenge or block rules

Examples:

```text
ip.src in {203.0.113.10 203.0.113.11}
```

```text
not ip.src in $trusted_security_scanners
```

CIDR example:

```text
ip.src in {192.0.2.0/24 2001:db8::/32}
```

### Important syntax rule

Use `in` for CIDR ranges.

Correct:

```text
ip.src in {192.0.2.0/24}
```

Incorrect:

```text
ip.src eq 192.0.2.0/24
```

## 9.2 `ip.src.country`

### Definition

`ip.src.country` is the two-letter country code in ISO 3166-1 Alpha 2 format.

### Use cases

Use country scoping for policy-based controls, not as a primary SQLi/XSS detector.

Example:

```text
ip.src.country in {"CN" "RU"}
```

## 9.3 `ip.src.asnum`

### Definition

`ip.src.asnum` is the autonomous system number associated with the client IP address.

### Use cases

Use ASN scoping for known networks, hosting providers, scanner networks, or business policy.

Example:

```text
ip.src.asnum in {12345 64512}
```

## 9.4 Additional Geolocation Fields

| Field | Use |
|---|---|
| `ip.src.city` | City-based policy; rarely primary WAF attack detection. |
| `ip.src.continent` | Continent-level policy scoping. |
| `ip.src.region` | Region name scoping. |
| `ip.src.region_code` | Region code scoping. |
| `ip.src.postal_code` | Postal code scoping; rarely used for WAF attack defense. |
| `ip.src.lat` | Latitude; rarely used in WAF rule generation. |
| `ip.src.lon` | Longitude; rarely used in WAF rule generation. |
| `ip.src.metro_code` | Metro/DMA policy scoping; rarely used for WAF attack defense. |
| `ip.src.timezone.name` | Timezone policy scoping; rarely primary for WAF attack defense. |
| `ip.src.is_in_european_union` | EU-origin scoping; Business or above. |

## 9.5 IP and Geolocation Best Practices

- Use IP and named lists for trusted exceptions.
- Use `not ip.src in $trusted_list` inside block expressions or use a separate skip rule.
- Do not block large geographies for SQLi/XSS unless the user explicitly asks.
- Combine geolocation with attack indicators, threat score, or bot score for higher confidence.

---

# 10. Bot, Threat, and Security Score Fields

## 10.1 `cf.client.bot`

### Definition

`cf.client.bot` indicates whether the request originated from a known good bot or crawler.

### Rule-generation use

Use to avoid challenging or blocking verified good bots.

Example:

```text
not cf.client.bot
```

Bot-aware challenge:

```text
http.request.uri.path eq "/login"
and cf.threat_score gt 20
and not cf.client.bot
```

## 10.2 `cf.threat_score`

### Definition

`cf.threat_score` represents a Cloudflare threat score.

### Rule-generation use

Use as a supporting signal for challenge or stricter policy.

Examples:

```text
cf.threat_score gt 20
```

```text
starts_with(http.request.uri.path, "/login")
and cf.threat_score gt 20
```

### Best practices

- Use threat score as a supporting condition, not the only signal for SQLi/XSS blocking.
- Prefer challenge actions for suspicious traffic based on score.
- Combine with endpoint scope or attack indicators.

## 10.3 Bot Management Fields

Many Bot Management fields require Enterprise add-on access.

| Field | Meaning | Use in rule generation |
|---|---|---|
| `cf.bot_management.score` | Bot likelihood score from 1 to 99. | Challenge or block low-score traffic on sensitive endpoints. |
| `cf.bot_management.verified_bot` | Known good bot or crawler. | Exclude verified bots from challenges or blocks. |
| `cf.bot_management.static_resource` | Indicates static resources in bot-score rules. | Avoid applying bot rules to static assets. |
| `cf.bot_management.js_detection.passed` | Whether the visitor passed JS Detection. | Challenge or block clients that fail JS posture checks. |
| `cf.bot_management.ja3_hash` | TLS JA3 fingerprint. | Bot fingerprint-based rules. |
| `cf.bot_management.ja4` | TLS JA4 fingerprint. | Bot fingerprint-based rules. |
| `cf.bot_management.detection_ids` | IDs for Bot Management heuristic detections. | Advanced bot detection logic. |
| `cf.bot_management.corporate_proxy` | Identified corporate proxy or secure web gateway. | Reduce friction or create exceptions for corporate proxy traffic. |

Example bot score rule:

```text
starts_with(http.request.uri.path, "/login")
and cf.bot_management.score lt 30
and not cf.bot_management.verified_bot
```

## 10.4 WAF Score Fields

WAF score fields represent Cloudflare attack-score signals. Availability depends on plan.

| Field | Meaning | Availability note |
|---|---|---|
| `cf.waf.score` | Global WAF attack score from 1 to 99. | Enterprise. |
| `cf.waf.score.class` | Attack score class based on WAF attack score. | Business or above. |
| `cf.waf.score.xss` | Attack score for cross-site scripting. | Enterprise. |
| `cf.waf.score.sqli` | Attack score for SQL injection. | Enterprise. |
| `cf.waf.score.rce` | Attack score for command injection or RCE. | Enterprise. |

### WAF score rule examples

XSS score:

```text
cf.waf.score.xss lt 30
```

SQLi score:

```text
cf.waf.score.sqli lt 30
```

Aggregate WAF score:

```text
cf.waf.score lt 30
```

### Best practices

- Use WAF score fields when available to supplement explicit payload patterns.
- Use lower scores as higher risk when Cloudflare's scoring model treats lower numbers as more suspicious.
- Combine WAF scores with endpoint scoping or request field evidence.
- Mention plan availability when generating rules using these fields.

---

# 11. API Shield and API Gateway Fields

## 11.1 API Shield Use in WAF Rule Generation

API Shield and API Gateway fields are useful for API-specific defenses, schema validation, and endpoint management. These fields are not generic SQLi/XSS payload fields, but they can scope or strengthen API rules.

## 11.2 API Gateway Fields

| Field | Meaning | Use |
|---|---|---|
| `cf.api_gateway.auth_id_present` | Indicates whether the request contained an API session authentication token defined by saved session identifiers. | Enforce auth-token presence on API endpoints. Enterprise add-on. |
| `cf.api_gateway.fallthrough_detected` | Indicates whether the request matched a saved endpoint in Endpoint Management. | Detect requests to unknown or unmanaged API endpoints. |
| `cf.api_gateway.request_violates_schema` | Indicates whether the request violated the schema assigned to the saved endpoint. | Block or challenge schema-violating API requests. |

## 11.3 API Shield Rule Examples

Block schema violations:

```text
cf.api_gateway.request_violates_schema
```

Block requests to unknown API endpoints:

```text
cf.api_gateway.fallthrough_detected
```

Require API session token on API routes:

```text
starts_with(http.request.uri.path, "/api/")
and not cf.api_gateway.auth_id_present
```

## 11.4 API Shield Best Practices

- Use API fields for API-specific enforcement, not as generic XSS/SQLi signatures.
- Combine with path scoping such as `/api/`.
- Start with logging or challenge when production behavior is unknown.
- For SQLi/XSS payloads in APIs, combine API Shield fields with query/body/header attack indicators.

---

# 12. JWT Fields

## 12.1 JWT Field Overview

JWT fields are available with an Enterprise add-on. They allow rule expressions to inspect JWT claims.

JWT fields are useful for:

- API access scoping
- tenant or audience restrictions
- issuer validation
- subject-based policy
- time-based claim checks
- blocking malformed or unexpected JWT traffic

## 12.2 Common JWT Claim Fields

| Field | Meaning |
|---|---|
| `http.request.jwt.claims.aud` | Audience claim. |
| `http.request.jwt.claims.aud.names` | Names associated with audience claim map/array structure. |
| `http.request.jwt.claims.aud.values` | Audience claim values. |
| `http.request.jwt.claims.iss` | Issuer claim. |
| `http.request.jwt.claims.iss.names` | Issuer claim names. |
| `http.request.jwt.claims.iss.values` | Issuer claim values. |
| `http.request.jwt.claims.sub` | Subject claim. |
| `http.request.jwt.claims.sub.names` | Subject claim names. |
| `http.request.jwt.claims.sub.values` | Subject claim values. |
| `http.request.jwt.claims.jti` | JWT ID claim. |
| `http.request.jwt.claims.iat.sec` | Issued-at time in seconds. |
| `http.request.jwt.claims.nbf.sec` | Not-before time in seconds. |

## 12.3 JWT Expression Examples

Audience match:

```text
any(http.request.jwt.claims.aud.values[*] == "api.example.com")
```

Issuer match:

```text
any(http.request.jwt.claims.iss.values[*] == "https://issuer.example.com/")
```

Subject scope:

```text
any(http.request.jwt.claims.sub.values[*] == "admin-service")
```

## 12.4 JWT Best Practices

- Use JWT fields for API scoping and authorization-adjacent routing rules.
- Do not use JWT fields as direct SQLi/XSS attack detectors.
- Combine JWT conditions with path and method scoping.
- Mention Enterprise add-on requirement.

---

# 13. TLS, mTLS, and Certificate Fields

## 13.1 `ssl`

### Definition

`ssl` returns `true` when the HTTP connection from client to Cloudflare is encrypted.

Example:

```text
ssl
```

Negated:

```text
not ssl
```

### Rule-generation use

Use to enforce HTTPS or scope rules by encrypted traffic.

## 13.2 TLS Version and Cipher Fields

| Field | Meaning |
|---|---|
| `cf.tls_version` | TLS version used for connection to Cloudflare. |
| `cf.tls_cipher` | TLS cipher used for connection to Cloudflare. |
| `cf.tls_client_hello_length` | Length of the TLS ClientHello message. |
| `cf.tls_client_random` | Client random value encoded in Base64. |
| `cf.tls_ciphers_sha1` | SHA-1 fingerprint of the client TLS cipher list. |
| `cf.tls_client_extensions_sha1` | SHA-1 fingerprint of TLS client extensions. |
| `cf.tls_client_extensions_sha1_le` | SHA-1 fingerprint of TLS client extensions in little-endian format. |

Use TLS fields for:

- TLS policy enforcement
- bot fingerprinting
- client posture
- advanced traffic classification

## 13.3 mTLS Certificate Fields

| Field | Meaning |
|---|---|
| `cf.tls_client_auth.cert_presented` | Request presented a client certificate. |
| `cf.tls_client_auth.cert_verified` | Request presented a valid client certificate. |
| `cf.tls_client_auth.cert_revoked` | Presented certificate is valid but revoked. |
| `cf.tls_client_auth.cert_fingerprint_sha1` | SHA-1 fingerprint of client certificate. |
| `cf.tls_client_auth.cert_fingerprint_sha256` | SHA-256 fingerprint of client certificate. |
| `cf.tls_client_auth.cert_issuer_dn` | Issuer Distinguished Name. |
| `cf.tls_client_auth.cert_subject_dn` | Subject Distinguished Name. |
| `cf.tls_client_auth.cert_serial` | Certificate serial number. |
| `cf.tls_client_auth.cert_not_before` | Certificate not valid before this date. |
| `cf.tls_client_auth.cert_not_after` | Certificate not valid after this date. |

## 13.4 mTLS Rule Examples

Require verified client certificate for admin API:

```text
starts_with(http.request.uri.path, "/admin/api/")
and not cf.tls_client_auth.cert_verified
```

Block revoked certificate:

```text
cf.tls_client_auth.cert_revoked
```

Allow specific certificate fingerprint:

```text
cf.tls_client_auth.cert_fingerprint_sha256 in {"<CERT_SHA256_FINGERPRINT>"}
```

## 13.5 TLS/mTLS Best Practices

- Use mTLS fields for trusted client access and strict API protection.
- Use certificate verification for high-trust exceptions instead of spoofable headers.
- Combine mTLS with path and method scoping.
- Do not use TLS fields as primary SQLi/XSS payload indicators.

---

# 14. WAF Credential and Content Scanning Fields

## 14.1 Credential Check Fields

Credential check fields indicate whether credentials detected in a request were previously leaked or similar to leaked credentials.

| Field | Meaning | Availability |
|---|---|---|
| `cf.waf.credential_check.username_and_password_leaked` | Username-password pair was previously leaked. | Pro or above. |
| `cf.waf.credential_check.password_leaked` | Password was previously leaked. | Plan-dependent. |
| `cf.waf.credential_check.username_leaked` | Username was previously leaked. | Enterprise. |
| `cf.waf.credential_check.username_password_similar` | Similar username/password credentials were previously leaked. | Enterprise. |

Example:

```text
cf.waf.credential_check.username_and_password_leaked
```

Use for:

- login protection
- credential stuffing defense
- compromised credential detection

## 14.2 Content Scan Fields

Content scan fields indicate whether uploaded/request content contains objects and whether scanning found malicious objects.

These fields often require Enterprise add-on access.

| Field | Meaning |
|---|---|
| `cf.waf.content_scan.has_obj` | Request contains at least one content object. |
| `cf.waf.content_scan.has_malicious_obj` | Request contains at least one malicious content object. |
| `cf.waf.content_scan.has_failed` | File scanner was unable to scan detected content. |
| `cf.waf.content_scan.num_obj` | Number of content objects detected. |
| `cf.waf.content_scan.num_malicious_obj` | Number of malicious content objects detected. |
| `cf.waf.content_scan.obj_results` | Array of scan results in detection order. |
| `cf.waf.content_scan.obj_sizes` | Array of file sizes. |
| `cf.waf.content_scan.obj_types` | Array of file types. |

Example:

```text
cf.waf.content_scan.has_malicious_obj
```

Strict upload rule:

```text
starts_with(http.request.uri.path, "/upload")
and cf.waf.content_scan.has_malicious_obj
```

Scanner failure rule:

```text
starts_with(http.request.uri.path, "/upload")
and cf.waf.content_scan.has_failed
```

## 14.3 Best Practices

- Use content scanning fields for upload defenses, not general SQLi/XSS query detection.
- Block malicious objects on upload paths.
- Treat scan failure according to risk tolerance.
- Include plan/add-on requirements in generated rules.

---

# 15. LLM Prompt Security Fields

## 15.1 LLM Prompt Fields

Cloudflare includes fields for LLM prompt security in supported Enterprise contexts.

| Field | Meaning |
|---|---|
| `cf.llm.prompt.detected` | Cloudflare detected an LLM prompt in the incoming request. |
| `cf.llm.prompt.injection_score` | Score from 1 to 99 indicating likelihood of prompt injection. |
| `cf.llm.prompt.pii_detected` | PII detected in the LLM prompt. |
| `cf.llm.prompt.pii_categories` | PII categories found in the prompt. |
| `cf.llm.prompt.unsafe_topic_detected` | Unsafe topic category detected. |
| `cf.llm.prompt.unsafe_topic_categories` | Unsafe topic categories found in the prompt. |

## 15.2 Rule Examples

Prompt injection score:

```text
cf.llm.prompt.injection_score gt 80
```

PII detected:

```text
cf.llm.prompt.pii_detected
```

Unsafe topic detected:

```text
cf.llm.prompt.unsafe_topic_detected
```

## 15.3 Best Practices

- Use these fields only for LLM application endpoints.
- Scope to LLM API routes such as `/api/chat`, `/v1/completions`, or `/llm/`.
- Do not use LLM fields for generic SQLi/XSS WAF rules.
- Include Enterprise availability note.

---

# 16. Response Fields

## 16.1 Response Field Scope

Response fields are useful in response-phase rules. They should not be used in ordinary request firewall custom rules unless the target phase supports response evaluation.

## 16.2 Common Response Fields

| Field | Meaning |
|---|---|
| `http.response.code` | HTTP status code returned to client. |
| `http.response.content_type.media_type` | Lowercased response content type without extra parameters. |
| `http.response.headers` | Response headers as a map. |
| `http.response.headers.names` | Names of response headers. |
| `http.response.headers.values` | Values of response headers. |
| `raw.http.response.headers` | Raw response headers. |
| `raw.http.response.headers.names` | Raw response header names. |
| `raw.http.response.headers.values` | Raw response header values. |
| `cf.response.error_type` | Type of error in the response. |
| `cf.response.1xxx_code` | Specific Cloudflare 1XXX error code. |

## 16.3 Response Field Examples

Match 5xx responses:

```text
http.response.code ge 500
```

Match HTML response:

```text
http.response.content_type.media_type eq "text/html"
```

Detect response header:

```text
any(http.response.headers.names[*] == "set-cookie")
```

## 16.4 Best Practices

- Use response fields only in response-capable phases and products.
- Do not generate response fields for request WAF custom rules.
- Mention phase constraint when a response field appears.

---

# 17. Miscellaneous Cloudflare Fields

## 17.1 `cf.ray_id`

### Definition

`cf.ray_id` is the Ray ID of the current request.

### Rule-generation use

Mostly useful for logging, tracing, and debugging. It is rarely used for attack blocking.

## 17.2 `cf.random_seed`

### Definition

`cf.random_seed` returns per-request random bytes usable with `uuidv4()`.

### Rule-generation use

Use only in rewrite expressions where `uuidv4()` is supported. Do not use for WAF attack detection.

## 17.3 Timing Fields

| Field | Meaning |
|---|---|
| `cf.timings.client_tcp_rtt_msec` | Smoothed TCP round-trip time from client to Cloudflare. |
| `cf.timings.edge_msec` | Time spent processing request inside Cloudflare global network. |
| `cf.timings.origin_ttfb_msec` | Round-trip time between Cloudflare and origin server. |

Use these fields for performance or advanced traffic policies, not primary SQLi/XSS detection.

## 17.4 Worker Field

| Field | Meaning |
|---|---|
| `cf.worker.upstream_zone` | Identifies whether a request comes from a Worker. |

Use for Worker-related routing or trust decisions, not direct payload detection.

---

# 18. Field Decision Matrix for Attack Rule Generation

## 18.1 XSS Field Selection

| Evidence | Recommended field |
|---|---|
| XSS in unknown query parameter | `http.request.uri.query` |
| Encoded XSS in query string | `raw.http.request.uri.query` |
| XSS in known query parameter | `http.request.uri.args["param"][*]` |
| XSS in URI path | `http.request.uri.path` and `raw.http.request.uri.path` |
| XSS in form field | `http.request.body.form.values[*]` |
| XSS in raw body | `http.request.body.raw` |
| XSS in header | `http.request.headers["header-name"][*]` |
| XSS in cookie | `http.cookie` or `http.request.cookies["name"][*]` |
| High false positives | Add `http.request.uri.path`, `http.host`, `http.request.method`, or `ip.src` scoping |

## 18.2 SQL Injection Field Selection

| Evidence | Recommended field |
|---|---|
| SQLi in unknown query parameter | `http.request.uri.query` |
| Encoded SQLi in query string | `raw.http.request.uri.query` |
| SQLi in known query parameter | `http.request.uri.args["id"][*]` or relevant parameter |
| SQLi in form value | `http.request.body.form.values[*]` |
| SQLi in raw body | `http.request.body.raw` |
| SQLi in API body | body fields if available, plus method/path scoping |
| SQLi in cookie | `http.cookie` or `http.request.cookies["name"][*]` |
| SQLi in header | `http.request.headers["header-name"][*]` |
| High false positives | Add path, host, method, parameter, or trusted IP scoping |

## 18.3 Bot and Scanner Field Selection

| Evidence | Recommended field |
|---|---|
| Known scanner User-Agent | `http.user_agent` or `http.request.headers["user-agent"][*]` |
| Known scanner IP | `ip.src` or named IP list |
| Verified bot exclusion | `cf.client.bot` or `cf.bot_management.verified_bot` |
| Suspicious bot score | `cf.bot_management.score` |
| Suspicious threat score | `cf.threat_score` |
| Bot TLS fingerprint | `cf.bot_management.ja3_hash` or `cf.bot_management.ja4` |

## 18.4 API Field Selection

| Evidence | Recommended field |
|---|---|
| Unknown API endpoint | `cf.api_gateway.fallthrough_detected` |
| Schema violation | `cf.api_gateway.request_violates_schema` |
| Missing API session token | `cf.api_gateway.auth_id_present` |
| API path scope | `http.request.uri.path` |
| JSON body or form payload | `http.request.body.*` if available |
| JWT claim scope | `http.request.jwt.claims.*` if available |

---

# 19. Complete Expression Examples Using Field References

## 19.1 Query-Based XSS with Encoded Payload Coverage

```text
(
  lower(http.request.uri.query) matches r"(<script|onerror\s*=|onload\s*=|javascript:|<svg|<img)"
  or lower(raw.http.request.uri.query) contains "%3cscript"
  or lower(raw.http.request.uri.query) contains "%3csvg"
  or lower(raw.http.request.uri.query) contains "javascript%3a"
)
and not ip.src in $trusted_security_scanners
```

## 19.2 Parameter-Specific XSS

```text
any(lower(http.request.uri.args["q"][*]) matches r"(<script|onerror\s*=|onload\s*=|javascript:)")
```

## 19.3 Query-Based SQL Injection with Encoded Payload Coverage

```text
(
  lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema)"
  or lower(raw.http.request.uri.query) contains "union%20select"
  or lower(raw.http.request.uri.query) contains "%27"
)
and not ip.src in $trusted_security_scanners
```

## 19.4 Parameter-Specific SQL Injection

```text
any(lower(http.request.uri.args["id"][*]) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()")
```

## 19.5 Header-Based Scanner Detection

```text
any(lower(http.request.headers["user-agent"][*]) contains "sqlmap")
or any(lower(http.request.headers["user-agent"][*]) contains "nikto")
or any(lower(http.request.headers["user-agent"][*]) contains "acunetix")
```

## 19.6 Body-Based XSS for Form Submissions

```text
http.request.method eq "POST"
and any(lower(http.request.headers["content-type"][*]) contains "application/x-www-form-urlencoded")
and (
  any(lower(http.request.body.form.values[*]) contains "<script")
  or any(lower(http.request.body.form.values[*]) contains "onerror=")
  or any(lower(http.request.body.form.values[*]) contains "javascript:")
)
```

## 19.7 Body Truncation Protection for API Uploads

```text
starts_with(http.request.uri.path, "/api/upload")
and http.request.body.truncated
```

## 19.8 API Schema Violation Rule

```text
starts_with(http.request.uri.path, "/api/")
and cf.api_gateway.request_violates_schema
```

## 19.9 WAF Score Assisted XSS Rule

```text
starts_with(http.request.uri.path, "/search")
and cf.waf.score.xss lt 30
```

## 19.10 Bot-Aware Login Challenge Scope

```text
http.request.uri.path eq "/login"
and cf.threat_score gt 20
and not cf.client.bot
```

---

# 20. Field-Specific False Positive Tuning

## 20.1 High-Risk Fields for False Positives

| Field | False-positive risk |
|---|---|
| `http.request.uri.query` | Broad query scanning may catch benign search syntax or encoded data. |
| `http.request.uri.args.values` | Broad value scanning may catch benign payload-like values. |
| `http.request.body.raw` | Raw body may contain legitimate HTML, JSON, code, SQL-like strings, or templates. |
| `http.request.body.form.values` | Form submissions may include rich text, Markdown, HTML, or code. |
| `http.cookie` | Cookies may be encoded, compressed, or application-defined. |
| `http.request.headers.values` | Broad header scanning may catch benign metadata or third-party headers. |
| `http.user_agent` | User-Agent is spoofable and not a strong attack signal alone. |
| `ip.src.country` | Country blocking is policy-based and can block legitimate users. |

## 20.2 Tuning Techniques

| Tuning technique | Field pattern |
|---|---|
| Scope by path | `starts_with(http.request.uri.path, "/search")` |
| Scope by host | `http.host eq "app.example.com"` |
| Scope by method | `http.request.method eq "POST"` |
| Scope by parameter | `http.request.uri.args["q"][*]` |
| Exclude trusted IPs | `not ip.src in $trusted_security_scanners` |
| Exclude verified bots | `not cf.client.bot` |
| Use raw fields only for encoded evidence | `raw.http.request.uri.query` |
| Use body fields only on body endpoints | `http.request.method in {"POST" "PUT" "PATCH"}` |
| Check truncation | `http.request.body.truncated` or `http.request.headers.truncated` |

---

# 21. Common Field Selection Mistakes and Corrections

## 21.1 Mistake: Using Full Query When Parameter Is Known

Risky:

```text
lower(http.request.uri.query) contains "<script"
```

Better:

```text
any(lower(http.request.uri.args["q"][*]) contains "<script")
```

Use the better pattern when the vulnerable parameter is known.

## 21.2 Mistake: Using Normalized Field for Encoded Payload Only

Incomplete:

```text
lower(http.request.uri.query) contains "<script"
```

Better:

```text
lower(http.request.uri.query) contains "<script"
or lower(raw.http.request.uri.query) contains "%3cscript"
```

Use the better pattern when encoded payload evidence exists.

## 21.3 Mistake: Header Wildcard Without `any()`

Incorrect:

```text
http.request.headers["user-agent"][*] contains "sqlmap"
```

Correct:

```text
any(lower(http.request.headers["user-agent"][*]) contains "sqlmap")
```

## 21.4 Mistake: CIDR with Equality

Incorrect:

```text
ip.src eq 192.0.2.0/24
```

Correct:

```text
ip.src in {192.0.2.0/24}
```

## 21.5 Mistake: Body Fields Without Availability Warning

Incomplete:

```text
lower(http.request.body.raw) contains "<script"
```

Better generation output:

```text
lower(http.request.body.raw) contains "<script"
```

And include:

> **Warning:** `http.request.body.raw` requires supported request-body inspection. Verify plan/product availability before deployment.

## 21.6 Mistake: Response Field in Request Firewall Custom Rule

Incorrect for request WAF custom rule:

```text
http.response.code ge 500
```

Correct guidance:

- Use response fields only in response-capable phases.
- Use request fields such as `http.request.uri.path`, `http.request.uri.query`, `http.request.headers`, or `ip.src` for request WAF custom rules.

---

# 22. Final Rule-Generation Template Using Cloudflare Fields

Use this template when generating a Cloudflare WAF rule based on field references.

```markdown
## Rule Objective

Describe:
- attack type
- payload location
- Cloudflare field selected
- target action

## Selected Cloudflare Fields

List:
- primary field
- supporting fields
- raw fields if encoded payloads exist
- plan-restricted fields if used

## Proposed Expression

Provide the Cloudflare expression.

## Proposed Rule JSON

Provide JSON with:
- description
- expression
- action
- enabled

## Field Rationale

Explain:
- why each field was selected
- what request component each field inspects
- why raw or map fields are needed
- whether body/JWT/API/Bot/WAF score fields require a plan or add-on

## False Positive and Tuning Notes

Mention:
- broad fields that may overmatch
- path/host/method/parameter scoping
- trusted IP or verified bot exceptions
- whether to split into multiple rules
```

---

# 23. Final Checklist for Cloudflare Field Selection

- [ ] The field matches the observed payload location.
- [ ] Query attacks use `http.request.uri.query` or `http.request.uri.args`.
- [ ] Encoded attacks use `raw.http.request.uri.query` or other raw fields when needed.
- [ ] Known parameters use map fields and `any()`.
- [ ] Headers use lowercase header names and `any()`.
- [ ] Cookies use `http.cookie` or `http.request.cookies` depending on required specificity.
- [ ] Body rules mention plan/add-on availability.
- [ ] Body rules account for `http.request.body.truncated`.
- [ ] IP exceptions use `ip.src in {}` or named lists.
- [ ] CIDR ranges use `in`, not `eq`.
- [ ] Bot and threat fields are supporting signals, not generic SQLi/XSS signatures.
- [ ] WAF score fields include plan availability notes.
- [ ] API Shield fields are scoped to API routes.
- [ ] JWT fields are used only for API/access context.
- [ ] TLS/mTLS fields are used for client identity or posture, not payload detection.
- [ ] Response fields are not used in request firewall custom rules.
- [ ] False-positive-prone fields are scoped by path, host, method, parameter, IP, or trusted list.
