# Cloudflare Rules Language Fields Overview for WAF Rule Generation
# 1. Cloudflare Rules Language Field Model
## 1.1 Definition

A Cloudflare Rules language field represents a value associated with an HTTP request, HTTP response, Cloudflare-computed signal, or original raw request/response value.

Cloudflare WAF custom rules use fields inside expressions. A rule expression evaluates to either `true` or `false`. If the expression evaluates to `true`, the rule action runs.

General expression form:

```text
<field> <comparison_operator> <value>
```

Example:

```text
lower(http.request.uri.query) contains "<script"
```

Compound expression form:

```text
<expression> <logical_operator> <expression>
```

Example:

```text
starts_with(http.request.uri.path, "/search")
and lower(http.request.uri.query) contains "<script"
```

## 1.2 Field Categories

Cloudflare Rules language fields are grouped into four high-level categories:

| Field category | Meaning | Rule-generation use |
|---|---|---|
| Request fields | Basic properties of incoming HTTP requests. They include request headers, URI components, request body fields, cookies, host, method, IP, and related request data. | Primary category for WAF custom rules that inspect XSS, SQLi, path traversal, scanner traffic, API traffic, and request-based abuse. |
| Dynamic fields | Computed or derived fields, commonly related to threat intelligence or Cloudflare security analysis for the request. | Useful for bot-aware rules, threat-score conditions, WAF-score rules, API Shield signals, and challenge decisions. |
| Response fields | Basic properties of the received response. | Use only in response-capable phases or response rules. Do not use response fields in ordinary request WAF custom rules unless the target phase supports them. |
| Raw fields | Original request or response values preserved for later evaluations. | Useful for encoded payloads, original URI matching, and cases where prior phase transformations should not affect rule logic. |

## 1.3 Field Selection Principle

For WAF rule generation, choose the field that most closely matches the observed payload location:

1. Use URI query fields when payloads appear in URL query parameters.
2. Use URI argument map fields when the vulnerable parameter name is known.
3. Use URI path fields when payloads or exploit probes appear in the path.
4. Use header fields when payloads appear in a request header.
5. Use cookie fields when payloads appear in cookies.
6. Use body fields only when request-body inspection is available and the payload is in the body.
7. Use IP fields for allowlists, blocklists, and trusted-source exceptions.
8. Use dynamic fields as supporting evidence, not as generic SQLi or XSS signatures.
9. Use raw fields when original encoded values matter.

---

# 2. Request Fields for WAF Custom Rules

## 2.1 Definition

Request fields represent properties of incoming HTTP requests. They are the primary field category for Cloudflare WAF custom rules.

Request fields can represent:

- hostnames
- URI paths
- URI query strings
- URI arguments
- request methods
- request headers
- cookies
- request body content
- source IP address
- geolocation properties
- user agent strings
- protocol and TLS-related request properties

## 2.2 Request Fields Commonly Used for Rule Generation

| Field | Use in WAF rule generation |
|---|---|
| `http.host` | Scope a rule to a hostname such as `www.example.com` or `api.example.com`. |
| `http.request.uri` | Match the request URI path and query string together. |
| `http.request.uri.path` | Scope rules to paths such as `/login`, `/admin`, `/api/`, `/search`, or `/upload`. |
| `http.request.uri.query` | Match XSS, SQLi, redirect payloads, or scanner probes in the full query string. |
| `http.request.uri.args` | Match query parameters as a map from argument name to values. |
| `http.request.uri.args.names` | Match query parameter names. |
| `http.request.uri.args.values` | Match all query parameter values. |
| `http.request.method` | Scope rules to `GET`, `POST`, `PUT`, `PATCH`, or `DELETE`. |
| `http.user_agent` | Detect scanners, scripts, curl, sqlmap, Nikto, or other client identifiers. |
| `http.referer` | Match or scope by Referer; treat as spoofable. |
| `http.cookie` | Coarse matching over the full Cookie header string. |
| `http.request.cookies` | Structured cookie map, when available. |
| `http.request.headers` | Structured request header map. |
| `http.request.headers.names` | Header name list. |
| `http.request.headers.values` | Header value list. |
| `http.request.body.raw` | Raw body inspection, when available. |
| `http.request.body.form` | Structured form body map, when available. |
| `http.request.body.form.values` | Values of form fields, when available. |
| `http.request.body.multipart.*` | Multipart body fields, filenames, content types, and values, when available. |
| `http.request.body.size` | Request body size, useful for upload or oversized request policies. |
| `http.request.body.truncated` | Whether the request body was truncated during inspection. |
| `ip.src` | Source IP address for allowlists, blocklists, trusted scanners, or source-based policy. |
| `ip.src.country` | Country-based scoping. |
| `ip.src.asnum` | ASN-based scoping. |
| `ssl` | Boolean indicating whether the client-to-Cloudflare connection is encrypted. |

## 2.3 Request Field Rule-Generation Guidance

Use request fields as the default category for Cloudflare WAF custom rule generation.

Recommended field choices:

| Observed evidence | Recommended field |
|---|---|
| XSS or SQLi in unknown query parameter | `http.request.uri.query` |
| XSS or SQLi in known query parameter | `http.request.uri.args["param"][*]` |
| Encoded XSS or SQLi in query string | `raw.http.request.uri.query` |
| Payload in URI path | `http.request.uri.path` and optionally `raw.http.request.uri.path` |
| Payload in User-Agent | `http.user_agent` or `http.request.headers["user-agent"][*]` |
| Payload in custom header | `http.request.headers["header-name"][*]` |
| Payload in cookie | `http.cookie` or `http.request.cookies["cookie-name"][*]` |
| Payload in POST form field | `http.request.body.form.values[*]` |
| Payload in raw body | `http.request.body.raw` |
| API route scoping | `http.request.uri.path` plus `http.request.method` |
| Trusted scanner exception | `ip.src in $trusted_security_scanners` |
| Verified HTTPS-only policy | `ssl` or `not ssl` |

## 2.4 Example: Request Field for Query-Based XSS

```text
lower(http.request.uri.query) contains "<script"
or lower(http.request.uri.query) contains "onerror="
or lower(http.request.uri.query) contains "javascript:"
```

Use this when the XSS payload appears somewhere in the query string and the vulnerable parameter is unknown.

## 2.5 Example: Request Field for Parameter-Specific XSS

```text
any(lower(http.request.uri.args["q"][*]) contains "<script")
or any(lower(http.request.uri.args["q"][*]) contains "onerror=")
or any(lower(http.request.uri.args["q"][*]) contains "javascript:")
```

Use this when the vulnerable parameter is known, such as `q`, `search`, `comment`, or `redirect`.

## 2.6 Example: Request Field for Query-Based SQL Injection

```text
lower(http.request.uri.query) contains "union select"
or lower(http.request.uri.query) contains "or 1=1"
or lower(http.request.uri.query) contains "sleep("
or lower(http.request.uri.query) contains "benchmark("
```

Use this when SQLi indicators are present in query parameters and a broad query inspection is acceptable.

## 2.7 Example: Request Field for Parameter-Specific SQL Injection

```text
any(lower(http.request.uri.args["id"][*]) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()")
```

Use this when SQLi is known to appear in a parameter such as `id`, `product`, `search`, or `q`.

---

# 3. Dynamic Fields for Threat Intelligence and Security Signals

## 3.1 Definition

Dynamic fields represent computed or derived values. These values are commonly related to threat intelligence, bot analysis, WAF scoring, API Shield, or product-specific Cloudflare security evaluation.

Dynamic fields are not usually raw request components. They are Cloudflare-generated signals.

## 3.2 Dynamic Fields Useful for WAF Rule Generation

| Field | Meaning | Rule-generation use |
|---|---|---|
| `cf.threat_score` | Cloudflare threat score. | Challenge or increase enforcement for suspicious traffic. |
| `cf.client.bot` | Known good bot or crawler indicator. | Avoid challenging or blocking verified good bots. |
| `cf.bot_management.score` | Bot likelihood score from 1 to 99. | Challenge low-score traffic on sensitive endpoints. |
| `cf.bot_management.verified_bot` | Known good bot/crawler signal. | Exclude verified bots from bot rules. |
| `cf.waf.score` | Global WAF attack score. | Supplement explicit WAF expressions when available. |
| `cf.waf.score.xss` | XSS attack score. | Use for XSS-focused scoring rules when available. |
| `cf.waf.score.sqli` | SQL injection attack score. | Use for SQLi-focused scoring rules when available. |
| `cf.waf.score.rce` | RCE or command injection attack score. | Use for RCE-focused scoring rules when available. |
| `cf.api_gateway.request_violates_schema` | API request violated an assigned schema. | Block or challenge schema-violating API traffic. |
| `cf.api_gateway.fallthrough_detected` | Request did not match a saved API endpoint. | Detect unmanaged API endpoint access. |
| `cf.api_gateway.auth_id_present` | Request contained an API session authentication token. | Enforce API session-token presence. |
| `cf.waf.credential_check.username_and_password_leaked` | Credentials detected in request were previously leaked. | Protect login endpoints. |
| `cf.waf.content_scan.has_malicious_obj` | Request contains malicious uploaded content. | Block malicious upload objects. |
| `cf.llm.prompt.injection_score` | Prompt injection score for LLM traffic. | Protect LLM API endpoints when available. |

## 3.3 Dynamic Field Rule-Generation Guidance

Use dynamic fields as supporting or specialized signals.

Do:

- Use `cf.threat_score` or Bot Management score for challenge decisions.
- Use `cf.client.bot` or `cf.bot_management.verified_bot` to avoid harming known good bots.
- Use WAF score fields when the user has Cloudflare WAF Attack Score capability.
- Use API Gateway fields for API schema and endpoint enforcement.
- Use content scan fields for upload defenses.
- Use credential check fields for login protections.

Do not:

- Use dynamic fields as the only evidence for SQLi or XSS payload-specific blocking unless the user explicitly wants score-based policy.
- Assume Enterprise or add-on fields are available without saying so.
- Use API, LLM, content-scan, or credential fields for ordinary query-string XSS/SQLi rules unless the endpoint requires them.

## 3.4 Example: Bot-Aware Login Challenge

```text
http.request.uri.path eq "/login"
and cf.threat_score gt 20
and not cf.client.bot
```

Recommended action:

```json
{
  "action": "managed_challenge"
}
```

## 3.5 Example: WAF Score Assisted XSS Rule

```text
starts_with(http.request.uri.path, "/search")
and cf.waf.score.xss lt 30
```

Use only when WAF attack score fields are available.

## 3.6 Example: API Schema Violation Rule

```text
starts_with(http.request.uri.path, "/api/")
and cf.api_gateway.request_violates_schema
```

Use for API Shield / API Gateway scenarios, not generic web-page XSS.

---

# 4. Response Fields

## 4.1 Definition

Response fields represent properties of the received HTTP response.

Response fields can include:

- response status code
- response headers
- response content type
- Cloudflare response error type
- Cloudflare 1XXX error code
- raw response headers

## 4.2 Response Fields Useful in Response-Capable Rules

| Field | Meaning |
|---|---|
| `http.response.code` | HTTP status code returned to the client. |
| `http.response.content_type.media_type` | Lowercased response content type without extra parameters. |
| `http.response.headers` | Response headers as a map. |
| `http.response.headers.names` | Response header names. |
| `http.response.headers.values` | Response header values. |
| `raw.http.response.headers` | Raw response headers as a map. |
| `raw.http.response.headers.names` | Raw response header names. |
| `raw.http.response.headers.values` | Raw response header values. |
| `cf.response.error_type` | Cloudflare response error type. |
| `cf.response.1xxx_code` | Specific Cloudflare 1XXX error code. |

## 4.3 Response Field Rule-Generation Guidance

Response fields are not the primary choice for WAF request blocking.

Use response fields when:

- the target product or phase supports response evaluation
- the user asks for response header modification or response inspection
- the rule operates after the origin response
- the policy depends on response code or content type

Do not use response fields in ordinary request WAF custom rules.

## 4.4 Example: Response Status Condition

```text
http.response.code ge 500
```

This is response-phase logic. It is not appropriate for a request firewall custom rule that blocks XSS or SQLi before the origin receives the request.

## 4.5 Example: Response Content Type Condition

```text
http.response.content_type.media_type eq "text/html"
```

Use only in a response-capable product or phase.

---

# 5. Raw Fields for Original Values and Encoded Payloads

## 5.1 Definition

Raw fields preserve original request or response values for later evaluations. They use the `raw.` prefix.

Raw fields are useful because normal request fields can reflect values at a particular phase, while raw fields can preserve original values during the request evaluation workflow.

## 5.2 Why Raw Fields Matter for WAF Rule Generation

Raw fields are important when:

- encoded payloads must be detected as they arrived
- URI rewrites or transformations may change regular request fields in later phases
- the rule needs original request evidence
- payload encoding is the bypass technique
- the generator needs to match `%3cscript`, `%27`, `%2f`, or similar encoded values directly

## 5.3 Common Raw Fields for WAF Rules

| Raw field | Use |
|---|---|
| `raw.http.request.uri` | Raw URI path and query string. |
| `raw.http.request.uri.path` | Raw URI path. |
| `raw.http.request.uri.query` | Raw query string without the `?` delimiter. |
| `raw.http.request.full_uri` | Raw full URI. |
| `raw.http.request.uri.args` | Raw query arguments as a map. |
| `raw.http.request.uri.args.names` | Raw query argument names. |
| `raw.http.request.uri.args.values` | Raw query argument values. |
| `raw.http.response.headers` | Raw response headers map. |
| `raw.http.response.headers.names` | Raw response header names. |
| `raw.http.response.headers.values` | Raw response header values. |

## 5.4 Raw Field Caveat

Some raw request URI fields may include basic normalization performed by Cloudflare's HTTP server. Treat raw fields as preserving original values for Ruleset Engine evaluation, but do not assume they are a byte-for-byte packet capture.

## 5.5 Example: Encoded XSS Detection

```text
lower(raw.http.request.uri.query) contains "%3cscript"
or lower(raw.http.request.uri.query) contains "%3csvg"
or lower(raw.http.request.uri.query) contains "javascript%3a"
```

## 5.6 Example: Encoded SQLi Detection

```text
lower(raw.http.request.uri.query) contains "union%20select"
or (
  lower(raw.http.request.uri.query) contains "%27"
  and lower(raw.http.request.uri.query) contains "%20or%20"
)
```

## 5.7 Example: Encoded Path Traversal Detection

```text
lower(raw.http.request.uri.path) contains "..%2f"
or lower(raw.http.request.uri.path) contains "%2e%2e%2f"
```

## 5.8 Recommended Combined Pattern

Use both normalized-looking fields and raw fields when encoded payloads are observed.

```text
lower(http.request.uri.query) contains "<script"
or lower(raw.http.request.uri.query) contains "%3cscript"
```

This covers both decoded-looking payloads and encoded payloads.

---

# 6. Differences Between Cloudflare Rules Fields and Wireshark Display Fields

## 6.1 Shared Naming Style

Cloudflare Rules language field naming is similar to Wireshark display filters, but the languages are not identical.

Do not assume that a valid Wireshark display filter is valid Cloudflare Rules language syntax.

## 6.2 CIDR Ranges Must Use `in`

### Constraint

Wireshark supports CIDR notation in equality comparisons such as:

```text
ip.src == 1.2.3.0/24
```

Cloudflare does not support CIDR ranges in equality comparisons.

### Correct Cloudflare syntax

Use `in` with an inline set:

```text
ip.src in {1.2.3.0/24 4.5.6.0/24}
```

### Incorrect Cloudflare syntax

```text
ip.src eq 1.2.3.0/24
```

```text
ip.src == 1.2.3.0/24
```

## 6.3 Rule-Generation Guidance for IP Ranges

When generating rules for IP ranges:

- Use `ip.src in {CIDR}`.
- Use named lists for large or reusable IP sets.
- Use `not ip.src in $trusted_list` to exclude trusted sources.
- Do not generate Wireshark-style CIDR equality.
- Use `in` for IPv4 and IPv6 CIDR ranges.

Example trusted scanner exclusion:

```text
(
  lower(http.request.uri.query) contains "<script"
  or lower(http.request.uri.query) contains "union select"
)
and not ip.src in $trusted_security_scanners
```

## 6.4 `ssl` Is a Boolean Field

### Constraint

In Wireshark, `ssl` is a protocol field with many child fields. In Cloudflare Rules language, `ssl` is a single Boolean field.

Correct Cloudflare usage:

```text
ssl
```

```text
not ssl
```

Incorrect assumption:

```text
ssl.record.version eq "TLS 1.2"
```

Use TLS-specific Cloudflare fields such as `cf.tls_version` when TLS version matching is required.

## 6.5 No `slice` Operator

Cloudflare Rules language does not support the Wireshark `slice` operator.

Do not generate expressions that rely on syntax such as:

```text
field[0:4]
```

Use supported Cloudflare functions, operators, map access, array access, or regex matching instead.

---

# 7. Field Values During Rule Evaluation

## 7.1 Field Evaluation Model

A Cloudflare rule expression compares field values to values defined in the expression. The expression must evaluate to a Boolean value.

If the expression is `true`, the rule action runs. If the expression is `false`, the rule action does not run.

## 7.2 Field Values Within a Phase

Within a given phase, request and response field values are immutable for rule evaluation. If earlier rules in the same phase modify headers or URI values, later rules in that same phase may not see those modifications.

## 7.3 Field Values Between Phases

Field values may change between phases.

Example:

- A URL Rewrite Rule can update the URI path or query string in the `http_request_transform` phase.
- Later phases may see changed `http.request.uri`, `http.request.uri.path`, `http.request.uri.query`, or `http.request.full_uri` values.
- Raw fields such as `raw.http.request.uri.path` can be used when later rules need original values.

## 7.4 Rule-Generation Guidance

When the rule must match the original value sent by the client:

- use raw fields such as `raw.http.request.uri.path`
- use raw fields such as `raw.http.request.uri.query`
- explain that raw fields preserve original values for later evaluations
- combine raw and non-raw fields when both original and current-phase values matter

Example:

```text
lower(raw.http.request.uri.query) contains "%3cscript"
or lower(http.request.uri.query) contains "<script"
```

---

# 8. Fields and Expression Structure

## 8.1 Simple Expression Pattern

Cloudflare simple expressions follow this structure:

```text
<field> <comparison_operator> <value>
```

Example:

```text
http.request.uri.path matches "/autodiscover\\.(xml|src)$"
```

## 8.2 Compound Expression Pattern

Compound expressions combine expressions with logical operators:

```text
<expression> <logical_operator> <expression>
```

Example:

```text
http.host eq "www.example.com"
and not cf.edge.server_port in {80 443}
```

## 8.3 Rule-Generation Guidance

Fields should be embedded in expressions that are:

- Boolean
- syntactically valid
- scoped enough to reduce false positives
- specific to the observed request component
- under the Cloudflare expression length limit
- compatible with the intended phase and product

## 8.4 Expression Length Limit

A Cloudflare rule expression has a maximum length of **4,096 characters**.

When an expression becomes too long:

- split logic into multiple rules
- use named lists
- use regex alternatives with `matches` when available
- use `http.request.uri.args.values[*]` instead of repeating parameter names
- avoid repeated duplicate `or` clauses
- keep each rule focused on one attack family or one endpoint

---

# 9. Field Selection for XSS Rule Generation

## 9.1 XSS Evidence

Use XSS field patterns when payloads contain:

- `<script`
- `</script`
- `onerror=`
- `onload=`
- `onclick=`
- `<svg`
- `<img`
- `javascript:`
- `document.cookie`
- `alert(`
- `%3cscript`
- `%3csvg`
- `javascript%3a`
- HTML entity encoded script indicators
- mixed-case HTML or JavaScript
- whitespace-obfuscated event handlers

## 9.2 XSS Field Decision Matrix

| Payload location | Recommended field |
|---|---|
| Unknown query parameter | `http.request.uri.query` |
| Known query parameter | `http.request.uri.args["param"][*]` |
| Encoded query payload | `raw.http.request.uri.query` |
| URI path | `http.request.uri.path` and `raw.http.request.uri.path` |
| Request header | `http.request.headers["header-name"][*]` |
| User-Agent | `http.user_agent` |
| Cookie | `http.cookie` or `http.request.cookies["name"][*]` |
| Form body | `http.request.body.form.values[*]` |
| Raw body | `http.request.body.raw` |
| High false-positive path | Add `http.request.uri.path` scoping |
| Trusted scanner exception | Add `not ip.src in $trusted_security_scanners` |

## 9.3 XSS Query Expression

```text
lower(http.request.uri.query) contains "<script"
or lower(http.request.uri.query) contains "onerror="
or lower(http.request.uri.query) contains "javascript:"
```

## 9.4 XSS Encoded Query Expression

```text
lower(raw.http.request.uri.query) contains "%3cscript"
or lower(raw.http.request.uri.query) contains "%3csvg"
or lower(raw.http.request.uri.query) contains "javascript%3a"
```

## 9.5 XSS Parameter-Specific Expression

```text
any(lower(http.request.uri.args["q"][*]) contains "<script")
or any(lower(http.request.uri.args["q"][*]) contains "onerror=")
or any(lower(http.request.uri.args["q"][*]) contains "javascript:")
```

## 9.6 XSS Header Expression

```text
any(lower(http.request.headers["x-search"][*]) contains "<script")
or any(lower(http.request.headers["x-search"][*]) contains "onerror=")
```

## 9.7 XSS Body Expression

```text
http.request.method eq "POST"
and (
  any(lower(http.request.body.form.values[*]) contains "<script")
  or any(lower(http.request.body.form.values[*]) contains "onerror=")
  or any(lower(http.request.body.form.values[*]) contains "javascript:")
)
```

> **Warning:** Body fields can require specific plan or add-on support. Do not generate body-field rules without noting availability and truncation behavior.

---

# 10. Field Selection for SQL Injection Rule Generation

## 10.1 SQLi Evidence

Use SQLi field patterns when payloads contain:

- `union select`
- `or 1=1`
- `and 1=1`
- `' or '1'='1`
- `" or "1"="1`
- `sleep(`
- `benchmark(`
- `information_schema`
- `load_file(`
- `xp_cmdshell`
- SQL comments such as `--`, `#`, or `/*`
- `%27`
- `%22`
- whitespace-split SQL tokens
- mixed-case SQL keywords

## 10.2 SQLi Field Decision Matrix

| Payload location | Recommended field |
|---|---|
| Unknown query parameter | `http.request.uri.query` |
| Known query parameter | `http.request.uri.args["id"][*]` or relevant parameter |
| Encoded query payload | `raw.http.request.uri.query` |
| URI path | `http.request.uri.path` and `raw.http.request.uri.path` |
| Request header | `http.request.headers["header-name"][*]` |
| Cookie | `http.cookie` or `http.request.cookies["name"][*]` |
| Form body | `http.request.body.form.values[*]` |
| Raw body | `http.request.body.raw` |
| API body | Body fields if available, with method and path scoping |
| High false-positive endpoint | Add host/path/method/parameter scoping |
| Trusted scanner exception | Add `not ip.src in $trusted_security_scanners` |

## 10.3 SQLi Query Expression

```text
lower(http.request.uri.query) contains "union select"
or lower(http.request.uri.query) contains "or 1=1"
or lower(http.request.uri.query) contains "sleep("
or lower(http.request.uri.query) contains "benchmark("
```

## 10.4 SQLi Regex Expression

```text
lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema)"
```

## 10.5 SQLi Encoded Query Expression

```text
lower(raw.http.request.uri.query) contains "union%20select"
or (
  lower(raw.http.request.uri.query) contains "%27"
  and (
    lower(raw.http.request.uri.query) contains "%20or%20"
    or lower(raw.http.request.uri.query) contains "or"
  )
)
```

## 10.6 SQLi Parameter-Specific Expression

```text
any(lower(http.request.uri.args["id"][*]) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()")
```

## 10.7 SQLi Body Expression

```text
http.request.method eq "POST"
and any(lower(http.request.body.form.values[*]) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()")
```

> **Warning:** SQL-like text can be legitimate in admin panels, database tools, reports, search boxes, training labs, and developer APIs. Scope SQLi rules carefully.

---

# 11. Field Selection for Exceptions and Skip Rules

## 11.1 Exception Field Strategy

Skip rules and false-positive exceptions must be narrower than blocking rules. Choose fields that define trusted context, not attack signatures.

Good exception fields:

- `ip.src`
- `http.host`
- `http.request.uri.path`
- `http.request.method`
- `cf.client.bot`
- `cf.bot_management.verified_bot`
- `cf.tls_client_auth.cert_verified`
- `cf.tls_client_auth.cert_fingerprint_sha256`
- structured JWT fields when available

Risky exception fields:

- spoofable request headers
- `http.referer`
- user-controlled query parameters
- broad country-only conditions
- broad ASN-only conditions without business justification

## 11.2 Trusted Scanner Exception

```text
ip.src in $trusted_security_scanners
```

## 11.3 Path-Scoped Trusted Scanner Exception

```text
ip.src in $trusted_security_scanners
and starts_with(http.request.uri.path, "/scanner/")
```

## 11.4 mTLS-Based Exception

```text
starts_with(http.request.uri.path, "/internal/")
and cf.tls_client_auth.cert_verified
```

## 11.5 Verified Bot Exception

```text
cf.client.bot
```

Use this to avoid challenging or blocking known good bots where appropriate.

---

# 12. Common Field Syntax Mistakes and Corrections

## 12.1 CIDR with Equality

Incorrect:

```text
ip.src eq 192.0.2.0/24
```

Correct:

```text
ip.src in {192.0.2.0/24}
```

## 12.2 Wireshark-Style CIDR Equality

Incorrect:

```text
ip.src == 1.2.3.0/24
```

Correct:

```text
ip.src in {1.2.3.0/24}
```

## 12.3 Using `ssl` as a Protocol Namespace

Incorrect:

```text
ssl.record.version eq "TLS 1.2"
```

Correct Boolean check:

```text
ssl
```

Correct TLS-version style:

```text
cf.tls_version eq "TLSv1.2"
```

## 12.4 Using Unsupported Slice Operator

Incorrect:

```text
http.request.uri.query[0:10] eq "token=test"
```

Better:

```text
starts_with(http.request.uri.query, "token=test")
```

or:

```text
http.request.uri.query contains "token=test"
```

## 12.5 Using Broad Query Field When Parameter Is Known

Risky:

```text
lower(http.request.uri.query) contains "<script"
```

Better:

```text
any(lower(http.request.uri.args["q"][*]) contains "<script")
```

## 12.6 Ignoring Encoded Payloads

Incomplete:

```text
lower(http.request.uri.query) contains "<script"
```

Better:

```text
lower(http.request.uri.query) contains "<script"
or lower(raw.http.request.uri.query) contains "%3cscript"
```

## 12.7 Using Header Arrays Without `any()`

Incorrect:

```text
http.request.headers["user-agent"][*] contains "sqlmap"
```

Correct:

```text
any(lower(http.request.headers["user-agent"][*]) contains "sqlmap")
```

---

# 13. Field-Aware WAF Rule Examples

## 13.1 Block Query-Based XSS with Encoded Coverage

```json
{
  "description": "Block XSS indicators in query string including encoded payloads",
  "expression": "(lower(http.request.uri.query) contains \"<script\" or lower(http.request.uri.query) contains \"onerror=\" or lower(http.request.uri.query) contains \"javascript:\" or lower(raw.http.request.uri.query) contains \"%3cscript\" or lower(raw.http.request.uri.query) contains \"javascript%3a\") and not ip.src in $trusted_security_scanners",
  "action": "block",
  "enabled": true
}
```

## 13.2 Block Parameter-Specific SQL Injection

```json
{
  "description": "Block SQL injection indicators in id query parameter",
  "expression": "any(lower(http.request.uri.args[\"id\"][*]) matches r\"(union\\s+select|or\\s+1\\s*=\\s*1|sleep\\s*\\()\")",
  "action": "block",
  "enabled": true
}
```

## 13.3 Managed Challenge Suspicious Login Traffic

```json
{
  "description": "Managed challenge suspicious login traffic using threat score",
  "expression": "http.request.uri.path eq \"/login\" and cf.threat_score gt 20 and not cf.client.bot",
  "action": "managed_challenge",
  "enabled": true
}
```

## 13.4 Skip Trusted Scanner Before Custom WAF Rules

```json
{
  "description": "Skip current custom rules for trusted security scanners",
  "expression": "ip.src in $trusted_security_scanners",
  "action": "skip",
  "action_parameters": {
    "ruleset": "current"
  },
  "enabled": true
}
```

## 13.5 Block Truncated Body on Sensitive Upload Endpoint

```json
{
  "description": "Block truncated request bodies on upload endpoint",
  "expression": "starts_with(http.request.uri.path, \"/api/upload\") and http.request.body.truncated",
  "action": "block",
  "enabled": true
}
```

> **Warning:** `http.request.body.truncated` requires request-body inspection support. Verify product and plan availability before deployment.

---

# 14. Field Selection Decision Matrix

| Rule-generation goal | Preferred field category | Preferred fields |
|---|---|---|
| Query-string XSS | Request + raw fields | `http.request.uri.query`, `raw.http.request.uri.query` |
| Query-string SQLi | Request + raw fields | `http.request.uri.query`, `raw.http.request.uri.query` |
| Known query parameter XSS | Request map fields | `http.request.uri.args["param"][*]` |
| Known query parameter SQLi | Request map fields | `http.request.uri.args["param"][*]` |
| Path traversal | Request + raw URI path | `http.request.uri.path`, `raw.http.request.uri.path` |
| Header payload | Request header map | `http.request.headers["name"][*]` |
| Cookie payload | Request cookie fields | `http.cookie`, `http.request.cookies` |
| Body payload | Request body fields | `http.request.body.raw`, `http.request.body.form.values`, `http.request.body.multipart.values` |
| API schema violation | Dynamic API fields | `cf.api_gateway.request_violates_schema` |
| Unknown API endpoint | Dynamic API fields | `cf.api_gateway.fallthrough_detected` |
| Bot challenge | Dynamic bot/threat fields | `cf.threat_score`, `cf.client.bot`, `cf.bot_management.score` |
| Trusted IP exception | Request IP fields | `ip.src`, named IP lists |
| mTLS exception | TLS/mTLS fields | `cf.tls_client_auth.cert_verified`, certificate fingerprint fields |
| Response-phase rule | Response fields | `http.response.code`, `http.response.headers`, `http.response.content_type.media_type` |
| Original value after rewrite | Raw fields | `raw.http.request.uri.path`, `raw.http.request.uri.query` |

---

# 15. Field-Aware False Positive Tuning

## 15.1 Fields with High False-Positive Risk

| Field | Why it may overmatch |
|---|---|
| `http.request.uri.query` | Broad query-string scanning can catch benign search strings or encoded values. |
| `http.request.uri.args.values` | Broad value scanning can catch benign user input. |
| `http.request.body.raw` | Raw body can contain legitimate HTML, SQL-like text, JSON, templates, or code. |
| `http.request.body.form.values` | Forms can contain rich text, Markdown, code snippets, or CMS content. |
| `http.cookie` | Cookies can be encoded, compressed, or application-defined. |
| `http.request.headers.values` | Broad header scanning can match benign metadata. |
| `http.user_agent` | User-Agent is spoofable and should not be the only strong security signal. |
| `ip.src.country` | Country-based controls can block legitimate users. |

## 15.2 Tuning Patterns

| Tuning method | Example |
|---|---|
| Scope by path | `starts_with(http.request.uri.path, "/search") and <attack-expression>` |
| Scope by host | `http.host eq "app.example.com" and <attack-expression>` |
| Scope by method | `http.request.method eq "POST" and <attack-expression>` |
| Scope by parameter | `any(lower(http.request.uri.args["q"][*]) contains "<script")` |
| Exclude trusted IPs | `<attack-expression> and not ip.src in $trusted_security_scanners` |
| Exclude verified bots | `<attack-expression> and not cf.client.bot` |
| Use raw fields only for encoded evidence | `lower(raw.http.request.uri.query) contains "%3cscript"` |
| Detect truncation | `http.request.body.truncated` or `http.request.headers.truncated` |
| Split broad rules | Separate XSS, SQLi, bot, and exception rules |

---

# 16. Final Template for Field-Aware Cloudflare Rule Generation

Use this template when generating a Cloudflare WAF rule from field knowledge.

```markdown
## Rule Objective

Describe:
- attack type
- payload location
- selected Cloudflare field category
- intended action

## Selected Fields

List:
- primary request field
- raw field if encoded payloads exist
- dynamic field if threat/bot/WAF score is used
- response field only if response phase applies
- plan-restricted field if applicable

## Proposed Expression

Provide the Cloudflare Rules language expression.

## Proposed Rule JSON

Provide JSON with:
- description
- expression
- action
- enabled
- action_parameters if needed

## Field Rationale

Explain:
- what each field inspects
- why the field matches the payload location
- why raw fields are or are not needed
- why dynamic fields are supporting signals
- whether any field has plan or phase constraints

## False Positive and Tuning Notes

Explain:
- broad fields that may overmatch
- path/host/method/parameter scoping
- trusted IP or verified bot exceptions
- whether to split rules
- whether to start with log/challenge/block
```

---

# 17. Final Checklist for Cloudflare Field Selection

- [ ] The chosen field matches the observed payload location.
- [ ] Request fields are used for request WAF custom rules.
- [ ] Response fields are used only in response-capable phases.
- [ ] Dynamic fields are used as supporting Cloudflare intelligence or product-specific signals.
- [ ] Raw fields are used when original or encoded request values matter.
- [ ] Query-string attacks use `http.request.uri.query` or `http.request.uri.args`.
- [ ] Known query parameters use map fields and `any()`.
- [ ] Encoded attacks include `raw.http.request.uri.query` or another raw field.
- [ ] Header fields use lowercase header names and `any()`.
- [ ] Cookie rules choose `http.cookie` or `http.request.cookies` based on specificity.
- [ ] Body fields include availability and truncation notes.
- [ ] IP ranges use `in`, not equality.
- [ ] `ssl` is treated as a Boolean field.
- [ ] The unsupported Wireshark `slice` operator is not generated.
- [ ] Expressions stay under 4,096 characters.
- [ ] False-positive-prone fields are scoped by path, host, method, parameter, IP, bot status, or trusted list.
