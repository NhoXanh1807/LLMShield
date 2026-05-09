# Cloudflare Rules Language Operators and Grouping Symbols Knowledge Base for WAF Rule Generation
# 1. Cloudflare Rules Language Operator Model
## 1.1 Definition

Cloudflare Rules language expressions evaluate request fields, dynamic fields, response fields, raw fields, transformed values, literal values, arrays, maps, and lists. An expression returns a Boolean result.

When a Cloudflare WAF custom rule expression evaluates to `true`, the configured action runs.

General simple expression pattern:

```text
<field> <comparison_operator> <value>
```

Example:

```text
http.request.uri.path eq "/login"
```

General compound expression pattern:

```text
<expression> <logical_operator> <expression>
```

Example:

```text
starts_with(http.request.uri.path, "/search")
and lower(http.request.uri.query) contains "<script"
```

## 1.2 Operator Categories

| Operator category | Operators | Rule-generation use |
|---|---|---|
| Equality | `eq`, `==`, `ne`, `!=` | Exact host, path, method, country, ASN, score, status, or field-value matching. |
| Numeric / ordered comparison | `lt`, `<`, `le`, `<=`, `gt`, `>`, `ge`, `>=` | Threat score, WAF score, bot score, length, body size, response code, or numeric policy thresholds. |
| String containment | `contains` | Literal XSS/SQLi indicators such as `<script`, `onerror=`, `union select`, `sleep(`. |
| Wildcard matching | `wildcard`, `strict wildcard` | Full-string wildcard matching for host, URI, path, or broad path policies. |
| Regex matching | `matches`, `~` | Flexible XSS/SQLi patterns, whitespace variants, grouped alternatives. |
| Set and list membership | `in` | IP allowlists/blocklists, CIDR ranges, host lists, country lists, ASN lists, named lists. |
| Logical operators | `not`, `!`, `and`, `&&`, `xor`, `^^`, `or`, `||` | Combine scope, attack evidence, exclusions, and policy conditions. |
| Grouping symbols | `(`, `)` | Enforce precedence and make compound expressions unambiguous. |

## 1.3 Operator Selection Principle for WAF Rules

Use the narrowest operator that correctly represents the observed attack evidence:

1. Use `eq` for exact path, host, method, country, or fixed values.
2. Use `contains` for stable literal payload indicators.
3. Use `matches` when payload structure varies by whitespace, casing after normalization, optional characters, or alternatives.
4. Use `wildcard` only when the whole field should match a wildcard pattern.
5. Use `in` for IP/CIDR/list membership.
6. Use `not` for explicit exclusions, especially trusted scanners or verified bots.
7. Use parentheses whenever `and` and `or` are mixed.
8. Use `lower()` with string operators unless case sensitivity is required.

---

# 2. Comparison Operators Overview

## 2.1 Definition

Comparison operators return `true` when a value from a request, response, computed field, or transformed field matches a value defined in the expression.

General pattern:

```text
<field> <comparison_operator> <value>
```

Example:

```text
http.request.uri.path eq "/articles/2008/"
```

## 2.2 Supported Comparison Operators

| Name | English notation | C-like notation | Supports string | Supports IP | Supports number | Best WAF rule-generation use |
|---|---|---|---:|---:|---:|---|
| Equal | `eq` | `==` | Yes | Yes | Yes | Exact host, path, method, IP, country, ASN, or status match. |
| Not equal | `ne` | `!=` | Yes | Yes | Yes | Exclude exact value. |
| Less than | `lt` | `<` | Yes | No | Yes | WAF score, bot score, threat score, numeric thresholds. |
| Less than or equal | `le` | `<=` | Yes | No | Yes | Score threshold and numeric thresholds. |
| Greater than | `gt` | `>` | Yes | No | Yes | Body size, length, score threshold, response code. |
| Greater than or equal | `ge` | `>=` | Yes | No | Yes | Score or numeric threshold. |
| Contains | `contains` | None | Yes | No | No | Literal string indicator in URI, query, header, cookie, or body. |
| Wildcard | `wildcard` | None | Yes | No | No | Case-insensitive full-string wildcard matching. |
| Strict wildcard | `strict wildcard` | None | Yes | No | No | Case-sensitive full-string wildcard matching. |
| Matches regex | `matches` | `~` | Yes | No | No | Regex pattern matching for flexible attack signatures. |
| Is in set / list | `in` | None | Yes | Yes | Yes | Inline sets, CIDR ranges, named lists, country/ASN/host sets. |

## 2.3 Lowercase Requirement for English Operators

Cloudflare English notation operators must be lowercase.

Correct:

```text
http.request.uri.path eq "/login"
```

Incorrect:

```text
http.request.uri.path EQ "/login"
```

Correct:

```text
lower(http.request.uri.query) contains "<script"
```

Incorrect:

```text
lower(http.request.uri.query) CONTAINS "<script"
```

Rule-generation requirement:

> Always generate `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `contains`, `matches`, `in`, `not`, `and`, `xor`, and `or` in lowercase.

## 2.4 String Comparison Is Case-Sensitive by Default

Most string comparisons in Cloudflare Rules language are case-sensitive unless the operator is explicitly case-insensitive, such as `wildcard`.

Case-sensitive expression:

```text
http.request.uri.query contains "<script"
```

This may not match:

```text
<SCRIPT>
<ScRiPt>
```

Case-normalized expression:

```text
lower(http.request.uri.query) contains "<script"
```

Rule-generation requirement:

- Use `lower()` for XSS and SQL injection payloads unless the user explicitly requires case-sensitive matching.
- Compare the transformed value against lowercase literals.
- For arrays, use `lower(field[*])[*]` inside `any()`.

Example:

```text
any(lower(http.request.headers["user-agent"][*])[*] contains "sqlmap")
```

---

# 3. Equality Operators: `eq`, `==`, `ne`, `!=`

## 3.1 Definition

The equality operators compare a field value to a specific value.

| Operator | Meaning |
|---|---|
| `eq` or `==` | Returns `true` when both values are equal. |
| `ne` or `!=` | Returns `true` when both values are not equal. |

## 3.2 Best Uses in WAF Rule Generation

Use equality operators for:

- exact URI path matching
- exact hostname matching
- exact HTTP method matching
- exact country or region code matching
- exact ASN matching when using numeric values
- exact header values when the value must be precise
- exact API route scoping
- exact response status in response phases

## 3.3 Exact Path Match

```text
http.request.uri.path eq "/login"
```

Use for:

- login protection
- admin endpoint protection
- exact route exceptions
- exact path skip rules

## 3.4 Exact Host Match

```text
http.host eq "api.example.com"
```

Use for:

- scoping WAF rules to one hostname
- avoiding cross-application false positives
- applying API rules only to API hosts

## 3.5 Exact Method Match

```text
http.request.method eq "POST"
```

Use for:

- applying body inspection only to POST requests
- protecting login submissions
- scoping API write operations

## 3.6 Not Equal Exclusion

```text
http.request.uri.path ne "/healthcheck"
```

Use cautiously. For multiple exclusions, prefer grouping:

```text
not (
  http.request.uri.path eq "/healthcheck"
  or http.request.uri.path eq "/status"
)
```

## 3.7 Equality Operator Checklist

- [ ] Use `eq` for exact scalar values.
- [ ] Use `in` instead of chained `or` when matching many exact values.
- [ ] Use `in` for IP ranges and CIDR blocks.
- [ ] Do not use equality with CIDR notation.
- [ ] Use `lower()` if string case may vary.

---

# 4. Numeric and Ordered Comparison Operators: `lt`, `le`, `gt`, `ge`

## 4.1 Definition

Numeric and ordered comparison operators compare values by ordering.

| Operator | Meaning |
|---|---|
| `lt` or `<` | Less than |
| `le` or `<=` | Less than or equal |
| `gt` or `>` | Greater than |
| `ge` or `>=` | Greater than or equal |

## 4.2 Best Uses in WAF Rule Generation

Use numeric comparison for:

- `cf.threat_score`
- `cf.waf.score`
- `cf.waf.score.xss`
- `cf.waf.score.sqli`
- `cf.bot_management.score`
- `len(...)`
- body size fields
- header count or value length
- response status codes in response phases
- timestamp or token-related comparisons when available

## 4.3 Threat Score Challenge Example

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

## 4.4 WAF Attack Score Examples

Cloudflare WAF attack scores are commonly used so lower scores represent more suspicious traffic.

XSS score:

```text
starts_with(http.request.uri.path, "/search")
and cf.waf.score.xss lt 30
```

SQLi score:

```text
starts_with(http.request.uri.path, "/api/search")
and cf.waf.score.sqli lt 30
```

Global WAF score:

```text
cf.waf.score lt 30
```

Use only when the account has the relevant WAF score fields.

## 4.5 Length-Based Example

```text
starts_with(http.request.uri.path, "/search")
and len(http.request.uri.query) gt 512
and lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()"
```

Use length as a supporting signal, not as the only SQLi/XSS indicator.

## 4.6 Numeric Operator Checklist

- [ ] Use numeric comparison for score, length, size, timestamp, or status fields.
- [ ] Combine score thresholds with path, host, method, or attack evidence.
- [ ] Avoid blocking solely on a broad score unless the user explicitly requests it.
- [ ] Mention plan or product constraints for WAF score and Bot Management fields.

---

# 5. String Containment Operator: `contains`

## 5.1 Definition

`contains` returns `true` when a string field contains a specified substring.

General syntax:

```text
<field> contains <string>
```

Example:

```text
http.request.uri.path contains "/articles/"
```

## 5.2 Best Uses in WAF Rule Generation

Use `contains` for stable literal indicators such as:

| Attack type | Good `contains` literals |
|---|---|
| XSS | `<script`, `onerror=`, `onload=`, `javascript:`, `<svg`, `<img`, `document.cookie` |
| SQLi | `union select`, `or 1=1`, `sleep(`, `benchmark(`, `information_schema` |
| Path traversal | `../`, `..%2f`, `%2e%2e%2f` |
| Scanner traffic | `sqlmap`, `nikto`, `acunetix`, `curl`, `python-requests` |
| Open redirect | `redirect=http`, `url=http`, `next=http` |

## 5.3 XSS Query String Example

```text
lower(http.request.uri.query) contains "<script"
or lower(http.request.uri.query) contains "onerror="
or lower(http.request.uri.query) contains "javascript:"
```

Use when:

- XSS appears in query string.
- Parameter name is unknown.
- Regex is unavailable or unnecessary.
- Literal indicators are stable.

## 5.4 SQLi Query String Example

```text
lower(http.request.uri.query) contains "union select"
or lower(http.request.uri.query) contains "or 1=1"
or lower(http.request.uri.query) contains "sleep("
or lower(http.request.uri.query) contains "benchmark("
```

Use when:

- SQLi appears in query string.
- Literal SQLi indicators are stable.
- Regex is unavailable or unnecessary.

## 5.5 Header Scanner Example

```text
any(lower(http.request.headers["user-agent"][*])[*] contains "sqlmap")
or any(lower(http.request.headers["user-agent"][*])[*] contains "nikto")
or any(lower(http.request.headers["user-agent"][*])[*] contains "acunetix")
```

## 5.6 Encoded Payload Example

If payloads arrive encoded and should be matched exactly:

```text
lower(raw.http.request.uri.query) contains "%3cscript"
or lower(raw.http.request.uri.query) contains "javascript%3a"
or lower(raw.http.request.uri.query) contains "union%20select"
```

If decoding is available and desired:

```text
lower(url_decode(http.request.uri.query, "r")) contains "<script"
or lower(url_decode(http.request.uri.query, "r")) contains "union select"
```

## 5.7 When Not to Use `contains`

Avoid broad literals such as:

```text
lower(http.request.uri.query) contains "select"
```

```text
lower(http.request.uri.query) contains "on"
```

These are too generic and likely to false positive.

Better SQLi pattern:

```text
lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()"
```

Better XSS pattern:

```text
lower(http.request.uri.query) matches r"(<script|onerror\s*=|onload\s*=|javascript:)"
```

## 5.8 `contains` Checklist

- [ ] Use for stable literal indicators.
- [ ] Pair with `lower()` for case-insensitive matching.
- [ ] Avoid one-word generic SQL/XSS tokens.
- [ ] Scope broad `contains` rules by path, host, method, or parameter.
- [ ] Use `matches` when whitespace, alternatives, or flexible syntax matter.

---

# 6. Regex Matching Operator: `matches` / `~`

## 6.1 Definition

`matches` performs regular expression matching against a string field. The C-like notation is `~`.

General syntax:

```text
<field> matches <regular_expression>
```

Example:

```text
http.request.uri.path matches "^/articles/200[7-8]/$"
```

## 6.2 Availability and Engine

Important constraints:

- `matches` requires Cloudflare Business or Enterprise plan access.
- Regex matching uses the Rust regular expression engine.
- Each rule supports a maximum number of regexes.
- Raw string syntax is recommended for regex literals.

## 6.3 Regex Partial Matching

The `matches` operator can match part of a value.

Example:

```text
lower(http.request.uri.query) matches r"(<script|onerror\s*=|javascript:)"
```

This can match when the query string contains any of these patterns anywhere in the field.

## 6.4 XSS Regex Example

```text
lower(http.request.uri.query) matches r"(<script|onerror\s*=|onload\s*=|onclick\s*=|javascript:|<svg|<img)"
```

Use when:

- event handlers vary by whitespace
- multiple XSS indicators should be covered compactly
- regex support is available
- a single rule should detect a family of XSS payloads

## 6.5 SQLi Regex Example

```text
lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema)"
```

Use when:

- SQL keywords vary by whitespace
- the payload family has multiple variants
- `contains` would require too many `or` clauses

## 6.6 Parameter-Specific Regex Example

```text
any(lower(http.request.uri.args["id"][*])[*] matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()")
```

Use when:

- vulnerable parameter is known
- repeated parameter values are possible
- false positives should be reduced

## 6.7 Raw String Syntax for Regex

Prefer raw string syntax for regex values:

```text
http.request.uri.path matches r"/api/login\.aspx$"
```

Raw strings reduce escaping complexity compared with quoted strings.

Quoted string syntax requires escaping `\` and `"`:

```text
http.request.uri.path matches "/api/login\\.aspx$"
```

## 6.8 Regex Limits and Alternatives

If regex is unavailable or too expensive, use alternatives:

| Regex goal | Alternative |
|---|---|
| Match stable literal | `contains` |
| Match path prefix | `starts_with()` |
| Match path suffix | `ends_with()` |
| Match simple full-string pattern | `wildcard` or `strict wildcard` |
| Match many exact values | `in` with inline list or named list |
| Avoid too many regexes | combine alternatives in one regex or split rules |

## 6.9 `matches` Checklist

- [ ] Use when flexible pattern matching is needed.
- [ ] Mention Business/Enterprise plan requirement.
- [ ] Prefer raw string syntax for regex.
- [ ] Keep regex compact and Rust-compatible.
- [ ] Avoid broad patterns that match benign traffic.
- [ ] Provide `contains` fallback if plan support is unknown.

---

# 7. Wildcard Operators: `wildcard` and `strict wildcard`

## 7.1 Definition

The `wildcard` and `strict wildcard` operators compare a string field against a literal string containing zero or more `*` metacharacters.

| Operator | Case behavior | Matching scope |
|---|---|---|
| `wildcard` | Case-insensitive | Entire field value must match the wildcard pattern. |
| `strict wildcard` | Case-sensitive | Entire field value must match the wildcard pattern. |

## 7.2 Important Wildcard Rule

Wildcard matching considers the entire field value.

Example:

```text
http.request.full_uri wildcard "http*://example.com/a/*"
```

This can match:

```text
https://example.com/a/
http://example.com/a/
https://example.com/a/page.html
https://example.com/a/sub/folder/?name=value
```

It does not match:

```text
https://example.com/ab/
https://example.com/b/page.html
https://sub.example.com/a/
```

## 7.3 Slashes Have No Special Meaning

In wildcard patterns, `/` has no special behavior beyond being a normal character.

Example:

```text
http.request.full_uri wildcard "*.example.com/*/page.html"
```

The `*` between slashes can match values containing slashes, such as:

```text
folder
team
team/subteam
```

## 7.4 Case-Insensitive Wildcard

```text
http.request.full_uri wildcard "*.example.com/*"
```

Use when case-insensitive full-value wildcard matching is intended.

## 7.5 Case-Sensitive Wildcard

```text
http.request.uri.path strict wildcard "/AdminTeam/*"
```

Use when case sensitivity is required.

## 7.6 Escaping Wildcard Literals

To match a literal `*`, escape it:

```text
\*
```

To match a literal backslash, escape it:

```text
\\
```

Two unescaped stars in a row are invalid:

```text
**
```

Recommended for complex wildcard literals:

```text
r"/path/with/\*/literal"
```

Use raw string syntax when escaping becomes complex.

## 7.7 Wildcard Versus Regex

| Feature | `wildcard` / `strict wildcard` | `matches` |
|---|---|---|
| Match scope | Entire field value | Can match partial value |
| Pattern language | `*` only | Regex |
| Case behavior | `wildcard` case-insensitive, `strict wildcard` case-sensitive | Case-sensitive unless pattern handles variants or field is lowercased |
| Plan requirement | Generally simpler than regex | Business/Enterprise requirement |
| Best use | Whole-host, whole-URI, route patterns | XSS/SQLi payload patterns and flexible matching |

## 7.8 When to Use Wildcard in WAF Rules

Use wildcard for:

- full hostname patterns
- full URI route families
- broad path policies
- simple whole-value matching
- cases where regex is unavailable but full-value matching is acceptable

Example:

```text
http.request.full_uri wildcard "https://*.example.com/admin/*"
```

## 7.9 When Not to Use Wildcard

Do not use wildcard when you need substring matching inside a larger field unless your pattern accounts for the entire field.

For XSS and SQLi detection, prefer:

```text
lower(http.request.uri.query) contains "<script"
```

or:

```text
lower(http.request.uri.query) matches r"(<script|onerror\s*=|javascript:)"
```

## 7.10 Wildcard Checklist

- [ ] Use only when entire field matching is intended.
- [ ] Use `wildcard` for case-insensitive matching.
- [ ] Use `strict wildcard` for case-sensitive matching.
- [ ] Escape literal `*` and `\`.
- [ ] Avoid `**`.
- [ ] Prefer `contains` or `matches` for payload detection.

---

# 8. Membership Operator: `in`

## 8.1 Definition

The `in` operator checks whether a field value is in an inline set or named list.

General syntax:

```text
<field> in {<value1> <value2> <value3>}
```

Named list syntax:

```text
<field> in $<list_name>
```

## 8.2 Best Uses in WAF Rule Generation

Use `in` for:

- IP allowlists
- IP blocklists
- CIDR ranges
- trusted scanners
- office networks
- country lists
- ASN lists
- host lists
- method lists
- status code lists
- exact string membership
- named Cloudflare lists

## 8.3 IP Inline Set Example

```text
ip.src in {203.0.113.10 203.0.113.11 198.51.100.0/24 2001:db8::/32}
```

## 8.4 Host Inline Set Example

```text
http.host in {"www.example.com" "api.example.com"}
```

## 8.5 Country Inline Set Example

```text
ip.src.country in {"CN" "RU" "KP"}
```

Use country-based logic only when the user explicitly wants geographic policy. It is not a primary SQLi/XSS detector.

## 8.6 ASN Inline Set Example

```text
ip.src.asnum in {12345 64512}
```

## 8.7 Named List Example

```text
ip.src in $trusted_security_scanners
```

Use named lists for reusable or large sets.

List names can contain lowercase letters, numbers, and underscores.

## 8.8 Not In List Example

Cloudflare expression syntax uses `not` with `in`:

```text
not ip.src in $trusted_security_scanners
```

Example attack rule excluding trusted scanners:

```text
(
  lower(http.request.uri.query) contains "<script"
  or lower(http.request.uri.query) contains "union select"
)
and not ip.src in $trusted_security_scanners
```

## 8.9 CIDR Syntax Requirement

Use `in` for CIDR ranges.

Correct:

```text
ip.src in {192.0.2.0/24}
```

Incorrect:

```text
ip.src eq 192.0.2.0/24
```

Incorrect Wireshark-style syntax:

```text
ip.src == 192.0.2.0/24
```

## 8.10 Inline List Rules

Inline lists:

- separate elements with spaces
- require all elements to be the same data type
- can include duplicate values
- can include string, integer, IP address, IP range, or CIDR values
- can include integer ranges using `<start>..<end>`
- can include IP ranges using `<start_address>..<end_address>`

Examples:

```text
http.host in {"example.com" "example.net"}
```

```text
ip.src in {198.51.100.1 198.51.100.3..198.51.100.7 192.0.2.0/24 2001:db8::/32}
```

```text
tcp.dstport in {8000..8009 8080..8089}
```

## 8.11 `in` Checklist

- [ ] Use for exact membership in sets and lists.
- [ ] Use for CIDR ranges.
- [ ] Use named lists for reusable allowlists/blocklists.
- [ ] Use `not <field> in <list>` for exclusions.
- [ ] Do not mix data types in one inline list.
- [ ] Do not use equality for CIDR ranges.

---

# 9. Dashboard Operator Labels Versus Expression Syntax

## 9.1 Dashboard Labels

The Cloudflare dashboard may show operator-like labels depending on field and rule type:

- starts with
- ends with
- is in list
- is not in list

These labels do not always map to operator syntax in manually written expressions.

## 9.2 `starts_with()` Must Be a Function

Correct:

```text
starts_with(http.request.uri.path, "/api/")
```

Incorrect:

```text
http.request.uri.path starts_with "/api/"
```

## 9.3 `ends_with()` Must Be a Function

Correct:

```text
ends_with(http.request.uri.path, ".html")
```

Incorrect:

```text
http.request.uri.path ends_with ".html"
```

## 9.4 List Membership Syntax

Dashboard label:

```text
is in list
```

Expression syntax:

```text
ip.src in $office_network
```

Dashboard label:

```text
is not in list
```

Expression syntax:

```text
not ip.src in $office_network
```

## 9.5 Path Prefix Scope Example

```text
starts_with(http.request.uri.path, "/api/")
and lower(http.request.uri.query) contains "union select"
```

## 9.6 Path Suffix Scope Example

```text
ends_with(http.request.uri.path, ".php")
and lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1)"
```

## 9.7 Generation Checklist

- [ ] Do not generate `field starts_with "value"`.
- [ ] Do not generate `field ends_with "value"`.
- [ ] Use function call syntax for `starts_with()` and `ends_with()`.
- [ ] Use `in $list_name` for named lists.
- [ ] Use `not field in $list_name` for not-in-list logic.

---

# 10. Logical Operators

## 10.1 Definition

Logical operators combine two or more expressions into a compound expression.

General syntax:

```text
<expression> <logical_operator> <expression>
```

Example:

```text
http.host eq "www.example.com"
and ip.src in {203.0.113.0/24}
```

## 10.2 Supported Logical Operators and Precedence

| Name | English notation | C-like notation | Meaning | Precedence |
|---|---|---|---|---:|
| Logical NOT | `not` | `!` | Negates an expression. | 1 |
| Logical AND | `and` | `&&` | Both expressions must be true. | 2 |
| Logical XOR | `xor` | `^^` | Exactly one expression must be true. | 3 |
| Logical OR | `or` | `||` | At least one expression must be true. | 4 |

Lower precedence number means earlier evaluation.

Precedence order:

```text
not
and
xor
or
```

## 10.3 Lowercase Requirement

English logical operators must be lowercase.

Correct:

```text
not ip.src in $trusted_security_scanners
```

Incorrect:

```text
NOT ip.src in $trusted_security_scanners
```

Correct:

```text
Expression1 and Expression2
```

Incorrect:

```text
Expression1 AND Expression2
```

## 10.4 `not` Operator

Use `not` for exclusions.

Example:

```text
not cf.client.bot
```

Example trusted IP exclusion:

```text
not ip.src in $trusted_security_scanners
```

Example grouped exclusion:

```text
not (
  http.request.uri.path eq "/healthcheck"
  or http.request.uri.path eq "/status"
)
```

## 10.5 `and` Operator

Use `and` when every condition must be true.

Example:

```text
starts_with(http.request.uri.path, "/search")
and lower(http.request.uri.query) contains "<script"
```

Use for:

- path-scoped attack rules
- host-scoped block rules
- method-scoped body rules
- attack condition plus trusted-source exclusion

## 10.6 `or` Operator

Use `or` when any one condition can match.

Example:

```text
lower(http.request.uri.query) contains "<script"
or lower(http.request.uri.query) contains "onerror="
or lower(http.request.uri.query) contains "javascript:"
```

Use for:

- multiple XSS indicators
- multiple SQLi indicators
- multiple paths
- multiple allowed hosts
- multiple detection branches

## 10.7 `xor` Operator

Use `xor` rarely. It matches when exactly one expression is true.

Example:

```text
http.host eq "api.example.com"
xor http.host eq "www.example.com"
```

For most WAF rules, prefer `and` or `or`.

## 10.8 Logical Operator Checklist

- [ ] Use `and` to combine scope and attack evidence.
- [ ] Use `or` for alternative attack indicators.
- [ ] Use `not` for trusted exclusions.
- [ ] Use parentheses whenever mixing `and` and `or`.
- [ ] Avoid `xor` unless exclusive logic is explicitly required.
- [ ] Keep English notation lowercase.

---

# 11. Grouping Symbols and Precedence

## 11.1 Definition

Grouping symbols are parentheses:

```text
(
)
```

They organize expressions, enforce precedence, and allow nested logic.

## 11.2 Why Grouping Matters

Without grouping, this expression:

```text
Expression1 and Expression2 or Expression3
```

is evaluated as:

```text
(Expression1 and Expression2) or Expression3
```

because `and` has higher precedence than `or`.

If the intended logic is:

```text
Expression1 and (Expression2 or Expression3)
```

then parentheses are required.

## 11.3 Grouped XSS Rule

```text
starts_with(http.request.uri.path, "/search")
and (
  lower(http.request.uri.query) contains "<script"
  or lower(http.request.uri.query) contains "onerror="
  or lower(http.request.uri.query) contains "javascript:"
)
```

This means:

- request path must start with `/search`
- and at least one XSS indicator must appear in the query string

## 11.4 Grouped SQLi Rule with Exclusion

```text
(
  lower(http.request.uri.query) contains "union select"
  or lower(http.request.uri.query) contains "or 1=1"
  or lower(http.request.uri.query) contains "sleep("
)
and not ip.src in $trusted_security_scanners
```

This means:

- any SQLi indicator can match
- trusted scanners are excluded

## 11.5 Nested Grouping Example

```text
(
  (
    http.host eq "api.example.com"
    and starts_with(http.request.uri.path, "/api/v2/auth")
  )
  or (
    http.host matches r"^(www|store|blog)\.example\.com"
    and http.request.uri.path contains "wp-login.php"
  )
  or ip.src.country in {"CN" "TH" "US" "ID" "KR" "MY" "IT" "SG" "GB"}
  or ip.src.asnum in {12345 54321 11111}
)
and not ip.src in {11.22.33.0/24}
```

## 11.6 Parentheses Inside Strings

Parentheses inside quoted strings or raw strings are part of the string or regex and are not grouping symbols for expression precedence.

Example:

```text
http.host matches r"^(www|store|blog)\.example\.com"
```

The parentheses in the regex group alternatives inside the regex. They do not group Cloudflare logical expressions.

## 11.7 Grouping Support Constraint

Grouping symbols are supported in:

- Expression Editor.
- Cloudflare API.

Grouping symbols are not supported by the visual Expression Builder.

Rule-generation guidance:

> If the generated expression uses parentheses, recommend deployment through the Expression Editor or API.

## 11.8 Grouping Checklist

- [ ] Use parentheses for mixed `and`/`or` logic.
- [ ] Use parentheses around `or` groups when adding path or host scope.
- [ ] Use parentheses around attack-indicator groups before trusted-source exclusions.
- [ ] Use parentheses for nested policy logic.
- [ ] Mention Expression Editor or API deployment for grouped expressions.

---

# 12. Operator Design for XSS Rule Generation

## 12.1 XSS Signals

Use XSS operator patterns when payloads contain:

- `<script`
- `</script`
- `onerror=`
- `onload=`
- `onclick=`
- `onmouseover=`
- `<svg`
- `<img`
- `<iframe`
- `javascript:`
- `document.cookie`
- `alert(`
- `%3cscript`
- `%3csvg`
- `javascript%3a`
- HTML entity encoded tags or attributes
- mixed-case event handlers
- whitespace-obfuscated event handlers

## 12.2 XSS with `contains`

```text
lower(http.request.uri.query) contains "<script"
or lower(http.request.uri.query) contains "onerror="
or lower(http.request.uri.query) contains "onload="
or lower(http.request.uri.query) contains "javascript:"
```

Use when:

- literals are stable
- regex support is unavailable
- query parameter name is unknown

## 12.3 XSS with `matches`

```text
lower(http.request.uri.query) matches r"(<script|onerror\s*=|onload\s*=|onclick\s*=|javascript:|<svg|<img)"
```

Use when:

- whitespace may vary
- multiple indicators should be compact
- Business/Enterprise regex support is available

## 12.4 XSS with Raw Encoded Matching

```text
lower(raw.http.request.uri.query) contains "%3cscript"
or lower(raw.http.request.uri.query) contains "%3csvg"
or lower(raw.http.request.uri.query) contains "javascript%3a"
or lower(raw.http.request.uri.query) contains "onerror%3d"
```

Use when:

- the observed bypass uses URL encoding
- encoded payloads reach Ruleset Engine fields unchanged
- exact original encoding should be detected

## 12.5 XSS with URL Decode Function and Operators

```text
lower(url_decode(http.request.uri.query, "r")) contains "<script"
or lower(url_decode(http.request.uri.query, "r")) contains "onerror="
or lower(url_decode(http.request.uri.query, "r")) contains "javascript:"
```

Use when:

- double URL encoding is observed
- recursive decoding is desired
- `url_decode()` is supported in the target rule context

## 12.6 Parameter-Specific XSS

```text
any(lower(http.request.uri.args["q"][*])[*] matches r"(<script|onerror\s*=|onload\s*=|javascript:)")
```

Use when:

- vulnerable parameter is known
- false positives are likely with whole query matching
- repeated parameter values are possible

## 12.7 Path-Scoped XSS

```text
starts_with(http.request.uri.path, "/search")
and (
  lower(http.request.uri.query) contains "<script"
  or lower(http.request.uri.query) contains "onerror="
  or lower(http.request.uri.query) contains "javascript:"
)
```

## 12.8 XSS Operator Checklist

- [ ] Use `lower()` before `contains` or `matches`.
- [ ] Use `contains` for stable literal tokens.
- [ ] Use `matches` for event handler spacing and variants.
- [ ] Use raw fields or `url_decode()` for encoded payloads.
- [ ] Use `any()` for arrays.
- [ ] Use path/host/method/parameter scoping when false positives are likely.
- [ ] Use `not ip.src in $trusted_security_scanners` for trusted scanner exclusions.

---

# 13. Operator Design for SQL Injection Rule Generation

## 13.1 SQLi Signals

Use SQLi operator patterns when payloads contain:

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
- `--`
- `#`
- `/*`
- `%27`
- `%22`
- mixed-case SQL keywords
- whitespace-split SQL keywords

## 13.2 SQLi with `contains`

```text
lower(http.request.uri.query) contains "union select"
or lower(http.request.uri.query) contains "or 1=1"
or lower(http.request.uri.query) contains "sleep("
or lower(http.request.uri.query) contains "benchmark("
or lower(http.request.uri.query) contains "information_schema"
```

Use when:

- SQLi indicators are stable literals
- regex is unavailable
- query parameter is unknown

## 13.3 SQLi with `matches`

```text
lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema)"
```

Use when:

- whitespace varies
- the attacker uses token spacing
- several SQLi patterns should be covered compactly

## 13.4 SQLi with Raw Encoded Matching

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

Use when:

- SQL quotes or SQL tokens are URL-encoded
- raw encoded payload evidence should be matched directly

## 13.5 SQLi with URL Decode Function and Operators

```text
lower(url_decode(http.request.uri.query, "r")) contains "union select"
or lower(url_decode(http.request.uri.query, "r")) contains "or 1=1"
or lower(url_decode(http.request.uri.query, "r")) contains "sleep("
```

Use for URL-encoded or double-encoded SQLi.

## 13.6 Parameter-Specific SQLi

```text
any(lower(http.request.uri.args["id"][*])[*] matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()")
```

Use when:

- SQLi is known to appear in a parameter such as `id`, `product`, `search`, `category`, or `q`
- full query inspection creates false positives

## 13.7 Path-Scoped SQLi

```text
starts_with(http.request.uri.path, "/api/search")
and (
  lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()"
)
```

## 13.8 SQLi Operator Checklist

- [ ] Use `lower()` for SQL keyword normalization.
- [ ] Use `matches` for whitespace-flexible patterns when available.
- [ ] Use `contains` fallback when regex is unavailable.
- [ ] Avoid single generic terms such as `"select"` alone.
- [ ] Use raw fields or `url_decode()` for encoded payloads.
- [ ] Scope SQLi rules by host, path, method, or parameter when possible.
- [ ] Include false-positive notes for search forms, SQL labs, admin tools, reporting tools, and developer APIs.

---

# 14. Operator Design for Path Traversal, LFI, and Encoded Path Rules

## 14.1 Path Traversal Signals

Use traversal operator patterns when payloads contain:

- `../`
- `..\`
- `%2e%2e%2f`
- `%2e%2e%5c`
- `..%2f`
- `..%5c`
- `/etc/passwd`
- `boot.ini`
- file path probes

## 14.2 Raw Encoded Path Traversal

```text
lower(raw.http.request.uri.path) contains "..%2f"
or lower(raw.http.request.uri.path) contains "%2e%2e%2f"
or lower(raw.http.request.uri.path) contains "..%5c"
or lower(raw.http.request.uri.path) contains "%2e%2e%5c"
```

## 14.3 Literal Path Traversal

```text
lower(http.request.uri.path) contains "../"
or lower(http.request.uri.path) contains "..\\"
or lower(http.request.uri.query) contains "/etc/passwd"
```

## 14.4 URL-Decoded Traversal

```text
lower(url_decode(http.request.uri.path, "r")) contains "../"
or lower(url_decode(http.request.uri.path, "r")) contains "..\\"
```

## 14.5 Path Traversal Checklist

- [ ] Use `raw.http.request.uri.path` for encoded traversal evidence.
- [ ] Use `url_decode(..., "r")` for recursive decoding if supported.
- [ ] Use `contains` for stable traversal tokens.
- [ ] Scope to sensitive paths if false positives are possible.
- [ ] Consider separate rules for path and query locations.

---

# 15. Operator Design for Skip Rules and Exceptions

## 15.1 Exception Principle

Skip rules and exceptions should be narrower than enforcement rules.

Good exception operators:

- `eq` for exact path/host/method.
- `starts_with()` for scoped path prefixes.
- `in` for trusted IP lists.
- `not` for exclusions.
- `and` to combine trusted source and target scope.

Avoid exceptions based only on user-controlled or spoofable values such as query parameters, Referer, or arbitrary headers.

## 15.2 Trusted Scanner Skip Expression

```text
ip.src in $trusted_security_scanners
```

Use this in a skip rule placed before broad block rules.

## 15.3 Path-Scoped Trusted Scanner Skip

```text
ip.src in $trusted_security_scanners
and starts_with(http.request.uri.path, "/scanner/")
```

## 15.4 Verified Bot Exclusion

```text
not cf.client.bot
```

Example challenge rule:

```text
http.request.uri.path eq "/login"
and cf.threat_score gt 20
and not cf.client.bot
```

## 15.5 Exclude Trusted IPs Inside Attack Rule

```text
(
  lower(http.request.uri.query) contains "<script"
  or lower(http.request.uri.query) contains "union select"
)
and not ip.src in $trusted_security_scanners
```

## 15.6 Exception Checklist

- [ ] Use `in` for trusted IP or named list membership.
- [ ] Use exact path/host/method constraints.
- [ ] Use `and` to combine trusted source and narrow scope.
- [ ] Place skip rules before the rules they should skip.
- [ ] Avoid broad `skip` expressions.
- [ ] Avoid trusting spoofable headers unless infrastructure guarantees them.

---

# 16. Operator-Aware False Positive Tuning

## 16.1 High False-Positive Operator Patterns

| Pattern | Why risky | Better approach |
|---|---|---|
| `contains "select"` | Matches benign search text or SQL tutorials. | Use `matches r"(union\s+select|or\s+1\s*=\s*1)"`. |
| `contains "on"` | Too generic for XSS. | Use `contains "onerror="` or regex for event handlers. |
| Broad query rule without scope | Catches benign query values. | Add path, host, method, or parameter scope. |
| Broad body rule without scope | Catches CMS/rich-text/code content. | Scope by path, method, Content-Type, or parameter. |
| Country-only block for SQLi/XSS | Blocks legitimate users and is not attack-specific. | Combine attack evidence with geography if required. |
| User-Agent-only block | User-Agent is spoofable. | Combine with payload, path, score, or rate signal. |
| Ungrouped `and`/`or` expression | Evaluation may not match intended logic. | Add parentheses. |

## 16.2 Tuning with Scope

Path scope:

```text
starts_with(http.request.uri.path, "/search")
and lower(http.request.uri.query) contains "<script"
```

Host scope:

```text
http.host eq "app.example.com"
and lower(http.request.uri.query) contains "union select"
```

Method scope:

```text
http.request.method eq "POST"
and lower(http.request.uri.query) contains "union select"
```

Parameter scope:

```text
any(lower(http.request.uri.args["q"][*])[*] contains "<script")
```

Trusted IP exclusion:

```text
not ip.src in $trusted_security_scanners
```

## 16.3 Tuning Checklist

- [ ] Add path scope for endpoint-specific vulnerabilities.
- [ ] Add host scope for multi-tenant or multi-app zones.
- [ ] Add method scope for body or login rules.
- [ ] Use parameter-specific map fields when possible.
- [ ] Use named lists for trusted source exclusions.
- [ ] Prefer `matches` over many broad `contains` clauses when regex is available.
- [ ] Split unrelated attack families into separate rules.

---

# 17. Operator-Aware Cloudflare WAF Rule JSON Patterns

## 17.1 XSS Query Rule with `contains`

```json
{
  "description": "Block XSS literal indicators in query string",
  "expression": "lower(http.request.uri.query) contains \"<script\" or lower(http.request.uri.query) contains \"onerror=\" or lower(http.request.uri.query) contains \"javascript:\"",
  "action": "block",
  "enabled": true
}
```

## 17.2 XSS Query Rule with `matches`

```json
{
  "description": "Block XSS regex indicators in query string",
  "expression": "lower(http.request.uri.query) matches r\"(<script|onerror\\s*=|onload\\s*=|javascript:)\"",
  "action": "block",
  "enabled": true
}
```

## 17.3 SQLi Query Rule with `matches`

```json
{
  "description": "Block SQL injection regex indicators in query string",
  "expression": "lower(http.request.uri.query) matches r\"(union\\s+select|or\\s+1\\s*=\\s*1|sleep\\s*\\(|benchmark\\s*\\()\"",
  "action": "block",
  "enabled": true
}
```

## 17.4 Path-Scoped SQLi Rule

```json
{
  "description": "Block SQL injection indicators on API search path",
  "expression": "starts_with(http.request.uri.path, \"/api/search\") and lower(http.request.uri.query) matches r\"(union\\s+select|or\\s+1\\s*=\\s*1|sleep\\s*\\()\"",
  "action": "block",
  "enabled": true
}
```

## 17.5 Trusted Scanner Skip Rule

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

## 17.6 Managed Challenge Suspicious Login Rule

```json
{
  "description": "Managed challenge suspicious login traffic",
  "expression": "http.request.uri.path eq \"/login\" and cf.threat_score gt 20 and not cf.client.bot",
  "action": "managed_challenge",
  "enabled": true
}
```

## 17.7 Grouped XSS and SQLi Rule with Trusted Scanner Exclusion

```json
{
  "description": "Block XSS and SQLi indicators in query string except trusted scanners",
  "expression": "(lower(http.request.uri.query) matches r\"(<script|onerror\\s*=|javascript:|union\\s+select|or\\s+1\\s*=\\s*1|sleep\\s*\\()\" or lower(raw.http.request.uri.query) contains \"%3cscript\" or lower(raw.http.request.uri.query) contains \"union%20select\") and not ip.src in $trusted_security_scanners",
  "action": "block",
  "enabled": true
}
```

> **Warning:** For maintainability and easier debugging, split XSS and SQLi into separate rules when possible.

---

# 18. Operator Decision Matrix for Rule Generation

| Input evidence or requirement | Preferred operator pattern |
|---|---|
| Exact path | `http.request.uri.path eq "/path"` |
| Path prefix | `starts_with(http.request.uri.path, "/api/")` |
| Path suffix | `ends_with(http.request.uri.path, ".php")` |
| Exact host | `http.host eq "example.com"` |
| Multiple hosts | `http.host in {"example.com" "api.example.com"}` |
| Trusted IPs | `ip.src in $trusted_security_scanners` |
| CIDR range | `ip.src in {192.0.2.0/24}` |
| Country set | `ip.src.country in {"CN" "RU"}` |
| Threat score threshold | `cf.threat_score gt 20` |
| WAF attack score threshold | `cf.waf.score.xss lt 30` or `cf.waf.score.sqli lt 30` |
| Stable XSS literal | `lower(field) contains "<script"` |
| XSS event-handler variants | `lower(field) matches r"(onerror\s*=|onload\s*=)"` |
| Stable SQLi literal | `lower(field) contains "union select"` |
| SQLi whitespace variants | `lower(field) matches r"(union\s+select|or\s+1\s*=\s*1)"` |
| Encoded payload | `lower(raw.field) contains "%3cscript"` or `url_decode(field, "r")` |
| Repeated headers | `any(lower(http.request.headers["name"][*])[*] contains "value")` |
| Repeated query parameter values | `any(lower(http.request.uri.args["param"][*])[*] contains "value")` |
| Exclusion | `and not ip.src in $trusted_list` |
| Mixed `and`/`or` | Use parentheses around intended groups |
| Regex unavailable | Use `contains`, `wildcard`, `starts_with()`, `ends_with()`, or split rules |

---

# 19. Common Operator Mistakes and Corrections

## 19.1 Mistake: Uppercase English Operators

Incorrect:

```text
http.host EQ "example.com"
```

Correct:

```text
http.host eq "example.com"
```

## 19.2 Mistake: CIDR with Equality

Incorrect:

```text
ip.src eq 192.0.2.0/24
```

Correct:

```text
ip.src in {192.0.2.0/24}
```

## 19.3 Mistake: `starts_with` as an Operator

Incorrect:

```text
http.request.uri.path starts_with "/api/"
```

Correct:

```text
starts_with(http.request.uri.path, "/api/")
```

## 19.4 Mistake: `ends_with` as an Operator

Incorrect:

```text
http.request.uri.path ends_with ".php"
```

Correct:

```text
ends_with(http.request.uri.path, ".php")
```

## 19.5 Mistake: Missing Parentheses Around Mixed Logic

Incorrect:

```text
starts_with(http.request.uri.path, "/search")
and lower(http.request.uri.query) contains "<script"
or lower(http.request.uri.query) contains "onerror="
```

This can match `onerror=` outside `/search`.

Correct:

```text
starts_with(http.request.uri.path, "/search")
and (
  lower(http.request.uri.query) contains "<script"
  or lower(http.request.uri.query) contains "onerror="
)
```

## 19.6 Mistake: Overbroad SQLi Token

Risky:

```text
lower(http.request.uri.query) contains "select"
```

Better:

```text
lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()"
```

## 19.7 Mistake: Overbroad XSS Token

Risky:

```text
lower(http.request.uri.query) contains "on"
```

Better:

```text
lower(http.request.uri.query) matches r"(<script|onerror\s*=|onload\s*=|javascript:)"
```

## 19.8 Mistake: Array Wildcard Without `any()`

Incorrect:

```text
http.request.headers["user-agent"][*] contains "sqlmap"
```

Correct:

```text
any(lower(http.request.headers["user-agent"][*])[*] contains "sqlmap")
```

## 19.9 Mistake: Wildcard Used for Partial Payload Matching

Risky:

```text
http.request.uri.query wildcard "*<script*"
```

Better:

```text
lower(http.request.uri.query) contains "<script"
```

or:

```text
lower(http.request.uri.query) matches r"(<script|onerror\s*=|javascript:)"
```

## 19.10 Mistake: Regex Without Plan Caveat

Incomplete generation:

```text
lower(http.request.uri.query) matches r"(union\s+select)"
```

Better generation includes:

- expression using `matches`
- note that `matches` requires Business or Enterprise plan
- fallback using `contains`

Fallback:

```text
lower(http.request.uri.query) contains "union select"
```

---

# 20. Complete Example: Operator-Optimized XSS Rule

## 20.1 Scenario

Observed payloads:

```text
<script>alert(1)</script>
<img src=x onerror=alert(1)>
%3Csvg%20onload=alert(1)%3E
```

## 20.2 Recommended Expression

```text
(
  lower(http.request.uri.query) matches r"(<script|onerror\s*=|onload\s*=|javascript:|<svg|<img)"
  or lower(raw.http.request.uri.query) contains "%3cscript"
  or lower(raw.http.request.uri.query) contains "%3csvg"
)
and not ip.src in $trusted_security_scanners
```

## 20.3 Recommended Rule JSON

```json
{
  "description": "Block XSS indicators in query string with encoded payload coverage",
  "expression": "(lower(http.request.uri.query) matches r\"(<script|onerror\\s*=|onload\\s*=|javascript:|<svg|<img)\" or lower(raw.http.request.uri.query) contains \"%3cscript\" or lower(raw.http.request.uri.query) contains \"%3csvg\") and not ip.src in $trusted_security_scanners",
  "action": "block",
  "enabled": true
}
```

## 20.4 Operator Rationale

- `matches` covers multiple XSS indicators with flexible whitespace.
- `contains` on `raw.http.request.uri.query` covers URL-encoded XSS payloads.
- `lower()` handles case-randomized payloads.
- `or` groups alternative XSS indicators.
- `and not ip.src in $trusted_security_scanners` excludes trusted scanner traffic.
- Parentheses ensure the exclusion applies to the whole XSS condition.

## 20.5 Fallback Without Regex

```text
(
  lower(http.request.uri.query) contains "<script"
  or lower(http.request.uri.query) contains "onerror="
  or lower(http.request.uri.query) contains "onload="
  or lower(http.request.uri.query) contains "javascript:"
  or lower(raw.http.request.uri.query) contains "%3cscript"
  or lower(raw.http.request.uri.query) contains "%3csvg"
)
and not ip.src in $trusted_security_scanners
```

---

# 21. Complete Example: Operator-Optimized SQL Injection Rule

## 21.1 Scenario

Observed payloads:

```text
1 UNION SELECT NULL--
1/**/UNION/**/SELECT/**/password
1%27%20OR%201%3D1--
1; SELECT SLEEP(5)
```

## 21.2 Recommended Expression

```text
(
  lower(url_decode(http.request.uri.query, "r")) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema)"
  or lower(raw.http.request.uri.query) contains "union%20select"
  or lower(raw.http.request.uri.query) contains "%27"
)
and not ip.src in $trusted_security_scanners
```

## 21.3 Recommended Rule JSON

```json
{
  "description": "Block SQL injection indicators in query string with encoded payload coverage",
  "expression": "(lower(url_decode(http.request.uri.query, \"r\")) matches r\"(union\\s+select|or\\s+1\\s*=\\s*1|sleep\\s*\\(|benchmark\\s*\\(|information_schema)\" or lower(raw.http.request.uri.query) contains \"union%20select\" or lower(raw.http.request.uri.query) contains \"%27\") and not ip.src in $trusted_security_scanners",
  "action": "block",
  "enabled": true
}
```

## 21.4 Operator Rationale

- `url_decode(..., "r")` normalizes recursively encoded SQLi payloads.
- `lower()` normalizes SQL keyword casing.
- `matches` handles whitespace variants such as `union   select` and `or 1 = 1`.
- `contains` on raw query catches encoded quote and encoded SQL tokens.
- `or` groups alternative SQLi evidence.
- `and not ip.src in $trusted_security_scanners` excludes trusted scanners.
- Parentheses ensure the exclusion applies to the full SQLi condition.

## 21.5 Fallback Without Regex

```text
(
  lower(url_decode(http.request.uri.query, "r")) contains "union select"
  or lower(url_decode(http.request.uri.query, "r")) contains "or 1=1"
  or lower(url_decode(http.request.uri.query, "r")) contains "sleep("
  or lower(url_decode(http.request.uri.query, "r")) contains "benchmark("
  or lower(raw.http.request.uri.query) contains "union%20select"
  or lower(raw.http.request.uri.query) contains "%27"
)
and not ip.src in $trusted_security_scanners
```

---

# 22. Final Rule-Generation Template for Operators

Use this output structure when generating Cloudflare WAF rules based on operator knowledge.

```markdown
## Rule Objective

Describe:
- attack type
- payload location
- bypass technique
- intended action

## Selected Operators

List:
- comparison operators used
- logical operators used
- grouping strategy
- function-style operators such as `starts_with()` / `ends_with()`
- regex or wildcard constraints if used

## Proposed Expression

Provide the Cloudflare Rules language expression.

## Proposed Rule JSON

Provide JSON with:
- description
- expression
- action
- enabled
- action_parameters if needed

## Operator Rationale

Explain:
- why `contains`, `matches`, `in`, `eq`, `gt`, or another operator was selected
- why parentheses are needed
- why `lower()` or `url_decode()` is used before comparison
- whether regex requires Business/Enterprise
- whether wildcard matching is full-field matching
- whether CIDR/list syntax is correct

## False Positive and Tuning Notes

Explain:
- broad operators that may overmatch
- path/host/method/parameter scoping
- trusted IP or verified bot exceptions
- fallback without regex if needed
- whether to split large expressions into multiple rules
```

---

# 23. Final Checklist for Cloudflare Operator Use

- [ ] Use lowercase English operators.
- [ ] Use `eq` for exact scalar matching.
- [ ] Use `contains` for stable literal attack indicators.
- [ ] Use `matches` for flexible XSS/SQLi patterns when plan support exists.
- [ ] Mention `matches` Business/Enterprise requirement.
- [ ] Use raw string syntax for regex when possible.
- [ ] Use `wildcard` only for full-field case-insensitive wildcard matching.
- [ ] Use `strict wildcard` only for full-field case-sensitive wildcard matching.
- [ ] Use `in` for inline sets, named lists, and CIDR ranges.
- [ ] Do not use equality with CIDR ranges.
- [ ] Use `not <field> in <list>` for trusted-source exclusions.
- [ ] Use `starts_with()` and `ends_with()` as functions, not operators.
- [ ] Use `lower()` for case-insensitive matching.
- [ ] Use `url_decode()` or raw fields for encoded payloads.
- [ ] Use `any()` for arrays before applying operators to all values.
- [ ] Use parentheses when mixing `and` and `or`.
- [ ] Recommend Expression Editor or API when grouping symbols are used.
- [ ] Avoid broad single-token rules such as `contains "select"` or `contains "on"`.
- [ ] Split unrelated XSS, SQLi, bot, and exception logic into separate rules when practical.
