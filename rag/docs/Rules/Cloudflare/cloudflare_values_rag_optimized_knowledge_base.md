# Cloudflare Rules Language Values Knowledge Base for WAF Rule Generation
# 1. Cloudflare Rules Language Value Model
## 1.1 Definition

When a request reaches Cloudflare, Cloudflare creates field-value pairs that are evaluated by Rules language expressions. These values exist while the current request is being processed.

A Cloudflare rule expression compares values from fields, transformed fields, computed signals, or static literals and returns a Boolean result:

```text
true
```

or:

```text
false
```

If a WAF custom rule expression evaluates to `true`, the configured action is applied.

General expression pattern:

```text
<field> <comparison_operator> <value>
```

Example:

```text
http.request.uri.path eq "/login"
```

Transformation example:

```text
lower(http.request.uri.query) contains "<script"
```

## 1.2 Value Sources

Cloudflare Rules language expressions can use values from several sources.

| Value source | Definition | Example | Rule-generation use |
|---|---|---|---|
| Primitive value | Value obtained directly from the request or response. | `http.request.uri.path` | Match path, query, headers, cookies, IP, host, method, or body. |
| Derived value | Value produced by transformation, composition, or basic operation. | `lower(http.request.uri.query)` | Normalize case, decode URLs, compute length, transform arrays. |
| Computed value | Value produced by Cloudflare lookup, scoring, or intelligence. | `cf.waf.score`, `cf.threat_score` | Use WAF scores, bot scores, API Shield signals, threat scores. |
| Literal value | Static value written directly in an expression. | `"<script"`, `{203.0.113.10}` | Compare fields against payload indicators, paths, hosts, lists, and constants. |

## 1.3 Value-Aware Rule Generation Principle

When generating WAF rules:

1. Use primitive request fields for payload location.
2. Use derived values for normalization such as `lower()` or `url_decode()`.
3. Use computed values as supporting security signals, not as generic payload evidence.
4. Use literal values for attack indicators, exact paths, hosts, IPs, countries, ASNs, and regex patterns.
5. Choose the value type that matches the operator: string with string operators, IP with IP membership, number with numeric comparison, Boolean as direct Boolean expression.
6. Avoid invalid type combinations, such as comparing an array directly with `contains`.

---

# 2. Literal Values in Rule Expressions

## 2.1 Literal Value Definition

A literal value is a static value written directly inside the expression.

Examples:

```text
"/login"
```

```text
"<script"
```

```text
203.0.113.10
```

```text
{203.0.113.10 198.51.100.0/24}
```

```text
r"(union\s+select|or\s+1\s*=\s*1)"
```

## 2.2 Literal Value Use in WAF Rules

Use literal values for:

- exact paths
- exact hostnames
- HTTP methods
- attack payload indicators
- regex patterns
- inline IP sets
- inline host sets
- country code sets
- ASN sets
- numeric thresholds
- Boolean logic where applicable

## 2.3 Literal Value Examples

Exact path:

```text
http.request.uri.path eq "/admin/login"
```

XSS literal:

```text
lower(http.request.uri.query) contains "<script"
```

SQLi literal:

```text
lower(http.request.uri.query) contains "union select"
```

IP inline set:

```text
ip.src in {203.0.113.10 198.51.100.0/24}
```

Host inline set:

```text
http.host in {"example.com" "api.example.com"}
```

Regex literal:

```text
lower(http.request.uri.query) matches r"(<script|onerror\s*=|javascript:)"
```

## 2.4 Literal Value Generation Rules

- Use quoted strings or raw strings for string and regex literals.
- Use raw string syntax for regex whenever possible.
- Use inline lists for small fixed sets.
- Use named lists for reusable or large sets.
- Do not mix literal value types inside one inline list.
- Keep regex literals compact because each rule supports a limited number of regexes.

---

# 3. String Values

## 3.1 Definition

String values are sequences of bytes enclosed by delimiters.

Cloudflare supports two string literal formats:

| String format | Best use |
|---|---|
| Quoted string syntax | Simple literals such as paths, hosts, and stable payload substrings. |
| Raw string syntax | Regex patterns, strings with many backslashes, or strings with embedded quotes. |

## 3.2 String Values in WAF Rule Generation

Use string values to match:

- URI paths
- URI query strings
- header values
- cookie values
- form values
- hostnames
- User-Agent values
- XSS indicators
- SQL injection indicators
- encoded payload indicators
- regex patterns

## 3.3 Case Sensitivity

String literal evaluation is case-sensitive unless the selected operator is explicitly case-insensitive.

Risky case-sensitive XSS expression:

```text
http.request.uri.query contains "<script"
```

This may miss:

```text
<SCRIPT>
<ScRiPt>
```

Recommended case-normalized expression:

```text
lower(http.request.uri.query) contains "<script"
```

Case-normalized SQLi expression:

```text
lower(http.request.uri.query) contains "union select"
```

Case-normalized header array expression:

```text
any(lower(http.request.headers["user-agent"][*])[*] contains "sqlmap")
```

## 3.4 Case-Insensitive Matching Options

| Option | Example | When to use |
|---|---|---|
| `lower()` normalization | `lower(field) contains "value"` | Best default for XSS/SQLi strings. |
| `wildcard` operator | `http.request.full_uri wildcard "https://*.example.com/*"` | Whole-field wildcard matching. |
| `matches` with regex | `lower(field) matches r"(union\s+select)"` | Flexible pattern matching when available. |
| Multiple `or` sub-expressions | `field eq "a" or field eq "A"` | Simple cases where functions are not desired. |

## 3.5 String Value Checklist

- [ ] Use `lower()` for case-randomized attack payloads.
- [ ] Compare `lower()` output with lowercase literals.
- [ ] Use `contains` for stable literals.
- [ ] Use `matches` for regex and variants.
- [ ] Use raw strings for regex.
- [ ] Avoid broad string literals such as `"select"` or `"on"` without context.

---

# 4. Quoted String Syntax

## 4.1 Definition

Quoted string syntax uses double quote characters:

```text
"string value"
```

Example:

```text
http.host eq "example.com"
```

## 4.2 Escaping in Quoted Strings

In quoted strings, escape these characters:

| Character | Escape sequence |
|---|---|
| Double quote `"` | `\"` |
| Backslash `\` | `\\` |

Example matching a quote inside a value:

```text
http.request.uri.path matches "a\"b"
```

Example matching a string containing `a"#b`:

```text
http.request.uri.path matches "a\"#b"
```

## 4.3 Quoted Strings with Regex

When quoted strings are used with the `matches` operator, regex escaping also applies.

Example regex using quoted string syntax:

```text
http.request.uri.path matches "/api/login\\.aspx$"
```

The dot must be escaped for regex, and the backslash must be escaped for the quoted string.

## 4.4 Double Escaping Problem

Quoted string syntax can require double escaping when a string is both:

- a function parameter
- a regular expression

Example replacement of a backslash with `a` using `regex_replace()`:

```text
regex_replace(http.host, "\\\\", "a")
```

This is difficult to generate reliably. For regex and complex escaping, prefer raw string syntax.

## 4.5 Quoted String Use Cases

Use quoted strings for simple values:

```text
http.request.uri.path eq "/login"
```

```text
http.host eq "api.example.com"
```

```text
http.request.method eq "POST"
```

```text
lower(http.request.uri.query) contains "<script"
```

## 4.6 Quoted String Checklist

- [ ] Use for simple exact strings and simple literals.
- [ ] Escape `"` as `\"`.
- [ ] Escape `\` as `\\`.
- [ ] Avoid quoted strings for complex regex when raw string syntax is clearer.
- [ ] Test regex when using quoted string syntax.

---

# 5. Raw String Syntax

## 5.1 Definition

Raw string syntax avoids normal string escape processing. Characters are interpreted as written until the ending delimiter.

Raw string delimiter form:

```text
r"raw string"
```

Raw string with `#` delimiters:

```text
r#"raw string with " quote"#
```

Raw string with more `#` delimiters:

```text
r##"raw string containing "# sequence"##
```

The starting delimiter has:

```text
r
```

followed by zero or more `#` characters, then:

```text
"
```

The ending delimiter is:

```text
"
```

followed by the same number of `#` characters.

## 5.2 Why Raw Strings Are Preferred for Regex

Raw strings are preferred for regular expressions because escaping rules are simpler and more predictable.

Recommended regex:

```text
http.request.uri.path matches r"/api/login\.aspx$"
```

Equivalent quoted regex:

```text
http.request.uri.path matches "/api/login\\.aspx$"
```

The raw string version is easier to read and less error-prone.

## 5.3 Raw String Examples

String containing a double quote:

```text
http.request.uri.path matches r#"a"b"#
```

String containing `"#`:

```text
http.request.uri.path matches r##"a"#b"##
```

Regex path suffix:

```text
http.request.uri.path matches r"/api/login\.aspx$"
```

XSS regex:

```text
lower(http.request.uri.query) matches r"(<script|onerror\s*=|onload\s*=|javascript:)"
```

SQLi regex:

```text
lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()"
```

## 5.4 Raw Strings Still Need Regex Escaping

Raw strings remove string escaping, but they do not remove regex escaping.

Correct regex dot escape:

```text
http.request.uri.path matches r"/api/login\.aspx$"
```

In this regex:

```text
\.
```

means a literal dot.

Backslash regex example:

```text
regex_replace(http.host, r"\\", "a")
```

## 5.5 Raw String Checklist

- [ ] Use raw strings for regex patterns.
- [ ] Use `r#"..."#` when the pattern contains double quotes.
- [ ] Use more `#` delimiters if the pattern contains `"#`.
- [ ] Still escape regex metacharacters according to regex rules.
- [ ] Prefer raw strings over quoted strings for `matches`.

---

# 6. Regular Expression Values

## 6.1 Definition

Regular expression values are string literals used with the `matches` operator.

Example:

```text
lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1)"
```

Cloudflare regex matching uses the Rust regular expression engine.

## 6.2 Regex Availability

The `matches` operator generally requires Business or Enterprise plan access.

Rule-generation requirement:

> When generating `matches`, include a fallback using `contains` if plan support is unknown.

## 6.3 Regex Count Limit

Each Cloudflare rule supports a maximum of 64 regular expressions.

This limit applies regardless of plan.

## 6.4 Regex Count Reduction Strategies

Use these strategies when a rule approaches regex limits:

| Strategy | Example |
|---|---|
| Replace stable regex with `contains` | `contains "<script"` |
| Use one regex with alternatives | `matches r"(<script|onerror\s*=|javascript:)"` |
| Use `wildcard` or `strict wildcard` for whole-field wildcard matching | `http.request.full_uri wildcard "https://*.example.com/*"` |
| Use `starts_with()` for path prefixes | `starts_with(http.request.uri.path, "/api/")` |
| Use `ends_with()` for suffixes | `ends_with(http.request.uri.path, ".php")` |
| Split into multiple rules | Separate XSS and SQLi rules |

## 6.5 XSS Regex Value

```text
r"(<script|</script|onerror\s*=|onload\s*=|onclick\s*=|javascript:|<svg|<img)"
```

Usage:

```text
lower(http.request.uri.query) matches r"(<script|</script|onerror\s*=|onload\s*=|onclick\s*=|javascript:|<svg|<img)"
```

## 6.6 SQLi Regex Value

```text
r"(union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema)"
```

Usage:

```text
lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema)"
```

## 6.7 Regex Fallback with `contains`

Regex expression:

```text
lower(http.request.uri.query) matches r"(<script|onerror\s*=|javascript:)"
```

Fallback without regex:

```text
lower(http.request.uri.query) contains "<script"
or lower(http.request.uri.query) contains "onerror="
or lower(http.request.uri.query) contains "javascript:"
```

Regex expression:

```text
lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()"
```

Fallback without regex:

```text
lower(http.request.uri.query) contains "union select"
or lower(http.request.uri.query) contains "or 1=1"
or lower(http.request.uri.query) contains "sleep("
```

## 6.8 Regex Checklist

- [ ] Use with `matches`.
- [ ] Prefer raw string syntax.
- [ ] Keep regex Rust-compatible.
- [ ] Mention Business/Enterprise availability.
- [ ] Avoid more than 64 regexes per rule.
- [ ] Provide `contains` fallback when plan support is unknown.
- [ ] Avoid broad regex that matches benign traffic.

---

# 7. Boolean Values

## 7.1 Definition

Boolean values represent `true` or `false`.

Simple expressions using Boolean fields do not require comparison operators or literal values. The field can appear alone.

Example:

```text
ssl
```

This matches requests where `ssl` is `true`.

To match `false`, use `not`:

```text
not ssl
```

## 7.2 Boolean Fields Useful for WAF Rules

| Boolean field | Use |
|---|---|
| `ssl` | Match whether client-to-Cloudflare connection uses SSL/TLS. |
| `cf.client.bot` | Match known good bots or crawlers. |
| `cf.bot_management.verified_bot` | Match verified bots when Bot Management is available. |
| `cf.api_gateway.request_violates_schema` | Match API schema violations when API Shield is available. |
| `cf.api_gateway.fallthrough_detected` | Match unknown or unmanaged API endpoints. |
| `http.request.body.truncated` | Match request body truncation when body inspection is available. |
| `http.request.headers.truncated` | Match request header truncation. |

## 7.3 Boolean Expression Examples

Require SSL:

```text
not ssl
```

Exclude verified bots from challenge:

```text
not cf.client.bot
```

Challenge suspicious login traffic but exclude known good bots:

```text
http.request.uri.path eq "/login"
and cf.threat_score gt 20
and not cf.client.bot
```

Block API schema violations:

```text
starts_with(http.request.uri.path, "/api/")
and cf.api_gateway.request_violates_schema
```

Block truncated body on upload endpoint:

```text
starts_with(http.request.uri.path, "/api/upload")
and http.request.body.truncated
```

## 7.4 Boolean Value Checklist

- [ ] Use Boolean fields directly without `eq true`.
- [ ] Use `not <field>` for false condition.
- [ ] Combine Boolean fields with path, host, method, or security scope.
- [ ] Do not treat Boolean fields as strings.
- [ ] Mention plan/add-on constraints for product-specific Boolean fields.

---

# 8. Arrays

## 8.1 Definition

Cloudflare Rules language includes fields of array type. You cannot define your own arrays. You can only use arrays returned by fields or functions.

Examples of array fields:

- `http.request.headers.names`
- `http.request.headers["user-agent"]`
- `http.request.uri.args["q"]`
- `http.request.uri.args.values`
- `http.request.body.form.values`
- `http.request.body.multipart.values`

## 8.2 Array Indexing

Array indexes start at `0`.

First header name:

```text
http.request.headers.names[0]
```

First User-Agent header value:

```text
http.request.headers["user-agent"][0]
```

Second value of repeated `filter` query argument:

```text
http.request.uri.args["filter"][1]
```

## 8.3 Out-of-Bounds Array Access

Accessing an out-of-bounds array index produces a missing value.

A missing value behaves as follows:

- comparison with a literal evaluates to `false`
- most functions return a missing value when given a missing value, but exact behavior can vary by function

Risky direct index:

```text
http.request.headers["x-token"][0] eq "abc"
```

This is acceptable only when the missing-value behavior is intended.

## 8.4 Array `[*]` Notation

Use `[*]` to evaluate an expression for each array element inside a compatible function.

Correct:

```text
any(http.request.headers.names[*] == "Content-Type")
```

Correct case-insensitive version:

```text
any(lower(http.request.headers.names[*])[*] == "content-type")
```

Invalid:

```text
http.request.headers.names[*] == "Content-Type"
```

Reason:

- Operators do not directly support `[*]`.
- Wrap array-wide comparisons in `any()` or `all()`.

## 8.5 `any()` for Array Values

Use `any()` when any array value should trigger the rule.

Header example:

```text
any(lower(http.request.headers["user-agent"][*])[*] contains "sqlmap")
```

Query parameter example:

```text
any(lower(http.request.uri.args["q"][*])[*] contains "<script")
```

Body form example:

```text
any(lower(http.request.body.form.values[*])[*] contains "<script")
```

## 8.6 `all()` for Array Values

Use `all()` only when every array value must satisfy a condition.

Example:

```text
all(http.request.headers["content-type"][*] == "application/json")
```

For attack detection, `any()` is usually correct because one malicious value is enough.

Risky:

```text
all(lower(http.request.uri.args.values[*])[*] contains "<script")
```

Better:

```text
any(lower(http.request.uri.args.values[*])[*] contains "<script")
```

## 8.7 Array Rules and Constraints

- You cannot define custom arrays.
- You can use arrays returned by fields and functions.
- Operators do not directly support `[*]` outside compatible functions.
- Indexed elements such as `[0]` are allowed.
- Use `any()` for malicious payload detection.
- Use `all()` only when every value must match.
- Use `lower(field[*])[*]` for case-insensitive array matching.
- Use `url_decode(field[*])[*]` when URL-decoded array values are needed.
- Be careful with missing values from absent keys or out-of-bounds indexes.

## 8.8 Array Checklist

- [ ] Use `[0]` only for a specific known element.
- [ ] Use `[*]` with `any()` or `all()` for repeated values.
- [ ] Use `any()` for XSS, SQLi, scanner, and suspicious-value detection.
- [ ] Use `lower(...[*])[*]` for case-insensitive array comparison.
- [ ] Do not compare arrays directly with `contains`, `eq`, or `matches`.

---

# 9. Maps

## 9.1 Definition

A map is a key-value collection. In Cloudflare Rules language, map keys are strings and map values can be a primitive or an array.

Common map fields:

| Map field | Value type | Use |
|---|---|---|
| `http.request.headers` | `Map<Array<String>>` | Access specific request headers. |
| `http.request.uri.args` | `Map<Array<String>>` | Access specific query parameters. |
| `http.request.cookies` | map-like cookie field when available | Access specific cookies. |
| `http.request.body.form` | form body map when available | Access specific form fields. |

## 9.2 Map Access Syntax

Map access pattern:

```text
<MAP_FIELD>[<KEY>]
```

Header map example:

```text
http.request.headers["accept"]
```

Query argument map example:

```text
http.request.uri.args["search"]
```

## 9.3 Header Map Example

If the request has:

```text
Accept: application/json
```

Then:

```text
http.request.headers["accept"]
```

evaluates to:

```text
["application/json"]
```

First value:

```text
http.request.headers["accept"][0]
```

evaluates to:

```text
"application/json"
```

Array-wide check:

```text
any(http.request.headers["accept"][*] == "application/json")
```

## 9.4 Header Name Case Rule

Header map keys should be lowercase.

Correct:

```text
http.request.headers["user-agent"]
```

Risky or incorrect:

```text
http.request.headers["User-Agent"]
```

Recommended scanner detection:

```text
any(lower(http.request.headers["user-agent"][*])[*] contains "sqlmap")
```

## 9.5 Query Argument Map Example

If the URL is:

```text
https://example.com/?filter=waf&filter=botm&filter=cdn
```

Then:

```text
http.request.uri.args["filter"]
```

evaluates to:

```text
["waf", "botm", "cdn"]
```

Second value length:

```text
len(http.request.uri.args["filter"][1])
```

evaluates to:

```text
4
```

Check if all `filter` values have length 3 or 4:

```text
all(len(http.request.uri.args["filter"][*])[*] in {3 4})
```

## 9.6 Map Key Missing Values

Accessing a non-existing map key produces a missing value.

Example absent key:

```text
http.request.uri.args["order"]
```

A comparison involving this missing value evaluates to `false`.

Example key-existence pattern from values semantics:

```text
len(http.request.uri.args["filter"]) >= 0
```

Example key-absence pattern:

```text
not len(http.request.uri.args["order"]) >= 0
```

When available, `has_key()` is often clearer for map-key existence:

```text
has_key(http.request.uri.args, "filter")
```

## 9.7 Parameter-Specific XSS with Map Values

```text
any(lower(http.request.uri.args["q"][*])[*] contains "<script")
or any(lower(http.request.uri.args["q"][*])[*] contains "onerror=")
or any(lower(http.request.uri.args["q"][*])[*] contains "javascript:")
```

Use when the vulnerable parameter is known.

## 9.8 Parameter-Specific SQLi with Map Values

```text
any(lower(http.request.uri.args["id"][*])[*] matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()")
```

Use when SQLi appears in a known parameter such as `id`, `product`, `category`, `search`, or `q`.

## 9.9 Broad Query Argument Value Inspection

Use `http.request.uri.args.values` when the parameter name is unknown but structured argument values should be inspected.

```text
any(lower(http.request.uri.args.values[*])[*] contains "<script")
```

SQLi example:

```text
any(lower(http.request.uri.args.values[*])[*] matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()")
```

## 9.10 Map Checklist

- [ ] Use map access when a specific header, query parameter, cookie, or form field matters.
- [ ] Use lowercase names for `http.request.headers`.
- [ ] Use `[*]` and `any()` for map values that are arrays.
- [ ] Treat absent map keys as missing values.
- [ ] Use `http.request.uri.query` when parameter names are unknown.
- [ ] Use map-specific values to reduce false positives when parameter names are known.

---

# 10. Lists

## 10.1 Definition

Cloudflare lists are reusable named collections of values. A list can be referenced in an expression with:

```text
$<list_name>
```

The expression uses the `in` operator:

```text
<field> in $<list_name>
```

## 10.2 Named List Example

IP list:

```text
ip.src in $office_network
```

Trusted scanner list:

```text
ip.src in $trusted_security_scanners
```

Host list:

```text
http.host in $protected_hosts
```

## 10.3 List Name Rules

List names can include:

- lowercase letters
- numbers
- underscore `_`

Avoid uppercase names and spaces.

Correct:

```text
$trusted_security_scanners
```

Incorrect:

```text
$Trusted Security Scanners
```

## 10.4 Named List Use Cases

Use named lists for:

- trusted scanner IPs
- office networks
- partner IPs
- blocked IPs
- protected hostnames
- country or ASN sets where supported
- long reusable allowlists or blocklists

## 10.5 Trusted Scanner Exclusion

```text
(
  lower(http.request.uri.query) contains "<script"
  or lower(http.request.uri.query) contains "union select"
)
and not ip.src in $trusted_security_scanners
```

## 10.6 Skip Rule with Named List

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

## 10.7 List Checklist

- [ ] Use named lists for reusable values.
- [ ] Use `$<list_name>` syntax.
- [ ] Use `in`, not `eq`, to test list membership.
- [ ] Use `not <field> in $list_name` for exclusions.
- [ ] Keep list names lowercase with underscores.
- [ ] Use named lists instead of huge inline lists when expressions become long.

---

# 11. Inline Lists

## 11.1 Definition

Inline lists directly include multiple literal values inside an expression.

General syntax:

```text
<field> in {<value1> <value2> <value3>}
```

Elements are separated by spaces.

## 11.2 Inline List Value Types

Inline lists can contain:

- strings
- integers
- IP addresses
- IP ranges
- CIDR ranges

All elements in one inline list must have the same data type.

## 11.3 Host Inline List

```text
http.host in {"example.com" "example.net" "api.example.com"}
```

## 11.4 IP Inline List

```text
ip.src in {198.51.100.1 198.51.100.3..198.51.100.7 192.0.2.0/24 2001:0db8::/32}
```

This list contains:

- individual IPv4 address
- explicit IPv4 range
- IPv4 CIDR range
- IPv6 CIDR range

## 11.5 Integer Range Inline List

```text
tcp.dstport in {8000..8009 8080..8089}
```

## 11.6 Country Inline List

```text
ip.src.country in {"CN" "RU" "KP"}
```

Use country logic only when the user asks for geographic policy or when it is a supporting condition. Country is not a primary SQLi or XSS signal.

## 11.7 ASN Inline List

```text
ip.src.asnum in {12345 64512}
```

## 11.8 CIDR Requirement

Use `in` for CIDR ranges.

Correct:

```text
ip.src in {192.0.2.0/24}
```

Incorrect:

```text
ip.src eq 192.0.2.0/24
```

Incorrect:

```text
ip.src == 192.0.2.0/24
```

## 11.9 Inline List Constraints

- Elements are separated by spaces.
- All elements must have the same data type.
- Values must be literal values.
- Duplicate values are allowed.
- IP ranges can be explicit ranges or CIDR ranges.
- Integer ranges use `<start>..<end>`.
- Inline lists are best for small sets.
- Use named lists for large or reusable sets.

## 11.10 Inline List Checklist

- [ ] Use inline lists for small fixed sets.
- [ ] Use named lists for large reusable sets.
- [ ] Do not mix strings and IPs in the same inline list.
- [ ] Use `in` for membership.
- [ ] Use CIDR only inside `in`.
- [ ] Avoid long inline lists that risk the 4,096-character expression limit.

---

# 12. Missing Values

## 12.1 Definition

A missing value is produced when:

- an array index is out of bounds
- a map key does not exist
- a function receives a missing value and returns a missing value
- a field is unavailable in the current context

## 12.2 Missing Value Comparison Behavior

Any comparison in this pattern evaluates to `false` if `<expr>` is missing:

```text
<expr> <op> <literal>
```

Example:

```text
http.request.uri.args["missing"][0] eq "value"
```

If the key or index is missing, the comparison is false.

## 12.3 Missing Value Function Behavior

Function calls where an argument is missing often return a missing value, but behavior can vary by function.

Risky:

```text
lower(http.request.uri.args["q"][0]) contains "<script"
```

If `q` is missing, the expression depends on missing-value propagation.

Safer broad field fallback:

```text
lower(http.request.uri.query) contains "<script"
```

Safer map pattern when parameter is known:

```text
any(lower(http.request.uri.args["q"][*])[*] contains "<script")
```

## 12.4 Map Key Existence

Values documentation shows this key-existence pattern:

```text
len(http.request.uri.args["filter"]) >= 0
```

Key absence:

```text
not len(http.request.uri.args["order"]) >= 0
```

When function support is available and clarity is preferred, use:

```text
has_key(http.request.uri.args, "filter")
```

## 12.5 Missing Value Rule-Generation Guidance

- Do not depend on `[0]` unless the first element is specifically required.
- Prefer `any(...[*])` for repeated or optional values.
- Use full query fields when parameter names are unknown.
- Use key-existence checks when rule logic depends on parameter presence.
- Mention missing-value behavior for optional headers, cookies, and query parameters.

---

# 13. Value Design for XSS Rule Generation

## 13.1 XSS Value Signals

Use XSS value patterns when observed payloads contain:

- `<script`
- `</script`
- `onerror=`
- `onload=`
- `onclick=`
- `<svg`
- `<img`
- `<iframe`
- `javascript:`
- `document.cookie`
- `alert(`
- `%3cscript`
- `%3csvg`
- `javascript%3a`
- HTML entity encoded tags
- mixed-case event handlers
- whitespace-obfuscated event handlers

## 13.2 Stable XSS String Literals

```text
"<script"
```

```text
"onerror="
```

```text
"onload="
```

```text
"javascript:"
```

```text
"%3cscript"
```

```text
"javascript%3a"
```

## 13.3 Query String XSS Values

```text
lower(http.request.uri.query) contains "<script"
or lower(http.request.uri.query) contains "onerror="
or lower(http.request.uri.query) contains "javascript:"
```

Use when:

- XSS appears in the query string
- parameter name is unknown
- stable literals are sufficient

## 13.4 Regex XSS Value

```text
r"(<script|</script|onerror\s*=|onload\s*=|onclick\s*=|javascript:|<svg|<img)"
```

Usage:

```text
lower(http.request.uri.query) matches r"(<script|</script|onerror\s*=|onload\s*=|onclick\s*=|javascript:|<svg|<img)"
```

Use when:

- whitespace or handler variants matter
- regex support is available
- a compact expression is needed

## 13.5 Encoded XSS Values

Raw encoded matching:

```text
lower(raw.http.request.uri.query) contains "%3cscript"
or lower(raw.http.request.uri.query) contains "%3csvg"
or lower(raw.http.request.uri.query) contains "javascript%3a"
or lower(raw.http.request.uri.query) contains "onerror%3d"
```

Decoded matching:

```text
lower(url_decode(http.request.uri.query, "r")) contains "<script"
or lower(url_decode(http.request.uri.query, "r")) contains "onerror="
or lower(url_decode(http.request.uri.query, "r")) contains "javascript:"
```

## 13.6 Parameter-Specific XSS Values

```text
any(lower(http.request.uri.args["q"][*])[*] contains "<script")
or any(lower(http.request.uri.args["q"][*])[*] contains "onerror=")
or any(lower(http.request.uri.args["q"][*])[*] contains "javascript:")
```

Use when:

- vulnerable query parameter is known
- repeated parameter values may exist
- false-positive reduction is important

## 13.7 XSS Rule JSON Example

```json
{
  "description": "Block XSS indicators in query string with encoded payload coverage",
  "expression": "(lower(http.request.uri.query) contains \"<script\" or lower(http.request.uri.query) contains \"onerror=\" or lower(http.request.uri.query) contains \"javascript:\" or lower(raw.http.request.uri.query) contains \"%3cscript\" or lower(raw.http.request.uri.query) contains \"javascript%3a\") and not ip.src in $trusted_security_scanners",
  "action": "block",
  "enabled": true
}
```

## 13.8 XSS Value Checklist

- [ ] Use lowercase string literals with `lower()`.
- [ ] Use raw string regex for `matches`.
- [ ] Use raw encoded values for encoded bypass payloads.
- [ ] Use `url_decode()` for decoded comparisons when supported.
- [ ] Use map values when parameter names are known.
- [ ] Avoid generic values such as `"on"` or `"script"` alone without context.

---

# 14. Value Design for SQL Injection Rule Generation

## 14.1 SQLi Value Signals

Use SQLi value patterns when observed payloads contain:

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
- `union%20select`
- mixed-case SQL keywords
- whitespace-split SQL keywords

## 14.2 Stable SQLi String Literals

```text
"union select"
```

```text
"or 1=1"
```

```text
"sleep("
```

```text
"benchmark("
```

```text
"information_schema"
```

```text
"union%20select"
```

```text
"%27"
```

## 14.3 Query String SQLi Values

```text
lower(http.request.uri.query) contains "union select"
or lower(http.request.uri.query) contains "or 1=1"
or lower(http.request.uri.query) contains "sleep("
or lower(http.request.uri.query) contains "benchmark("
```

Use when:

- SQLi appears in query string
- regex is unavailable
- stable literals are sufficient

## 14.4 Regex SQLi Value

```text
r"(union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema)"
```

Usage:

```text
lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema)"
```

Use when:

- attackers vary whitespace
- SQL tokens may be spaced
- compact pattern is preferable to many `or` clauses

## 14.5 Encoded SQLi Values

Raw encoded matching:

```text
lower(raw.http.request.uri.query) contains "union%20select"
or lower(raw.http.request.uri.query) contains "%27"
or lower(raw.http.request.uri.query) contains "%22"
```

Decoded matching:

```text
lower(url_decode(http.request.uri.query, "r")) contains "union select"
or lower(url_decode(http.request.uri.query, "r")) contains "or 1=1"
or lower(url_decode(http.request.uri.query, "r")) contains "sleep("
```

## 14.6 Parameter-Specific SQLi Values

```text
any(lower(http.request.uri.args["id"][*])[*] matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()")
```

Use when:

- SQLi is known to appear in a specific parameter
- full query scanning may false positive
- repeated parameter values may occur

## 14.7 SQLi Rule JSON Example

```json
{
  "description": "Block SQL injection indicators in query string with encoded payload coverage",
  "expression": "(lower(url_decode(http.request.uri.query, \"r\")) contains \"union select\" or lower(url_decode(http.request.uri.query, \"r\")) contains \"or 1=1\" or lower(url_decode(http.request.uri.query, \"r\")) contains \"sleep(\" or lower(raw.http.request.uri.query) contains \"union%20select\" or lower(raw.http.request.uri.query) contains \"%27\") and not ip.src in $trusted_security_scanners",
  "action": "block",
  "enabled": true
}
```

## 14.8 SQLi Value Checklist

- [ ] Use lowercase SQL literals with `lower()`.
- [ ] Use regex for whitespace variants when `matches` is available.
- [ ] Use raw encoded values for URL-encoded SQLi evidence.
- [ ] Avoid generic single SQL terms such as `"select"` alone.
- [ ] Scope values by parameter, path, host, or method where possible.
- [ ] Add false-positive notes for search boxes, SQL labs, reporting tools, admin panels, and developer APIs.

---

# 15. Values for Encoded Payload and Normalization Handling

## 15.1 Encoded Payload Problem

Attackers may encode XSS or SQLi payloads to bypass literal matching.

Examples:

```text
%3Cscript%3Ealert(1)%3C/script%3E
```

```text
%253Cscript%253Ealert(1)%253C/script%253E
```

```text
1%27%20OR%201%3D1--
```

```text
union%20select
```

## 15.2 Raw Encoded Value Pattern

Use raw fields when the encoded value must be matched as received:

```text
lower(raw.http.request.uri.query) contains "%3cscript"
```

```text
lower(raw.http.request.uri.query) contains "union%20select"
```

## 15.3 Decoded Value Pattern

Use `url_decode()` when decoded comparison is appropriate:

```text
lower(url_decode(http.request.uri.query, "r")) contains "<script"
```

```text
lower(url_decode(http.request.uri.query, "r")) contains "union select"
```

## 15.4 Combined Encoded and Decoded Pattern

```text
lower(http.request.uri.query) contains "<script"
or lower(raw.http.request.uri.query) contains "%3cscript"
or lower(url_decode(http.request.uri.query, "r")) contains "<script"
```

SQLi combined pattern:

```text
lower(http.request.uri.query) contains "union select"
or lower(raw.http.request.uri.query) contains "union%20select"
or lower(url_decode(http.request.uri.query, "r")) contains "union select"
```

## 15.5 Normalization Checklist

- [ ] Use `lower()` for case normalization.
- [ ] Use raw fields for original encoded evidence.
- [ ] Use `url_decode(..., "r")` for recursive decoding when double encoding is observed.
- [ ] Use literal encoded values such as `%3c`, `%27`, and `%22` when matching raw encoded payloads.
- [ ] Avoid relying on one representation if payloads appear in multiple forms.

---

# 16. Values for Path, Host, Method, and Scope

## 16.1 Exact Path Values

```text
"/login"
```

```text
"/admin"
```

```text
"/api/search"
```

Usage:

```text
http.request.uri.path eq "/login"
```

## 16.2 Path Prefix Values

Use with `starts_with()`:

```text
starts_with(http.request.uri.path, "/api/")
```

```text
starts_with(http.request.uri.path, "/search")
```

## 16.3 Path Suffix Values

Use with `ends_with()`:

```text
ends_with(http.request.uri.path, ".php")
```

```text
ends_with(http.request.uri.path, ".aspx")
```

## 16.4 Host Values

```text
http.host eq "example.com"
```

```text
http.host in {"example.com" "api.example.com"}
```

## 16.5 Method Values

```text
http.request.method eq "POST"
```

```text
http.request.method in {"POST" "PUT" "PATCH"}
```

## 16.6 Scope Example

```text
http.host eq "api.example.com"
and starts_with(http.request.uri.path, "/api/search")
and lower(http.request.uri.query) contains "union select"
```

## 16.7 Scope Checklist

- [ ] Use exact values for exact host, path, and method.
- [ ] Use inline lists for small host/method sets.
- [ ] Use `starts_with()` for path prefixes.
- [ ] Use `ends_with()` for path suffixes.
- [ ] Add scope values before broad attack values to reduce false positives.

---

# 17. Values for Trusted Exceptions and Skip Rules

## 17.1 Trusted Exception Value Types

Use these value types for exceptions:

| Exception type | Preferred value form |
|---|---|
| Trusted IPs | Named list or inline IP list |
| Trusted scanner networks | Named IP list |
| Exact trusted path | Quoted string with `eq` |
| Trusted path prefix | Quoted string with `starts_with()` |
| Trusted hostname | Quoted string or host list |
| Verified bot | Boolean field |
| mTLS certificate fingerprint | Exact string or string list |

## 17.2 Trusted IP Named List

```text
ip.src in $trusted_security_scanners
```

## 17.3 Trusted IP Inline List

```text
ip.src in {203.0.113.10 203.0.113.11}
```

## 17.4 Trusted Path and IP

```text
ip.src in $trusted_security_scanners
and starts_with(http.request.uri.path, "/scanner/")
```

## 17.5 Exclusion Inside Attack Rule

```text
(
  lower(http.request.uri.query) contains "<script"
  or lower(http.request.uri.query) contains "union select"
)
and not ip.src in $trusted_security_scanners
```

## 17.6 Skip Rule JSON

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

## 17.7 Exception Value Checklist

- [ ] Prefer IP lists, mTLS, or exact paths for trusted exceptions.
- [ ] Avoid exceptions based only on spoofable headers.
- [ ] Use named lists for reusable trusted sources.
- [ ] Use inline lists for small fixed trusted sets.
- [ ] Place skip rules before block rules they should bypass.
- [ ] Keep exception expressions narrower than enforcement expressions.

---

# 18. Value-Aware False Positive Tuning

## 18.1 High False-Positive Values

| Value pattern | Risk |
|---|---|
| `"select"` | Common benign word and SQL-related content. |
| `"on"` | Too generic for XSS. |
| `"<"` | Too broad; may match benign HTML or encoded content. |
| `"script"` | May match benign code or documentation. |
| `"%27"` alone | Encoded quote may appear in benign content. |
| Long query length alone | Not necessarily malicious. |
| User-Agent value alone | Spoofable. |
| Country list alone | Policy-based, not attack-specific. |

## 18.2 Safer XSS Values

Risky:

```text
lower(http.request.uri.query) contains "on"
```

Better:

```text
lower(http.request.uri.query) contains "onerror="
or lower(http.request.uri.query) contains "onload="
```

Best with regex when available:

```text
lower(http.request.uri.query) matches r"(onerror\s*=|onload\s*=|onclick\s*=)"
```

## 18.3 Safer SQLi Values

Risky:

```text
lower(http.request.uri.query) contains "select"
```

Better:

```text
lower(http.request.uri.query) contains "union select"
```

Best with regex when available:

```text
lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()"
```

## 18.4 False Positive Reduction Values

Use these scoping values:

```text
http.host eq "app.example.com"
```

```text
starts_with(http.request.uri.path, "/search")
```

```text
http.request.method eq "POST"
```

```text
any(lower(http.request.uri.args["q"][*])[*] contains "<script")
```

```text
not ip.src in $trusted_security_scanners
```

## 18.5 Tuning Checklist

- [ ] Replace broad literals with attack-specific values.
- [ ] Use parameter-specific map values when possible.
- [ ] Add path, host, and method values for scope.
- [ ] Use trusted-source named lists for exceptions.
- [ ] Split unrelated value families into separate rules.
- [ ] Validate broad rules with `log` where available before blocking.

---

# 19. Complete Example: Values-Optimized XSS Rule

## 19.1 Scenario

Observed payloads:

```text
<script>alert(1)</script>
<img src=x onerror=alert(1)>
%3Csvg%20onload=alert(1)%3E
```

Target:

- query string payloads
- encoded payload support
- trusted scanner exclusion
- Cloudflare WAF custom rule

## 19.2 Preferred Expression with Regex

```text
(
  lower(http.request.uri.query) matches r"(<script|</script|onerror\s*=|onload\s*=|javascript:|<svg|<img)"
  or lower(raw.http.request.uri.query) contains "%3cscript"
  or lower(raw.http.request.uri.query) contains "%3csvg"
)
and not ip.src in $trusted_security_scanners
```

## 19.3 Rule JSON

```json
{
  "description": "Block XSS indicators in query string with encoded payload coverage",
  "expression": "(lower(http.request.uri.query) matches r\"(<script|</script|onerror\\s*=|onload\\s*=|javascript:|<svg|<img)\" or lower(raw.http.request.uri.query) contains \"%3cscript\" or lower(raw.http.request.uri.query) contains \"%3csvg\") and not ip.src in $trusted_security_scanners",
  "action": "block",
  "enabled": true
}
```

## 19.4 Fallback Without Regex

```text
(
  lower(http.request.uri.query) contains "<script"
  or lower(http.request.uri.query) contains "</script"
  or lower(http.request.uri.query) contains "onerror="
  or lower(http.request.uri.query) contains "onload="
  or lower(http.request.uri.query) contains "javascript:"
  or lower(raw.http.request.uri.query) contains "%3cscript"
  or lower(raw.http.request.uri.query) contains "%3csvg"
)
and not ip.src in $trusted_security_scanners
```

## 19.5 Value Rationale

- String literals such as `"<script"` and `"onerror="` are strong XSS indicators.
- Raw encoded values such as `"%3cscript"` preserve encoded bypass evidence.
- Raw regex syntax keeps the XSS pattern readable.
- `lower()` normalizes case-randomized payloads.
- Named list `$trusted_security_scanners` avoids hardcoding reusable trusted IPs.
- Parentheses ensure the trusted-source exclusion applies to the whole XSS condition.

---

# 20. Complete Example: Values-Optimized SQL Injection Rule

## 20.1 Scenario

Observed payloads:

```text
1 UNION SELECT NULL--
1/**/UNION/**/SELECT/**/password
1%27%20OR%201%3D1--
1; SELECT SLEEP(5)
```

Target:

- query string payloads
- encoded quote support
- recursive URL decoding
- trusted scanner exclusion

## 20.2 Preferred Expression with Regex

```text
(
  lower(url_decode(http.request.uri.query, "r")) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema)"
  or lower(raw.http.request.uri.query) contains "union%20select"
  or lower(raw.http.request.uri.query) contains "%27"
)
and not ip.src in $trusted_security_scanners
```

## 20.3 Rule JSON

```json
{
  "description": "Block SQL injection indicators in query string with encoded payload coverage",
  "expression": "(lower(url_decode(http.request.uri.query, \"r\")) matches r\"(union\\s+select|or\\s+1\\s*=\\s*1|sleep\\s*\\(|benchmark\\s*\\(|information_schema)\" or lower(raw.http.request.uri.query) contains \"union%20select\" or lower(raw.http.request.uri.query) contains \"%27\") and not ip.src in $trusted_security_scanners",
  "action": "block",
  "enabled": true
}
```

## 20.4 Fallback Without Regex

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

## 20.5 Value Rationale

- `"union select"`, `"or 1=1"`, and `"sleep("` are SQLi-specific values.
- Raw encoded values such as `"union%20select"` and `"%27"` cover URL-encoded bypass evidence.
- `url_decode(..., "r")` handles recursively encoded payloads.
- `lower()` normalizes mixed-case SQL keywords.
- Regex raw string syntax captures whitespace variants.
- Trusted scanner list exclusion reduces false positives during testing.

---

# 21. Common Value Syntax Mistakes and Corrections

## 21.1 Mistake: Using Quoted Regex with Insufficient Escaping

Risky:

```text
http.request.uri.path matches "/api/login\.aspx$"
```

Better:

```text
http.request.uri.path matches r"/api/login\.aspx$"
```

## 21.2 Mistake: Missing Case Normalization

Risky:

```text
http.request.uri.query contains "<script"
```

Better:

```text
lower(http.request.uri.query) contains "<script"
```

## 21.3 Mistake: Comparing Array Directly

Invalid:

```text
http.request.headers.names[*] == "Content-Type"
```

Correct:

```text
any(http.request.headers.names[*] == "Content-Type")
```

## 21.4 Mistake: Missing `[*]` After Array Transformation

Risky or invalid:

```text
any(lower(http.request.headers.names[*]) == "content-type")
```

Correct:

```text
any(lower(http.request.headers.names[*])[*] == "content-type")
```

## 21.5 Mistake: Header Map Key Case

Risky:

```text
http.request.headers["User-Agent"][0] contains "sqlmap"
```

Better:

```text
any(lower(http.request.headers["user-agent"][*])[*] contains "sqlmap")
```

## 21.6 Mistake: CIDR Outside `in`

Incorrect:

```text
ip.src eq 192.0.2.0/24
```

Correct:

```text
ip.src in {192.0.2.0/24}
```

## 21.7 Mistake: Mixed Inline List Types

Incorrect:

```text
ip.src in {203.0.113.10 "api.example.com"}
```

Correct IP list:

```text
ip.src in {203.0.113.10 198.51.100.0/24}
```

Correct host list:

```text
http.host in {"example.com" "api.example.com"}
```

## 21.8 Mistake: Boolean Field Compared as String

Incorrect:

```text
ssl eq "true"
```

Correct:

```text
ssl
```

Negated:

```text
not ssl
```

## 21.9 Mistake: Overbroad Value

Risky:

```text
lower(http.request.uri.query) contains "select"
```

Better:

```text
lower(http.request.uri.query) contains "union select"
or lower(http.request.uri.query) contains "or 1=1"
```

Best with regex when available:

```text
lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()"
```

---

# 22. Value Decision Matrix for Rule Generation

| Input evidence or requirement | Preferred value design |
|---|---|
| XSS in unknown query parameter | Lowercased full query string with XSS literals. |
| XSS in known parameter | Map value array with `any(lower(http.request.uri.args["param"][*])[*] ...)`. |
| Encoded XSS | Raw encoded string values such as `%3cscript`, plus optional `url_decode()`. |
| SQLi in unknown query parameter | Lowercased full query string with SQLi literals or raw regex. |
| SQLi in known parameter | Parameter-specific map values with regex or literals. |
| SQLi whitespace variants | Raw string regex with `\s+` and `\s*`. |
| Case-randomized payload | `lower()` derived value plus lowercase literal values. |
| Header payload | Header map value array with lowercase header key and `any()`. |
| Cookie payload | `http.cookie` string or cookie map values if available. |
| Body form payload | Body form values array with `any()`, if supported. |
| Trusted scanners | Named IP list or inline IP list. |
| Multiple hosts | String inline list. |
| CIDR ranges | IP inline list with `in`. |
| Boolean condition | Boolean field directly or `not <field>`. |
| Large reusable values | Named list. |
| Regex unavailable | `contains` literals, `starts_with()`, `ends_with()`, or split rules. |
| Expression too long | Named lists, fewer literals, compact regex, split rules. |

---

# 23. Final Template for Value-Aware Cloudflare WAF Rule Generation

Use this output structure when generating Cloudflare WAF rules based on value semantics.

```markdown
## Rule Objective

Describe:
- attack type
- observed payload values
- payload location
- intended Cloudflare action

## Selected Values

List:
- primitive request fields used
- derived values such as `lower()` or `url_decode()`
- literal values
- raw encoded values
- regex raw string values
- named lists or inline lists
- Boolean/computed values if used

## Proposed Expression

Provide the Cloudflare Rules language expression.

## Proposed Rule JSON

Provide JSON with:
- description
- expression
- action
- enabled
- action_parameters if needed

## Value Rationale

Explain:
- why each literal value was selected
- why raw string syntax was used for regex
- why `lower()` or `url_decode()` was used
- why arrays/maps require `any()` and `[*]`
- why named or inline lists were used
- how missing values affect optional headers/parameters

## False Positive and Tuning Notes

Explain:
- broad values that may overmatch
- safer replacement values
- path/host/method/parameter scoping
- trusted list exceptions
- fallback without regex if needed
```

---

# 24. Final Checklist for Cloudflare Values

- [ ] Use the correct value type for the selected operator.
- [ ] Use quoted strings for simple string literals.
- [ ] Use raw strings for regex literals.
- [ ] Escape quoted string values correctly.
- [ ] Use `lower()` for case-insensitive XSS and SQLi matching.
- [ ] Use lowercase literals after `lower()`.
- [ ] Use `matches` only when regex support is acceptable.
- [ ] Mention the 64-regex-per-rule limit.
- [ ] Provide `contains` fallback when regex availability is unknown.
- [ ] Use Boolean fields directly, such as `ssl` or `not ssl`.
- [ ] Do not compare Boolean fields to string values.
- [ ] Use `any()` for array-wide matching.
- [ ] Use `all()` only when every value must match.
- [ ] Do not compare arrays directly with operators.
- [ ] Use `lower(field[*])[*]` for case-insensitive array values.
- [ ] Use map access for known headers, query arguments, cookies, or form fields.
- [ ] Treat missing map keys and out-of-bounds array indexes as missing values.
- [ ] Use `in` for inline lists and named lists.
- [ ] Use `in` for CIDR ranges.
- [ ] Do not mix data types inside inline lists.
- [ ] Use named lists for long reusable value sets.
- [ ] Use raw encoded values and/or `url_decode()` for encoded payloads.
- [ ] Avoid broad literals such as `"select"`, `"on"`, and `"<"` without additional context.
- [ ] Scope broad value checks by path, host, method, parameter, or trusted source.
