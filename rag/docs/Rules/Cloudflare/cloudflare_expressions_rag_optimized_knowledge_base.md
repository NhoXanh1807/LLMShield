# Cloudflare Ruleset Engine Expression Knowledge Base for WAF Rule Generation
# 1. Cloudflare Rules Language Overview
## 1.1 Definition

The Cloudflare Rules language is the expression language used by the Cloudflare Ruleset Engine. It is based on a field/operator/value model similar to Wireshark display filters.

A Cloudflare rule expression evaluates request, response, computed, or derived fields and returns a Boolean result:

- `true`: the rule matches the request or response.
- `false`: the rule does not match.

A Cloudflare WAF custom rule uses the expression to decide whether its action should apply to the request.

## 1.2 Rule Expression Components

A Cloudflare expression can contain:

| Component | Purpose | Example |
|---|---|---|
| Field | Selects request, response, computed, dynamic, or raw data | `http.request.uri.query` |
| Comparison operator | Compares a field value to a literal, set, list, or pattern | `contains`, `eq`, `matches`, `in` |
| Value | Literal or structured value used for comparison | `"union select"`, `{203.0.113.10}` |
| Logical operator | Combines expressions | `and`, `or`, `not`, `xor` |
| Function | Transforms or validates values | `lower()`, `any()`, `all()` |
| Grouping symbol | Controls precedence | `( ... )` |

## 1.3 Simple and Compound Expressions

Cloudflare supports two main expression types:

| Expression type | Description | General form |
|---|---|---|
| Simple expression | Compares a request value to a defined value | `<field> <comparison_operator> <value>` |
| Compound expression | Combines multiple expressions with logical operators | `<expression> <logical_operator> <expression>` |

Example simple expression:

```text
http.request.uri.path matches "/autodiscover\\.(xml|src)$"
```

Example compound expression:

```text
http.host eq "www.example.com" and not cf.edge.server_port in {80 443}
```

## 1.4 Expression Length Limit

The maximum length of a Cloudflare rule expression is **4,096 characters**.

This limit applies whether the expression is created with:

- Expression Builder.
- Expression Editor.
- API.

Rule-generation guidance:

- Keep generated expressions compact.
- Avoid repeating many near-duplicate `or` clauses.
- Prefer sets, lists, `matches`, `contains`, and scoped conditions when appropriate.
- Use multiple rules or a ruleset when a single expression would exceed 4,096 characters.
- Avoid embedding very large regex patterns in one expression.

---

# 2. Simple Expressions

## 2.1 Definition

A simple expression compares a value extracted from an HTTP request or other Cloudflare field to a literal, list, regular expression, or another supported value.

General syntax:

```text
<field> <comparison_operator> <value>
```

## 2.2 Simple Expression Examples for WAF Rule Generation

### Match a specific URI path

```text
http.request.uri.path eq "/login"
```

Use when the rule must apply only to an exact path.

### Match a URI path prefix

```text
starts_with(http.request.uri.path, "/api/")
```

Use when the rule should apply to all endpoints under a path prefix.

### Match XSS indicators in the query string

```text
lower(http.request.uri.query) contains "<script"
```

Use when the payload is a stable literal indicator and case normalization is needed.

### Match SQL injection indicators in the query string

```text
lower(http.request.uri.query) contains "union select"
```

Use when the SQLi token sequence is expected to appear literally after lowercasing.

### Match an IP allowlist or exception

```text
ip.src in {203.0.113.10 203.0.113.11}
```

Use for trusted source exceptions, skip rules, or scoped security policies.

### Match a host

```text
http.host eq "example.com"
```

Use to scope a rule to a specific hostname.

## 2.3 Simple Expression Generation Rules

When generating simple expressions:

- Choose the field that corresponds to the observed payload location.
- Use `lower()` when comparing strings that may vary in case.
- Use `contains` for stable literal indicators.
- Use `matches` for variable or regex-based patterns.
- Use `in` for inline sets, IP ranges, and named lists.
- Use exact equality `eq` for exact host, path, method, or known header values.
- Avoid overly broad expressions such as `http.request.uri.query contains "select"` unless scoped by path, host, method, or additional SQLi context.

---

# 3. Compound Expressions

## 3.1 Definition

A compound expression combines two or more expressions using logical operators. Compound expressions allow targeted WAF rules that combine attack indicators with scope conditions.

General syntax:

```text
<expression> <logical_operator> <expression>
```

Example:

```text
http.host eq "example.com" and lower(http.request.uri.query) contains "<script"
```

## 3.2 Logical Operators

| Operator | C-like notation | Meaning | Precedence |
|---|---|---|---:|
| `not` | `!` | Negates an expression | 1 |
| `and` | `&&` | Both expressions must be true | 2 |
| `xor` | `^^` | Exactly one expression must be true | 3 |
| `or` | `||` | At least one expression must be true | 4 |

Lower precedence number means the operator is evaluated earlier.

## 3.3 Grouping Symbols

Use parentheses to make evaluation explicit:

```text
(http.request.uri.path contains "/login" or http.request.uri.path contains "/admin")
and not ip.src in {203.0.113.10 203.0.113.11}
```

Grouping is important because `and` has higher precedence than `or`.

Ambiguous expression:

```text
Expression1 and Expression2 or Expression3
```

Clear expression:

```text
(Expression1 and Expression2) or Expression3
```

Alternative clear expression:

```text
Expression1 and (Expression2 or Expression3)
```

## 3.4 Grouping Support Constraint

Grouping symbols are supported in:

- Expression Editor.
- Cloudflare API.

Grouping symbols are not supported in the visual Expression Builder.

Generation rule:

> **Warning:** If a generated expression uses parentheses, it should be deployed through the Expression Editor or API, not through the visual Expression Builder.

## 3.5 Compound Expression Patterns for WAF Rules

### Scope XSS detection to a path

```text
http.request.uri.path starts_with "/search"
and lower(http.request.uri.query) matches r"(<script|onerror\s*=|onload\s*=|javascript:)"
```

### Scope SQLi detection to API search endpoints

```text
starts_with(http.request.uri.path, "/api/search")
and lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\()"
```

### Exclude trusted IPs from a block expression

```text
(
  lower(http.request.uri.query) contains "<script"
  or lower(http.request.uri.query) contains "onerror="
)
and not ip.src in {203.0.113.10 203.0.113.11}
```

### Match sensitive paths and suspicious score

```text
(http.request.uri.path eq "/login" or http.request.uri.path eq "/admin")
and cf.threat_score gt 20
```

## 3.6 Compound Expression Generation Rules

When generating compound expressions:

- Use parentheses for every non-trivial `and`/`or` combination.
- Put scope conditions first when possible: host, path, method, IP, or country.
- Put attack indicators after the scope condition.
- Use `not` only for clear exclusions.
- Avoid long ungrouped expressions.
- Use one semantic objective per expression when possible.

---

# 4. Fields for Cloudflare WAF Rule Expressions

## 4.1 Definition

Fields specify properties associated with HTTP requests, responses, dynamic computations, raw request values, or Cloudflare intelligence. A rule expression evaluates fields to decide whether a request matches.

Common field categories:

| Field category | Description |
|---|---|
| Request fields | Basic properties of incoming requests, including URI, host, method, headers, cookies, body, and user agent. |
| Dynamic fields | Computed or threat-intelligence-related values. |
| Response fields | Response header and status properties in response phases. |
| Raw fields | Immutable raw request values preserved for later evaluation. |
| URI argument fields | Query parameter maps, names, and values. |
| Header fields | HTTP request header maps and names. |
| Body fields | Request body values, form values, MIME information, body size, and truncation state when available. |

## 4.2 Request Fields Most Useful for WAF Rule Generation

| Field | Type / behavior | Use in generated WAF expressions |
|---|---|---|
| `http.host` | Hostname string | Scope rule to a hostname. |
| `http.request.full_uri` | Full request URI | Broad URI matching when path and query both matter. |
| `http.request.uri` | URI object or URI-related value depending on context | General URI matching. |
| `http.request.uri.path` | URI path string | Scope by endpoint path, route, admin path, login path, API path. |
| `http.request.uri.query` | Entire query string without `?` | Detect reflected XSS, SQLi, redirect payloads, parameter-based attacks. |
| `raw.http.request.uri.query` | Raw query string without transformations | Detect encoded or unmodified query payloads when normalized field behavior is not desired. |
| `http.request.method` | HTTP method | Scope to `GET`, `POST`, `PUT`, etc. |
| `http.user_agent` | User-Agent string | Detect suspicious user agents or scope bot-like requests. |
| `http.referer` | Referer string | Scope or detect suspicious referrers. |
| `http.cookie` | Cookie header string | Match cookie-based payloads at coarse granularity. |
| `http.request.headers` | Map of header names to arrays of header values | Match specific request header values. |
| `http.request.headers.names` | Array of request header names | Check whether a header exists. |
| `ip.src` | Source IP address | IP allowlists, blocklists, trusted sources, exception rules. |
| `ip.src.country` | Source country code | Country-based scoping. |
| `ip.src.asnum` | Source ASN | ASN-based scoping. |
| `cf.threat_score` | Cloudflare computed threat score | Scope challenge rules to suspicious traffic. |
| `cf.client.bot` | Known verified bot indicator | Avoid challenging or blocking verified good bots. |
| `ssl` | Boolean indicating encrypted client-to-Cloudflare connection | Scope expressions by HTTPS usage. |

## 4.3 URI Query Fields

### Entire query string

```text
http.request.uri.query
```

This field contains the entire query string without the `?`.

Example:

```text
lower(http.request.uri.query) contains "union select"
```

Use for:

- reflected XSS in query strings
- SQLi in query strings
- redirect parameter abuse
- broad query-string inspection

### Raw query string

```text
raw.http.request.uri.query
```

This field preserves the original query value for later evaluations and is not affected by actions of previously matched rules.

Use raw fields when:

- exact original encoding matters
- you need to match encoded payloads as they arrived
- prior transformations or rewrite actions should not affect evaluation

Example:

```text
lower(raw.http.request.uri.query) contains "%3cscript"
```

## 4.4 URI Argument Map Fields

`http.request.uri.args` is a map from query parameter name to an array of values.

Use it when you need parameter-specific matching.

Example:

```text
any(lower(http.request.uri.args["search"][*]) contains "<script")
```

Use `http.request.uri.args` when:

- the vulnerable parameter name is known
- false positives are high with full query-string matching
- only one parameter should be inspected
- a repeated parameter may contain multiple values

Example for SQLi in a known `id` parameter:

```text
any(lower(http.request.uri.args["id"][*]) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()")
```

Generation rule:

- Use `http.request.uri.query` when parameter names are unknown.
- Use `http.request.uri.args["name"][*]` with `any()` when a vulnerable parameter name is known.
- Use lowercase parameter names only when the application and Cloudflare field behavior make that appropriate. Query argument names retain their original case.

## 4.5 Header Map Fields

`http.request.headers` is a map from lowercase header names to arrays of values.

Example:

```text
any(lower(http.request.headers["user-agent"][*]) contains "sqlmap")
```

Use header maps for:

- User-Agent based scanning indicators
- Referer-based payloads
- API keys or custom header scoping
- trusted client headers, when reliable
- content-type checks

Important header access rules:

- Header names are accessed in lowercase.
- Repeated headers are represented as arrays.
- Use `[0]` for a specific first header value.
- Use `[*]` with `any()` to evaluate all values.

Example: match JSON requests

```text
any(http.request.headers["content-type"][*] contains "application/json")
```

Example: match XSS indicator in a custom header

```text
any(lower(http.request.headers["x-search"][*]) contains "<script")
```

## 4.6 Body Fields

Cloudflare request body fields may require specific plan or add-on support. Body inspection availability depends on the Cloudflare product and plan.

Generation rules:

- Do not assume request body fields are available unless the product and plan support them.
- Prefer URI query or URI argument fields for query-based reflected attacks.
- Use body fields only when payloads appear in POST form data, JSON payloads, or API bodies and support is available.
- Include fallback guidance if body fields are unavailable.

Common body-oriented expression pattern:

```text
http.request.body.raw contains "payload"
```

Form value pattern using arrays:

```text
any(lower(http.request.body.form.values[*]) contains "<script")
```

Encoded form value pattern:

```text
any(url_decode(http.request.body.form.values[*])[*] contains "<script")
```

> **Warning:** Body inspection has size and availability constraints. Generated body-inspection expressions should mention plan/product requirements and test behavior before enforcement.

## 4.7 Field Selection Matrix

| Payload location | Preferred field | Example |
|---|---|---|
| Query string, unknown parameter | `http.request.uri.query` | `lower(http.request.uri.query) contains "<script"` |
| Query string, exact parameter known | `http.request.uri.args["param"][*]` | `any(lower(http.request.uri.args["q"][*]) contains "<script")` |
| URI path | `http.request.uri.path` | `lower(http.request.uri.path) contains "../"` |
| Hostname | `http.host` | `http.host eq "example.com"` |
| Source IP | `ip.src` | `ip.src in {203.0.113.10}` |
| Country | `ip.src.country` | `ip.src.country in {"CN" "RU"}` |
| ASN | `ip.src.asnum` | `ip.src.asnum in {12345 64512}` |
| User-Agent | `http.user_agent` or `http.request.headers["user-agent"]` | `lower(http.user_agent) contains "sqlmap"` |
| Specific header | `http.request.headers["header-name"][*]` | `any(lower(http.request.headers["x-test"][*]) contains "<script")` |
| Cookie string | `http.cookie` | `lower(http.cookie) contains "payload="` |
| Request body | `http.request.body.*` | `any(lower(http.request.body.form.values[*]) contains "<script")` |
| Raw encoded query | `raw.http.request.uri.query` | `lower(raw.http.request.uri.query) contains "%3cscript"` |

---

# 5. Comparison Operators

## 5.1 Definition

Comparison operators define how a field value must relate to a specified value for a simple expression to evaluate to `true`.

General pattern:

```text
<field> <comparison_operator> <value>
```

## 5.2 Common Comparison Operators

| Operator | C-like notation | Use in WAF rule generation |
|---|---|---|
| `eq` | `==` | Exact equality for host, path, method, country, known values. |
| `ne` | `!=` | Exclusions when exact value should not match. |
| `contains` | N/A | Literal substring matching for stable attack indicators. |
| `matches` | `~` | Regular expression matching for flexible attack patterns. |
| `in` | N/A | Membership in inline sets or named lists. |
| `lt` | `<` | Numeric less-than comparison. |
| `le` | `<=` | Numeric less-than-or-equal comparison. |
| `gt` | `>` | Numeric greater-than comparison, such as threat score thresholds. |
| `ge` | `>=` | Numeric greater-than-or-equal comparison. |
| `wildcard` | N/A | Case-insensitive wildcard matching where supported. |
| `strict wildcard` | N/A | More controlled wildcard matching where supported. |

## 5.3 Lowercase Requirement for English Operators

English notation operators such as `eq`, `lt`, `gt`, `contains`, `matches`, `in`, `not`, `and`, and `or` must be lowercase.

Correct:

```text
http.host eq "example.com"
```

Incorrect:

```text
http.host EQ "example.com"
```

## 5.4 Case Sensitivity in String Comparisons

String comparisons are case-sensitive by default.

For case-insensitive matching, use one of these patterns:

### Recommended for literal indicators

```text
lower(http.request.uri.query) contains "<script"
```

### Recommended for regex patterns

```text
lower(http.request.uri.query) matches r"(<script|onerror\s*=|javascript:)"
```

### Alternative when regex is unavailable

```text
lower(http.request.uri.query) contains "<script"
or lower(http.request.uri.query) contains "onerror="
or lower(http.request.uri.query) contains "javascript:"
```

## 5.5 `contains` Operator

Use `contains` for stable literal substrings.

Example:

```text
lower(http.request.uri.query) contains "union select"
```

Good use cases:

- `<script`
- `onerror=`
- `javascript:`
- `union select`
- `or 1=1`
- `sleep(`
- `benchmark(`
- `%3cscript`

Avoid `contains` when:

- token spacing varies significantly
- attackers insert comments or whitespace
- a regex would express the pattern more reliably
- the literal is too broad, such as `"select"` alone

## 5.6 `matches` Operator

Use `matches` for regular expression matching.

Example XSS regex:

```text
lower(http.request.uri.query) matches r"(<script|onerror\s*=|onload\s*=|javascript:)"
```

Example SQLi regex:

```text
lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\()"
```

Important constraints:

- Access to `matches` requires an eligible Cloudflare plan, commonly Business or Enterprise.
- Regex matching uses the Rust regular expression engine.
- Each rule supports a limited number of regular expressions.
- Use raw string syntax for regex when possible.

Generation rule:

> If `matches` may not be available, provide an alternative using `contains`, multiple sub-expressions, or wildcard matching.

## 5.7 `in` Operator

Use `in` for membership in inline sets or named lists.

Example IP inline set:

```text
ip.src in {203.0.113.10 203.0.113.11 198.51.100.0/24}
```

Example hostname inline set:

```text
http.host in {"example.com" "api.example.com"}
```

Example named list:

```text
ip.src in $office_network
```

Generation rules:

- Use `in` for IP allowlists and blocklists.
- Use `in` for host allowlists.
- Use `not <field> in <set>` for exclusions.
- Do not use equality with CIDR ranges. Use `in`.

## 5.8 Starts With and Ends With

In hand-written expressions, `starts_with()` and `ends_with()` are functions, not operators.

Correct:

```text
starts_with(http.request.uri.path, "/api/")
```

Correct:

```text
ends_with(http.request.uri.path, ".php")
```

Incorrect:

```text
http.request.uri.path starts_with "/api/"
```

Use `starts_with()` for path scoping:

```text
starts_with(http.request.uri.path, "/admin/")
```

Use `ends_with()` for extension scoping:

```text
ends_with(http.request.uri.path, ".php")
```

---

# 6. Values, Strings, Regex Literals, Lists, Arrays, and Maps

## 6.1 Definition

Values in Cloudflare expressions can come from:

- direct request fields
- derived values from functions
- computed Cloudflare intelligence fields
- static literals written in the expression

## 6.2 String Values

String values can be written using quoted string syntax or raw string syntax.

### Quoted string syntax

Quoted strings use double quotes:

```text
http.host eq "example.com"
```

Inside quoted strings, escape `"` and `\`:

```text
http.request.uri.path matches "/autodiscover\\.(xml|src)$"
```

### Raw string syntax

Raw strings are recommended for regex expressions because they reduce escaping complexity.

Example:

```text
http.request.uri.path matches r"/api/login\.aspx$"
```

Raw string with embedded quote:

```text
http.request.uri.path matches r#"a"b"#
```

Raw strings use:

- starting delimiter: `r"` or `r#"` or more `#` symbols
- ending delimiter: matching `"` plus the same number of `#` symbols

Generation rule:

> Prefer raw string syntax for regex generated in Cloudflare expressions.

## 6.3 Regular Expression Values

Use regex values with `matches`.

Example:

```text
lower(http.request.uri.query) matches r"(<script|onerror\s*=|javascript:)"
```

Regex generation guidance:

- Use raw strings where possible.
- Keep regex compact.
- Use grouping for alternatives.
- Avoid catastrophic or overly broad patterns.
- Use `contains` when a stable literal is enough.
- Mention plan requirements if using `matches`.

## 6.4 Boolean Values

Boolean fields can be used directly.

Example:

```text
ssl
```

This matches requests where `ssl` is `true`.

Negated boolean:

```text
not ssl
```

Example with verified bots:

```text
not cf.client.bot
```

## 6.5 Inline Lists

Inline lists allow values to be directly included in an expression with the `in` operator.

Example host list:

```text
http.host in {"example.com" "api.example.com"}
```

Example IP list:

```text
ip.src in {198.51.100.1 198.51.100.3..198.51.100.7 192.0.2.0/24 2001:db8::/32}
```

Example port list:

```text
tcp.dstport in {8000..8009 8080..8089}
```

Inline list rules:

- Elements are separated by spaces.
- Elements can be strings, integers, IP addresses, IP ranges, or CIDR ranges.
- All elements must be the same data type.
- Duplicate values are allowed.
- IP ranges can be explicit ranges or CIDR ranges.
- Integer ranges use `<start>..<end>`.

## 6.6 Named Lists

Named lists are reusable Cloudflare lists referenced with `$<list_name>`.

Example:

```text
ip.src in $office_network
```

Named list rules:

- List names can include lowercase letters, numbers, and underscores.
- Use named lists for maintainable IP allowlists, IP blocklists, host lists, ASN lists, and other reusable sets.
- Use named lists when an inline list would make the expression too long.

## 6.7 Arrays

Some fields return arrays. Array indexing starts at `0`.

Example first header value:

```text
http.request.headers["accept"][0]
```

Use `[*]` to evaluate all array values inside supported functions.

Example:

```text
any(http.request.headers["accept"][*] == "application/json")
```

Array rules:

- You cannot define your own arrays.
- Arrays come from fields or functions.
- Operators do not directly support `[*]` outside enclosing functions.
- Use `any()` or `all()` for array-wide checks.
- Out-of-bounds array access produces a missing value.

Invalid:

```text
http.request.headers.names[*] == "content-type"
```

Valid:

```text
any(http.request.headers.names[*] == "content-type")
```

## 6.8 Maps

Some fields are maps. A map stores key-value pairs.

Map access syntax:

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

If a map value is an array, use `[0]` for a specific element or `[*]` with `any()` or `all()`.

Example:

```text
any(http.request.uri.args["search"][*] == "red+apples")
```

Example case-normalized query argument match:

```text
any(lower(http.request.uri.args["search"][*]) contains "<script")
```

## 6.9 Missing Values

When a field, map key, or array element is missing:

- comparisons with missing values evaluate to `false`
- most functions return missing values when given missing values, depending on the function

Generation guidance:

- Guard optional fields when necessary.
- Use `any()` over repeated values.
- Prefer broad fields like `http.request.uri.query` when map-key existence is uncertain.
- Use parameter-specific maps only when the parameter name is known.

---

# 7. Functions for Cloudflare WAF Expressions

## 7.1 Definition

Functions manipulate, transform, validate, or evaluate values in expressions. Functions are useful for case normalization, array evaluation, string manipulation, URI decoding, and robust WAF matching.

## 7.2 `lower()`

`lower()` converts uppercase ASCII bytes in a string to lowercase.

Example:

```text
lower(http.host) == "www.example.com"
```

Use `lower()` for:

- case-insensitive host matching
- case-insensitive path matching
- case-insensitive query matching
- XSS indicators with mixed casing
- SQLi indicators with mixed casing

Example XSS:

```text
lower(http.request.uri.query) contains "onerror="
```

Example SQLi:

```text
lower(http.request.uri.query) contains "union select"
```

## 7.3 `any()`

`any()` returns `true` when any Boolean value in an array is true.

Use it with arrays such as headers, query argument values, or form values.

Example header value match:

```text
any(lower(http.request.headers["user-agent"][*]) contains "sqlmap")
```

Example query argument XSS:

```text
any(lower(http.request.uri.args["q"][*]) contains "<script")
```

Example decoded body form values:

```text
any(url_decode(http.request.body.form.values[*])[*] contains "an xss attack")
```

## 7.4 `all()`

`all()` returns `true` when all Boolean values in an array are true.

Example:

```text
all(http.request.headers["content-type"][*] == "application/json")
```

Use `all()` cautiously. Most WAF detection expressions should use `any()` because a single malicious repeated value is enough to match.

## 7.5 `starts_with()`

Use `starts_with()` for path, host, or string prefix checks.

Example:

```text
starts_with(http.request.uri.path, "/api/")
```

Use cases:

- scope custom WAF rules to `/api/`
- scope admin rules to `/admin/`
- scope login rules to `/login`
- scope skip exceptions to known safe paths

## 7.6 `ends_with()`

Use `ends_with()` for suffix checks.

Example:

```text
ends_with(http.request.uri.path, ".php")
```

Use cases:

- apply rules to PHP endpoints
- apply rules to script-like paths
- avoid applying rules to static assets

## 7.7 `url_decode()`

Use `url_decode()` where supported to decode URL-encoded values before comparison.

Example:

```text
any(lower(url_decode(http.request.uri.args["q"][*])[*]) contains "<script")
```

Use cases:

- `%3cscript%3e`
- `%27 or 1=1`
- URL-encoded SQLi or XSS payloads
- form values that may be encoded

Generation caution:

- Confirm field and function compatibility.
- If function support is uncertain for the target product, include a fallback expression that matches encoded literals directly.

## 7.8 `regex_replace()`

`regex_replace()` replaces part of a string matched by a regular expression with a replacement string.

Example:

```text
regex_replace("/foo/bar", "/bar$", "/baz") == "/foo/baz"
```

Important constraints:

- `regex_replace()` has product/context limitations.
- It is available in rewrite expressions of Transform Rules and target URL expressions of dynamic URL redirects.
- It should not be used as a primary WAF custom rule detection pattern unless the target phase/product supports it.
- It can only be used once in a rewrite expression and cannot be nested with `wildcard_replace()`.

Generation rule:

> Do not generate `regex_replace()` for ordinary WAF custom-rule attack detection. Use `matches`, `contains`, `lower()`, `any()`, or direct field comparisons instead.

## 7.9 Function Selection Matrix

| Goal | Function or pattern | Example |
|---|---|---|
| Case-insensitive string match | `lower()` | `lower(http.request.uri.query) contains "<script"` |
| Check any repeated header value | `any()` | `any(lower(http.request.headers["user-agent"][*]) contains "sqlmap")` |
| Check all repeated header values | `all()` | `all(http.request.headers["content-type"][*] contains "json")` |
| Match path prefix | `starts_with()` | `starts_with(http.request.uri.path, "/api/")` |
| Match path suffix | `ends_with()` | `ends_with(http.request.uri.path, ".php")` |
| Match flexible pattern | `matches` with raw regex | `lower(http.request.uri.query) matches r"(union\s+select)"` |
| Decode URL-encoded arrays | `url_decode()` if supported | `any(url_decode(http.request.body.form.values[*])[*] contains "<script")` |

---

# 8. Expression Design for XSS Rule Generation

## 8.1 XSS Payload Signals

Use XSS expression patterns when payloads contain:

- `<script`
- `</script`
- `alert(`
- `prompt(`
- `confirm(`
- `onerror=`
- `onload=`
- `onclick=`
- `onmouseover=`
- `<svg`
- `<img`
- `<iframe`
- `src=`
- `href=`
- `javascript:`
- `document.cookie`
- `%3cscript`
- `%3csvg`
- HTML entities for tags or quotes
- mixed-case event handlers
- whitespace-obfuscated attributes

## 8.2 Basic XSS Query String Expression

```text
lower(http.request.uri.query) contains "<script"
or lower(http.request.uri.query) contains "onerror="
or lower(http.request.uri.query) contains "onload="
or lower(http.request.uri.query) contains "javascript:"
```

Use when:

- payloads are reflected in query string
- regex is not available
- literal indicators are stable

## 8.3 Regex XSS Query String Expression

```text
lower(http.request.uri.query) matches r"(<script|onerror\s*=|onload\s*=|onclick\s*=|javascript:|<svg|<img)"
```

Use when:

- `matches` is available
- payloads vary by whitespace or event handler
- a compact pattern is preferable to many `or` clauses

## 8.4 Encoded XSS Query String Expression

```text
lower(raw.http.request.uri.query) contains "%3cscript"
or lower(raw.http.request.uri.query) contains "%3csvg"
or lower(raw.http.request.uri.query) contains "onerror%3d"
or lower(raw.http.request.uri.query) contains "javascript%3a"
```

Use when:

- encoded payloads reach Ruleset Engine fields unchanged
- raw encoded form must be detected
- function-based decoding is unavailable or uncertain

## 8.5 Parameter-Specific XSS Expression

```text
any(lower(http.request.uri.args["q"][*]) matches r"(<script|onerror\s*=|onload\s*=|javascript:)")
```

Use when:

- vulnerable parameter is known
- broad query inspection creates false positives
- repeated parameter values are possible

## 8.6 Path-Scoped XSS Expression

```text
starts_with(http.request.uri.path, "/search")
and (
  lower(http.request.uri.query) contains "<script"
  or lower(http.request.uri.query) contains "onerror="
  or lower(http.request.uri.query) contains "javascript:"
)
```

Use when:

- only specific paths accept user input
- application has false-positive-prone endpoints elsewhere
- enforcement should be narrow

## 8.7 XSS Body/Form Expression

```text
any(lower(http.request.body.form.values[*]) contains "<script")
or any(lower(http.request.body.form.values[*]) contains "onerror=")
or any(lower(http.request.body.form.values[*]) contains "javascript:")
```

Use when:

- body inspection fields are available
- stored XSS appears in forms
- payloads are submitted through comments, profile fields, CMS fields, or rich-text editors

> **Warning:** Applications that intentionally accept HTML, Markdown, templates, code snippets, or rich text can generate false positives. Start with logging or a non-disruptive validation approach where available.

## 8.8 Complete XSS Expression Pattern

```text
(
  lower(http.request.uri.query) matches r"(<script|onerror\s*=|onload\s*=|onclick\s*=|javascript:|<svg|<img)"
  or lower(raw.http.request.uri.query) contains "%3cscript"
  or lower(raw.http.request.uri.query) contains "%3csvg"
)
and not ip.src in $trusted_security_scanners
```

Use when:

- both decoded/literal and encoded indicators matter
- trusted scanners should be excluded
- the account has a named list for trusted sources

## 8.9 XSS Expression Generation Checklist

- [ ] Use `lower()` for case normalization.
- [ ] Use `contains` for stable literal indicators.
- [ ] Use `matches` for event-handler or tag variants if plan supports regex.
- [ ] Use `raw.http.request.uri.query` for encoded indicators when needed.
- [ ] Use parameter-specific `http.request.uri.args["name"][*]` when vulnerable parameter is known.
- [ ] Scope to path or host if false-positive risk is high.
- [ ] Do not generate broad HTML-blocking expressions for CMS or rich-text endpoints without an exception.

---

# 9. Expression Design for SQL Injection Rule Generation

## 9.1 SQL Injection Payload Signals

Use SQLi expression patterns when payloads contain:

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
- `/* */`
- `%27`
- `%22`
- mixed-case SQL keywords
- whitespace-split SQL keywords

## 9.2 Basic SQLi Query String Expression

```text
lower(http.request.uri.query) contains "union select"
or lower(http.request.uri.query) contains "or 1=1"
or lower(http.request.uri.query) contains "sleep("
or lower(http.request.uri.query) contains "benchmark("
```

Use when:

- SQLi payloads appear in query strings
- regex is unavailable
- patterns are stable enough for literal matching

## 9.3 Regex SQLi Query String Expression

```text
lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema)"
```

Use when:

- `matches` is available
- attackers vary whitespace
- multiple SQLi forms must be covered compactly

## 9.4 Encoded SQLi Query String Expression

```text
lower(raw.http.request.uri.query) contains "%27"
and (
  lower(raw.http.request.uri.query) contains "or"
  or lower(raw.http.request.uri.query) contains "%20or%20"
)
```

Use when:

- URL-encoded quotes or SQL tokens are present
- raw encoded query must be detected
- decoding functions are unavailable or uncertain

## 9.5 Parameter-Specific SQLi Expression

```text
any(lower(http.request.uri.args["id"][*]) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()")
```

Use when:

- the vulnerable parameter is known
- false positives are likely in other parameters
- repeated values must be evaluated

## 9.6 Path-Scoped SQLi Expression

```text
starts_with(http.request.uri.path, "/api/search")
and (
  lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()"
)
```

Use when:

- SQLi tests target a specific endpoint
- the rule should avoid broad application-wide blocking
- false-positive risk is high

## 9.7 SQLi Body/Form Expression

```text
any(lower(http.request.body.form.values[*]) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\()")
```

Use when:

- body inspection fields are available
- SQLi payloads appear in form data
- SQL-like query strings in forms must be detected

## 9.8 Complete SQLi Expression Pattern

```text
(
  lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema)"
  or lower(raw.http.request.uri.query) contains "%27"
)
and not ip.src in $trusted_security_scanners
```

Use when:

- both decoded-looking and encoded SQLi indicators matter
- trusted scanner traffic should be excluded
- named lists are available

## 9.9 SQLi Expression Generation Checklist

- [ ] Use `lower()` for SQL keyword case normalization.
- [ ] Use `matches` for whitespace-flexible patterns when available.
- [ ] Use `contains` fallback if regex is unavailable.
- [ ] Use `raw.http.request.uri.query` for encoded indicators.
- [ ] Scope to path, host, method, or parameter when possible.
- [ ] Avoid matching single generic tokens such as `"select"` without SQLi context.
- [ ] Include false-positive risk for search forms, SQL labs, admin tools, reporting tools, and developer APIs.

---

# 10. Header, Cookie, and User-Agent Expression Patterns

## 10.1 User-Agent Scanner Detection

```text
lower(http.user_agent) contains "sqlmap"
or lower(http.user_agent) contains "nikto"
or lower(http.user_agent) contains "acunetix"
```

Use when the rule should match common scanner user agents.

## 10.2 Header Map Scanner Detection

```text
any(lower(http.request.headers["user-agent"][*]) contains "sqlmap")
```

Use when direct `http.user_agent` is insufficient or header-map consistency is needed.

## 10.3 Content-Type Scoped Body Rule

```text
any(lower(http.request.headers["content-type"][*]) contains "application/x-www-form-urlencoded")
and any(lower(http.request.body.form.values[*]) contains "<script")
```

Use when body inspection should apply only to form submissions.

## 10.4 Cookie Payload Detection

```text
lower(http.cookie) contains "<script"
or lower(http.cookie) contains "union select"
```

Use when malicious payloads appear in cookie values.

## 10.5 Header and Cookie Generation Rules

- Use lowercase header names in `http.request.headers["header-name"]`.
- Use `any()` for repeated header values.
- Use direct `http.cookie` for coarse cookie matching.
- Use path, host, or IP scoping when matching cookies or headers to reduce false positives.
- Do not trust spoofable headers for security allowlists unless the deployment guarantees their integrity.

---

# 11. IP, Bot, Threat Score, Country, ASN, and Scope Expressions

## 11.1 Trusted IP Exception

```text
ip.src in {203.0.113.10 203.0.113.11}
```

Use for allowlists, skip rules, and scanner exceptions.

## 11.2 Named IP List Exception

```text
ip.src in $trusted_office_networks
```

Use when the IP list is reusable or too long for an inline list.

## 11.3 Exclude Trusted IPs from Attack Rule

```text
(
  lower(http.request.uri.query) contains "<script"
  or lower(http.request.uri.query) contains "union select"
)
and not ip.src in $trusted_security_scanners
```

## 11.4 Bot-Aware Challenge Scope

```text
http.request.uri.path eq "/login"
and cf.threat_score gt 20
and not cf.client.bot
```

Use when suspicious traffic should be challenged but verified bots should not be affected.

## 11.5 Country or ASN Scope

```text
ip.src.country in {"CN" "RU"}
```

```text
ip.src.asnum in {12345 64512}
```

Use country and ASN conditions only when they are relevant to the user's policy. Do not use them as primary SQLi or XSS indicators.

---

# 12. Raw Fields and Encoded Payload Handling

## 12.1 Raw Fields Definition

Raw fields preserve original request values for later evaluations. They are prefixed with `raw.`.

Example:

```text
raw.http.request.uri.query
```

Raw fields are immutable during the request evaluation workflow and are not affected by actions of previously matched rules.

## 12.2 When to Use Raw Fields

Use raw fields when:

- matching encoded payloads exactly
- query normalization may hide important original evidence
- you need to inspect what arrived at Cloudflare
- previous transformations or rewrite actions should not influence matching

## 12.3 Encoded XSS Examples

```text
lower(raw.http.request.uri.query) contains "%3cscript"
```

```text
lower(raw.http.request.uri.query) contains "%3csvg"
```

```text
lower(raw.http.request.uri.query) contains "javascript%3a"
```

## 12.4 Encoded SQLi Examples

```text
lower(raw.http.request.uri.query) contains "%27"
and lower(raw.http.request.uri.query) contains "%20or%20"
```

```text
lower(raw.http.request.uri.query) contains "union%20select"
```

## 12.5 Raw Field Generation Caution

Raw field matching should usually supplement, not replace, normalized/lowercased field matching.

Recommended combined pattern:

```text
lower(http.request.uri.query) contains "<script"
or lower(raw.http.request.uri.query) contains "%3cscript"
```

---

# 13. Expression Length, Regex Count, and Maintainability

## 13.1 Expression Length Constraint

Cloudflare rule expressions are limited to 4,096 characters.

When generated expressions approach the limit:

- use named lists
- use compact regex alternatives
- split into multiple rules
- scope rules by path or host
- remove redundant alternatives
- replace repeated `or` equality checks with `in`

## 13.2 Regex Count Constraint

Cloudflare limits the number of regular expressions per rule. Each rule supports a maximum of 64 regexes.

Generation guidance:

- Prefer one compact regex with alternatives over many separate regex checks.
- Use `contains` for stable literals.
- Use `starts_with()` and `ends_with()` for prefix/suffix checks.
- Split very large regex logic into multiple rules if needed.

## 13.3 Plan Constraint for Regex Matching

The `matches` operator can require Business or Enterprise plan access.

Generation guidance:

- If using `matches`, mention plan dependency.
- Provide a `contains` fallback when plan support is unknown.
- For broad security policy, generate both a preferred regex version and a fallback literal version.

## 13.4 Expression Maintainability Rules

- Prefer clear grouping over compact but ambiguous logic.
- Use descriptive rule descriptions outside the expression.
- Keep each expression aligned to one objective.
- Avoid mixing unrelated detections in one expression.
- Use named lists for reusable IPs, hosts, countries, or ASNs.
- Use parameter-specific fields to reduce false positives.

---

# 14. Expression Builder, Expression Editor, and API

## 14.1 Expression Builder

The Expression Builder provides a visual way to define rule expressions.

Use Expression Builder when:

- the expression is simple
- grouping symbols are not required
- the user prefers dashboard-based rule creation

Limitation:

- Expression Builder does not support grouping symbols.

## 14.2 Expression Editor

The Expression Editor allows manually written expressions.

Use Expression Editor when:

- parentheses are needed
- complex compound expressions are needed
- regex expressions are needed
- functions and map/array access are needed

## 14.3 API

Use API-based expression deployment when:

- generating rules programmatically
- deploying custom rulesets
- using complex expressions
- versioning and automation are required
- expressions include grouping and precise syntax

## 14.4 Generation Rule

When generated expressions include:

- parentheses
- nested compound expressions
- raw strings
- map access
- array access
- advanced functions
- regex

then recommend Expression Editor or API deployment.

---

# 15. Expression Patterns for Cloudflare WAF Custom Rules

## 15.1 Basic Rule JSON Shape

A WAF custom rule generally pairs an expression with an action.

```json
{
  "description": "Block XSS indicators in query string",
  "expression": "lower(http.request.uri.query) contains \"<script\" or lower(http.request.uri.query) contains \"onerror=\"",
  "action": "block",
  "enabled": true
}
```

## 15.2 WAF Custom Rule Phase

Cloudflare WAF custom rules run in the `http_request_firewall_custom` phase.

Generation guidance:

- Use this phase for WAF custom rules.
- Use expressions based on request fields.
- Do not use response-only fields in request firewall custom rules.
- Ensure the selected action is available in the target phase.

## 15.3 XSS Block Rule

```json
{
  "description": "Block reflected XSS indicators in query string",
  "expression": "lower(http.request.uri.query) matches r\"(<script|onerror\\s*=|onload\\s*=|javascript:)\"",
  "action": "block",
  "enabled": true
}
```

## 15.4 XSS Literal Fallback Rule Without Regex

```json
{
  "description": "Block reflected XSS literal indicators in query string",
  "expression": "lower(http.request.uri.query) contains \"<script\" or lower(http.request.uri.query) contains \"onerror=\" or lower(http.request.uri.query) contains \"onload=\" or lower(http.request.uri.query) contains \"javascript:\"",
  "action": "block",
  "enabled": true
}
```

## 15.5 SQLi Block Rule

```json
{
  "description": "Block SQL injection indicators in query string",
  "expression": "lower(http.request.uri.query) matches r\"(union\\s+select|or\\s+1\\s*=\\s*1|sleep\\s*\\(|benchmark\\s*\\(|information_schema)\"",
  "action": "block",
  "enabled": true
}
```

## 15.6 SQLi Literal Fallback Rule Without Regex

```json
{
  "description": "Block SQL injection literal indicators in query string",
  "expression": "lower(http.request.uri.query) contains \"union select\" or lower(http.request.uri.query) contains \"or 1=1\" or lower(http.request.uri.query) contains \"sleep(\" or lower(http.request.uri.query) contains \"benchmark(\" or lower(http.request.uri.query) contains \"information_schema\"",
  "action": "block",
  "enabled": true
}
```

## 15.7 Path-Scoped XSS Rule

```json
{
  "description": "Block XSS indicators on search path",
  "expression": "starts_with(http.request.uri.path, \"/search\") and (lower(http.request.uri.query) contains \"<script\" or lower(http.request.uri.query) contains \"onerror=\" or lower(http.request.uri.query) contains \"javascript:\")",
  "action": "block",
  "enabled": true
}
```

## 15.8 Trusted Scanner Exception Expression

Use this expression in a skip rule placed before block rules.

```text
ip.src in $trusted_security_scanners
```

Or with path scope:

```text
ip.src in $trusted_security_scanners
and starts_with(http.request.uri.path, "/scanner/")
```

---

# 16. False Positive Tuning for Expressions

## 16.1 High False-Positive Scenarios

Cloudflare WAF expressions can produce false positives when applications legitimately accept:

- HTML
- Markdown
- rich text
- JavaScript snippets
- SQL fragments
- template syntax
- encoded content
- search operators
- debugging payloads
- security scanner traffic
- internal admin input

## 16.2 False Positive Reduction Techniques

| Technique | Expression pattern |
|---|---|
| Scope by path | `starts_with(http.request.uri.path, "/search") and <attack expression>` |
| Scope by host | `http.host eq "app.example.com" and <attack expression>` |
| Scope by method | `http.request.method eq "POST" and <attack expression>` |
| Scope by parameter | `any(lower(http.request.uri.args["q"][*]) contains "<script")` |
| Exclude trusted IPs | `<attack expression> and not ip.src in $trusted_security_scanners` |
| Use literal indicators | `contains "<script"` instead of a broad regex |
| Use regex only for attack-specific patterns | `matches r"(onerror\s*=|union\s+select)"` |
| Split rules | one rule per attack family or endpoint |
| Start with non-blocking validation where available | action choice outside expression |

## 16.3 Example: False-Positive-Aware XSS Rule

```text
starts_with(http.request.uri.path, "/public/search")
and (
  lower(http.request.uri.query) contains "<script"
  or lower(http.request.uri.query) contains "onerror="
  or lower(http.request.uri.query) contains "javascript:"
)
and not ip.src in $trusted_security_scanners
```

## 16.4 Example: False-Positive-Aware SQLi Rule

```text
starts_with(http.request.uri.path, "/api/products")
and (
  lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()"
)
and not ip.src in $trusted_security_scanners
```

---

# 17. Expression Decision Matrix for Rule Generation

| Input evidence | Preferred expression design |
|---|---|
| XSS in unknown query parameter | `lower(http.request.uri.query)` with `contains` or `matches` |
| XSS in known parameter | `any(lower(http.request.uri.args["param"][*]) ...)` |
| URL-encoded XSS | `raw.http.request.uri.query` encoded literals plus normal query checks |
| SQLi in unknown query parameter | `lower(http.request.uri.query)` with SQLi literals or regex |
| SQLi in known parameter | `any(lower(http.request.uri.args["id"][*]) ...)` |
| SQLi with whitespace evasion | `matches r"(union\s+select|or\s+1\s*=\s*1)"` |
| Case-randomized payload | wrap string field in `lower()` |
| Header-based payload | `any(lower(http.request.headers["header"][*]) ...)` |
| User-Agent scanner | `lower(http.user_agent) contains "sqlmap"` |
| Cookie payload | `lower(http.cookie) contains "<script"` |
| Trusted scanner exception | `not ip.src in $trusted_security_scanners` or separate skip expression |
| Broad false positives | scope by host, path, method, parameter, or trusted list |
| Regex unavailable | use `contains` fallback expressions |
| Expression too long | named lists, compact regex, multiple rules |

---

# 18. Complete Example: Cloudflare WAF Expressions for XSS and SQLi

## 18.1 Scenario

The application receives:

- reflected XSS payloads in query strings
- SQL injection payloads in query strings
- trusted security scanner traffic from a named IP list
- false-positive risk on admin and CMS paths

## 18.2 XSS Expression

```text
(
  starts_with(http.request.uri.path, "/search")
  or starts_with(http.request.uri.path, "/comments")
)
and (
  lower(http.request.uri.query) matches r"(<script|onerror\s*=|onload\s*=|javascript:|<svg|<img)"
  or lower(raw.http.request.uri.query) contains "%3cscript"
  or lower(raw.http.request.uri.query) contains "%3csvg"
)
and not ip.src in $trusted_security_scanners
```

## 18.3 SQLi Expression

```text
(
  starts_with(http.request.uri.path, "/api/search")
  or starts_with(http.request.uri.path, "/api/products")
)
and (
  lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema)"
  or lower(raw.http.request.uri.query) contains "union%20select"
  or lower(raw.http.request.uri.query) contains "%27"
)
and not ip.src in $trusted_security_scanners
```

## 18.4 Literal Fallback Expression Without Regex

```text
(
  lower(http.request.uri.query) contains "<script"
  or lower(http.request.uri.query) contains "onerror="
  or lower(http.request.uri.query) contains "javascript:"
  or lower(http.request.uri.query) contains "union select"
  or lower(http.request.uri.query) contains "or 1=1"
  or lower(http.request.uri.query) contains "sleep("
)
and not ip.src in $trusted_security_scanners
```

## 18.5 Rule JSON Example

```json
{
  "description": "Block XSS and SQLi indicators in scoped query-string traffic",
  "expression": "((starts_with(http.request.uri.path, \"/search\") or starts_with(http.request.uri.path, \"/api/search\")) and (lower(http.request.uri.query) matches r\"(<script|onerror\\s*=|javascript:|union\\s+select|or\\s+1\\s*=\\s*1|sleep\\s*\\()\") and not ip.src in $trusted_security_scanners",
  "action": "block",
  "enabled": true
}
```

> **Warning:** The JSON example is intentionally compact. If the final expression becomes complex, split XSS and SQLi into separate rules for maintainability and clearer debugging.

---

# 19. Common Expression Mistakes and Corrections

## 19.1 Incorrect: Missing Lowercase Normalization

Incorrect:

```text
http.request.uri.query contains "<script"
```

Better:

```text
lower(http.request.uri.query) contains "<script"
```

## 19.2 Incorrect: CIDR with Equality

Incorrect:

```text
ip.src eq 192.0.2.0/24
```

Correct:

```text
ip.src in {192.0.2.0/24}
```

## 19.3 Incorrect: Using `starts_with` as an Operator

Incorrect:

```text
http.request.uri.path starts_with "/api/"
```

Correct:

```text
starts_with(http.request.uri.path, "/api/")
```

## 19.4 Incorrect: Ungrouped Mixed `and` / `or`

Incorrect:

```text
http.request.uri.path contains "/search" and lower(http.request.uri.query) contains "<script" or lower(http.request.uri.query) contains "onerror="
```

Correct:

```text
http.request.uri.path contains "/search"
and (
  lower(http.request.uri.query) contains "<script"
  or lower(http.request.uri.query) contains "onerror="
)
```

## 19.5 Incorrect: Array Wildcard Without `any()`

Incorrect:

```text
http.request.headers["user-agent"][*] contains "sqlmap"
```

Correct:

```text
any(lower(http.request.headers["user-agent"][*]) contains "sqlmap")
```

## 19.6 Incorrect: Overbroad SQLi Token

Risky:

```text
lower(http.request.uri.query) contains "select"
```

Better:

```text
lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()"
```

## 19.7 Incorrect: Overbroad XSS Token

Risky:

```text
lower(http.request.uri.query) contains "on"
```

Better:

```text
lower(http.request.uri.query) matches r"(<script|onerror\s*=|onload\s*=|javascript:)"
```

---

# 20. Final Rule-Generation Template for Cloudflare Expressions

Use this output structure when generating Cloudflare WAF rules.

```markdown
## Rule Objective

Describe:
- attack type
- bypass behavior
- target request component
- intended action

## Proposed Cloudflare Expression

Provide the expression.

## Proposed Cloudflare Rule JSON

Provide JSON with:
- description
- expression
- action
- enabled

## Expression Explanation

Explain:
- selected fields
- selected operators
- selected functions
- selected literals or regex patterns
- grouping and precedence
- encoded payload handling
- false-positive scoping

## Deployment Notes

Mention:
- target phase, usually `http_request_firewall_custom`
- Expression Editor/API if grouping or advanced syntax is used
- plan requirements for regex/body/logging if relevant
- expression length risk
- named lists or inline lists

## False Positive and Tuning Notes

Mention:
- likely false positives
- how to narrow by path, host, method, parameter, IP, ASN, country, or list
- whether to split into multiple rules
```

---

# 21. Final Checklist for Cloudflare Expression Generation

- [ ] Expression type is clear: simple or compound.
- [ ] The field matches the observed payload location.
- [ ] String comparisons use `lower()` when case variations matter.
- [ ] Literal indicators use `contains` when stable.
- [ ] Regex patterns use `matches` only when plan support is acceptable.
- [ ] Regex strings use raw string syntax when possible.
- [ ] Query parameters use `http.request.uri.args["name"][*]` and `any()` when parameter name is known.
- [ ] Header maps use lowercase header names.
- [ ] Arrays use `any()` or `all()`.
- [ ] Raw fields are used for encoded payloads when needed.
- [ ] CIDR and IP sets use `in`, not equality.
- [ ] `starts_with()` and `ends_with()` are used as functions, not operators.
- [ ] Mixed `and`/`or` expressions use parentheses.
- [ ] The expression stays under 4,096 characters.
- [ ] The expression does not exceed regex-count limits.
- [ ] Body fields are used only when supported.
- [ ] Trusted exceptions use named lists or tightly scoped inline sets.
- [ ] False-positive risk is documented.
- [ ] Complex expressions are recommended for Expression Editor or API deployment.
