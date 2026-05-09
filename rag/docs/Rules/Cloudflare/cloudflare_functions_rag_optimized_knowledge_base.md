# Cloudflare Rules Language Functions Knowledge Base for WAF Rule Generation
# 1. Cloudflare Rules Language Function Model
## 1.1 Definition

Cloudflare Rules language functions manipulate, transform, validate, or evaluate values in an expression.

A Cloudflare expression evaluates to a Boolean result:

```text
true
```

or:

```text
false
```

When a WAF custom rule expression evaluates to `true`, the configured rule action runs, such as `block`, `managed_challenge`, `js_challenge`, `challenge`, `log`, or `skip`.

Functions are typically used inside expressions with fields, operators, arrays, maps, and literal values.

Example:

```text
lower(http.request.uri.query) contains "<script"
```

In this expression:

- `http.request.uri.query` is a field.
- `lower()` is a transformation function.
- `contains` is a comparison operator.
- `"<script"` is a string literal.

## 1.2 Function Categories for Rule Generation

| Function category | Functions | WAF rule-generation use |
|---|---|---|
| Array evaluation | `any`, `all` | Evaluate arrays from headers, query arguments, form values, cookies, or decoded values. |
| Case normalization | `lower`, `upper` | Normalize case for case-insensitive XSS, SQLi, host, path, header, or cookie matching. |
| String boundary checks | `starts_with`, `ends_with` | Scope rules by path prefix or suffix; replace invalid operator-style `starts_with` syntax. |
| Encoding and decoding | `url_decode`, `decode_base64`, `encode_base64` | Detect encoded payloads or construct transformed values where supported. |
| String composition and conversion | `concat`, `join`, `split`, `substring`, `to_string` | Build or inspect strings; many are phase/product restricted. |
| Map and collection checks | `has_key`, `has_value` | Check header/query map keys or values without unsafe direct indexing. |
| Length and size checks | `len` | Match string, byte, or array length conditions. |
| JSON body lookup | `lookup_json_string`, `lookup_json_integer` | Extract JSON values from raw JSON request body. |
| IP network normalization | `cidr`, `cidr6` | Match network grouping in custom/rate limiting rules. |
| Rewrite-only replacement | `regex_replace`, `wildcard_replace`, `remove_query_args`, `remove_bytes` | Use primarily in Transform Rules or redirect/rewrite contexts, not ordinary WAF attack blocking. |
| Cryptographic / token validation | `is_timed_hmac_valid_v0`, `sha256`, `uuidv4` | Validate signed URLs or create signed transformed values where supported. |
| Network firewall | `bit_slice` | Cloudflare Network Firewall use, not ordinary HTTP WAF SQLi/XSS rules. |

## 1.3 Function Selection Principle

For Cloudflare WAF rule generation:

1. Use `lower()` for case-insensitive string matching.
2. Use `any()` when matching arrays such as repeated headers, query argument values, or form values.
3. Use `url_decode()` when the observed bypass uses URL encoding or recursive URL encoding.
4. Use `starts_with()` for path prefix scoping.
5. Use `ends_with()` for path extension or suffix scoping.
6. Use `has_key()` when checking whether a map key exists.
7. Use `lookup_json_string()` or `lookup_json_integer()` for specific JSON request body keys.
8. Use `is_timed_hmac_valid_v0()` only for token-authentication custom rules.
9. Avoid rewrite-only functions in ordinary WAF custom block rules unless the target product/phase supports them.
10. Mention product, phase, or plan constraints whenever a function is restricted.

---

# 2. Arrays, Maps, and Function Evaluation Rules

## 2.1 Why Arrays Matter

Many Cloudflare fields return arrays or maps of arrays.

Examples:

- `http.request.headers["user-agent"]` returns an array of User-Agent header values.
- `http.request.headers.names` returns an array of header names.
- `http.request.uri.args["q"]` returns an array of values for query parameter `q`.
- `http.request.body.form.values` returns an array of form values when supported.

Operators do not directly support array-wide matching with `[*]` unless the array is inside a compatible function.

## 2.2 Correct Array Pattern with `any()`

Use `any()` when any value in an array should trigger the rule.

Correct:

```text
any(lower(http.request.headers["user-agent"][*])[*] contains "sqlmap")
```

Correct:

```text
any(lower(http.request.uri.args["q"][*])[*] contains "<script")
```

Correct:

```text
any(url_decode(http.request.body.form.values[*])[*] contains "an xss attack")
```

## 2.3 Incorrect Array Pattern Without `any()`

Incorrect:

```text
http.request.headers["user-agent"][*] contains "sqlmap"
```

Incorrect:

```text
lower(http.request.uri.args["q"][*]) contains "<script"
```

Why incorrect:

- `[*]` produces an array of values.
- Comparison operators do not directly evaluate all array elements.
- Wrap the comparison in `any()` or `all()`.

## 2.4 Function `[ * ]` Notation Rule

When a transformation function does not take arrays directly, apply `[*]` to unpack array elements before calling the function.

Example:

```text
any(lower(http.request.headers.names[*])[*] == "content-type")
```

In this expression:

1. `http.request.headers.names[*]` unpacks every header name.
2. `lower(...)[*]` returns lowercased header names and unpacks them for comparison.
3. `== "content-type"` returns an array of Boolean values.
4. `any()` returns `true` if any value is true.

## 2.5 Missing Values

If a map key or array element is missing:

- comparisons against the missing value evaluate to `false`
- most functions receiving a missing value return a missing value
- behavior can vary by function

Rule-generation guidance:

- Use `has_key()` when key existence matters.
- Use broad fields like `http.request.uri.query` when parameter names are unknown.
- Use parameter-specific map access only when the parameter name is known.
- Avoid direct `[0]` indexing unless a value is guaranteed or acceptable to be missing.

---

# 3. `any()` Function

## 3.1 Definition

```text
any(Array<Boolean>) -> Boolean
```

`any()` returns `true` when at least one Boolean value in the input array is `true`. Otherwise, it returns `false`.

## 3.2 Rule-Generation Use

Use `any()` when matching:

- repeated HTTP header values
- query argument values
- query argument names
- form body values
- multipart body values
- decoded arrays
- lowercased arrays
- cookie map values when represented as arrays

For WAF attack detection, `any()` is usually preferred over `all()` because a single malicious value is sufficient to match.

## 3.3 XSS in Known Query Parameter

```text
any(lower(http.request.uri.args["q"][*])[*] contains "<script")
or any(lower(http.request.uri.args["q"][*])[*] contains "onerror=")
or any(lower(http.request.uri.args["q"][*])[*] contains "javascript:")
```

Use when the vulnerable query parameter is known.

## 3.4 SQLi in Known Query Parameter

```text
any(lower(http.request.uri.args["id"][*])[*] matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()")
```

Use when the SQLi payload appears in a known parameter such as `id`, `product`, `category`, `search`, or `q`.

## 3.5 Header Scanner Detection

```text
any(lower(http.request.headers["user-agent"][*])[*] contains "sqlmap")
or any(lower(http.request.headers["user-agent"][*])[*] contains "nikto")
or any(lower(http.request.headers["user-agent"][*])[*] contains "acunetix")
```

## 3.6 URL-Decoded Form Value XSS

```text
any(url_decode(http.request.body.form.values[*])[*] contains "<script")
or any(url_decode(http.request.body.form.values[*])[*] contains "onerror=")
```

Use when form values can be URL encoded and request-body inspection is supported.

## 3.7 `any()` Generation Checklist

- [ ] Use `any()` when matching any element of an array.
- [ ] Use `[*]` correctly inside transformation functions.
- [ ] Use `lower()` inside `any()` for case-insensitive string matching.
- [ ] Use `url_decode()` inside `any()` when payloads are encoded.
- [ ] Do not use `any()` for scalar fields such as `http.request.uri.query`.

---

# 4. `all()` Function

## 4.1 Definition

```text
all(Array<Boolean>) -> Boolean
```

`all()` returns `true` only when every Boolean value in the input array is `true`.

## 4.2 Rule-Generation Use

Use `all()` when every array value must satisfy a condition.

Example:

```text
all(http.request.headers["content-type"][*] == "application/json")
```

## 4.3 When Not to Use `all()`

For attack detection, do not use `all()` when a single malicious value should trigger a rule.

Risky:

```text
all(lower(http.request.uri.args.values[*])[*] contains "<script")
```

This requires every query argument value to contain `<script`, which is usually not the intended WAF behavior.

Better:

```text
any(lower(http.request.uri.args.values[*])[*] contains "<script")
```

## 4.4 `all()` Generation Checklist

- [ ] Use only when every array element must match.
- [ ] Avoid for XSS/SQLi detection unless intentionally requiring all elements.
- [ ] Prefer `any()` for malicious payload detection.
- [ ] Use with repeated headers only when strict uniformity is required.

---

# 5. `lower()` Function

## 5.1 Definition

```text
lower(String) -> String
```

`lower()` converts uppercase ASCII bytes in a string field to lowercase. Other bytes are unaffected.

String comparisons in Cloudflare expressions are case-sensitive by default. Use `lower()` to make matching more robust against case-randomized payloads.

## 5.2 Rule-Generation Use

Use `lower()` for:

- XSS tags and event handlers with random casing
- SQL keywords with random casing
- host matching
- URI path matching
- query string matching
- header values
- cookie values
- form values
- scanner User-Agent strings

## 5.3 XSS Example

```text
lower(http.request.uri.query) contains "<script"
or lower(http.request.uri.query) contains "onerror="
or lower(http.request.uri.query) contains "javascript:"
```

## 5.4 SQLi Example

```text
lower(http.request.uri.query) contains "union select"
or lower(http.request.uri.query) contains "or 1=1"
or lower(http.request.uri.query) contains "sleep("
```

## 5.5 Header Array Example

```text
any(lower(http.request.headers["user-agent"][*])[*] contains "sqlmap")
```

## 5.6 Query Parameter Array Example

```text
any(lower(http.request.uri.args["search"][*])[*] contains "<script")
```

## 5.7 `lower()` Generation Checklist

- [ ] Use for case-insensitive matching.
- [ ] Compare the result to lowercased literals.
- [ ] Use `lower(field[*])[*]` when applying to arrays.
- [ ] Do not assume Unicode case folding beyond supported behavior.
- [ ] Pair with `url_decode()` when encoded payloads are observed.

---

# 6. `upper()` Function

## 6.1 Definition

```text
upper(String) -> String
```

`upper()` converts lowercase ASCII bytes in a string field to uppercase.

## 6.2 Rule-Generation Use

`upper()` is less common for WAF rule generation than `lower()`. Use it only when the target comparison value is naturally uppercase or a policy requires uppercase normalization.

Example:

```text
upper(http.request.method) == "POST"
```

## 6.3 Best Practice

Prefer `lower()` for XSS and SQL injection payload detection because security examples and attack indicators are usually written in lowercase.

---

# 7. `url_decode()` Function

## 7.1 Definition

```text
url_decode(source String, options String optional) -> String
```

`url_decode()` decodes a URL-formatted string from a field.

Supported behavior includes:

- `%20` decoding to a space
- `+` decoding to a space
- optional recursive decoding with `"r"`
- optional Unicode percent decoding with `"u"`

The `source` must be a field. It cannot be a literal string.

## 7.2 Options

| Option | Meaning | Rule-generation use |
|---|---|---|
| `"r"` | Recursive decoding | Use for double-encoded payloads such as `%253Cscript%253E`. |
| `"u"` | Unicode percent decoding | Use for `%uXXXX` style payloads where relevant. |
| `"ur"` or `"ru"` | Unicode + recursive decoding | Use for Unicode encoded and double-encoded payloads. |

## 7.3 XSS URL Decode Example

```text
url_decode(http.request.uri.query) contains "<script"
or url_decode(http.request.uri.query) contains "onerror="
or url_decode(http.request.uri.query) contains "javascript:"
```

## 7.4 Case-Insensitive URL-Decoded XSS

```text
lower(url_decode(http.request.uri.query)) contains "<script"
or lower(url_decode(http.request.uri.query)) contains "onerror="
or lower(url_decode(http.request.uri.query)) contains "javascript:"
```

## 7.5 Recursive URL Decode for Double Encoding

```text
lower(url_decode(http.request.uri.query, "r")) contains "<script"
or lower(url_decode(http.request.uri.query, "r")) contains "onerror="
```

Use when observed payloads include double URL encoding such as:

```text
%253Cscript%253Ealert(1)%253C/script%253E
```

## 7.6 Unicode URL Decode

```text
url_decode(http.request.uri.path, "u") matches r"(?u)\p{Hangul}+"
```

Use Unicode decoding only when the observed bypass uses Unicode percent encoding or the rule specifically requires Unicode-aware matching.

## 7.7 URL Decode with Arrays

```text
any(url_decode(http.request.body.form.values[*])[*] contains "<script")
```

For case-insensitive array matching:

```text
any(lower(url_decode(http.request.body.form.values[*])[*])[*] contains "<script")
```

## 7.8 Raw Field Alternative

If function support is uncertain or you want to match encoded values exactly, use raw fields:

```text
lower(raw.http.request.uri.query) contains "%3cscript"
or lower(raw.http.request.uri.query) contains "javascript%3a"
```

## 7.9 `url_decode()` Generation Checklist

- [ ] Use when payloads contain `%xx`, `+`, double-encoding, or Unicode percent encoding.
- [ ] Use `"r"` for recursive decoding when double encoding is observed.
- [ ] Use `"u"` when Unicode percent encoding is observed.
- [ ] Use `lower(url_decode(...))` for case-insensitive decoded matching.
- [ ] Use raw encoded checks as fallback or supplemental detection.
- [ ] Do not pass a literal string as the source argument.

---

# 8. `starts_with()` Function

## 8.1 Definition

```text
starts_with(source String, substring String) -> Boolean
```

`starts_with()` returns `true` when the source string starts with the given substring.

The source cannot be a literal string.

## 8.2 Rule-Generation Use

Use `starts_with()` to scope WAF rules by path prefix.

Common examples:

```text
starts_with(http.request.uri.path, "/api/")
```

```text
starts_with(http.request.uri.path, "/admin/")
```

```text
starts_with(http.request.uri.path, "/search")
```

## 8.3 XSS Path-Scoped Example

```text
starts_with(http.request.uri.path, "/search")
and (
  lower(http.request.uri.query) contains "<script"
  or lower(http.request.uri.query) contains "onerror="
  or lower(http.request.uri.query) contains "javascript:"
)
```

## 8.4 SQLi API-Scoped Example

```text
starts_with(http.request.uri.path, "/api/search")
and lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()"
```

## 8.5 Important Syntax Rule

Correct:

```text
starts_with(http.request.uri.path, "/api/")
```

Incorrect:

```text
http.request.uri.path starts_with "/api/"
```

## 8.6 `starts_with()` Generation Checklist

- [ ] Use as a function call, not as an operator.
- [ ] Use for path prefix scoping.
- [ ] Combine with attack indicators to reduce false positives.
- [ ] Do not pass a literal string as the source argument.

---

# 9. `ends_with()` Function

## 9.1 Definition

```text
ends_with(source String, substring String) -> Boolean
```

`ends_with()` returns `true` when the source string ends with the given substring.

The source cannot be a literal value.

## 9.2 Rule-Generation Use

Use `ends_with()` for suffix and extension scoping.

Examples:

```text
ends_with(http.request.uri.path, ".php")
```

```text
ends_with(http.request.uri.path, ".aspx")
```

```text
ends_with(http.request.uri.path, "/login")
```

## 9.3 Extension-Scoped Rule Example

```text
ends_with(http.request.uri.path, ".php")
and lower(http.request.uri.query) contains "union select"
```

## 9.4 Static Asset Exclusion Example

```text
not (
  ends_with(http.request.uri.path, ".js")
  or ends_with(http.request.uri.path, ".css")
  or ends_with(http.request.uri.path, ".png")
  or ends_with(http.request.uri.path, ".jpg")
)
```

## 9.5 Important Syntax Rule

Correct:

```text
ends_with(http.request.uri.path, ".html")
```

Incorrect:

```text
http.request.uri.path ends_with ".html"
```

## 9.6 `ends_with()` Generation Checklist

- [ ] Use as a function call, not as an operator.
- [ ] Use for path suffix or file extension scoping.
- [ ] Combine with attack indicators.
- [ ] Avoid broad suffix rules without a security reason.

---

# 10. `has_key()` Function

## 10.1 Definition

```text
has_key(map: Map<T>, key: String) -> Boolean
```

`has_key()` returns `true` if the provided map contains the specified key.

The key can be a literal or dynamic string.

If any argument is nil, the returned value is nil.

## 10.2 Rule-Generation Use

Use `has_key()` to check whether a request map contains a field before relying on it.

Useful maps include:

- `http.request.headers`
- `http.request.uri.args`
- `http.request.cookies` when available
- body form maps when available

## 10.3 Header Exists Example

```text
has_key(http.request.headers, "x-api-key")
```

## 10.4 Query Argument Exists Example

```text
has_key(http.request.uri.args, "redirect")
```

## 10.5 Suspicious Parameter Presence

```text
has_key(http.request.uri.args, "cmd")
or has_key(http.request.uri.args, "exec")
or has_key(http.request.uri.args, "redirect")
```

## 10.6 Dynamic Key Example

```text
has_key(http.request.headers, lower(http.request.uri.args.names[0]))
```

Use dynamic keys cautiously because missing values can propagate.

## 10.7 `has_key()` Generation Checklist

- [ ] Use to check map-key existence.
- [ ] Use lowercase header names for header maps.
- [ ] Use before parameter-specific access when missing keys are common.
- [ ] Do not use as the only attack indicator unless key presence itself is suspicious.

---

# 11. `has_value()` Function

## 11.1 Definition

```text
has_value(collection: Map<T> | Array<T>, value: T) -> Boolean
```

`has_value()` returns `true` if the provided collection contains the specified value.

The collection value type and provided value type must match. The value type must be primitive: Boolean, Integer, String, Bytes, or IP address.

If any argument is nil, the returned value is nil.

## 11.2 Rule-Generation Use

Use `has_value()` for exact membership checks in arrays or maps.

## 11.3 Header Name Exists Example

```text
has_value(http.request.headers.names, "X-My-Header")
```

## 11.4 Case-Insensitive Header Name Example

```text
has_value(lower(http.request.headers.names[*]), "x-my-header")
```

If the function/array typing is uncertain, prefer:

```text
any(lower(http.request.headers.names[*])[*] == "x-my-header")
```

## 11.5 Query Argument Name Example

```text
has_value(http.request.uri.args.names, "redirect")
```

## 11.6 `has_value()` Generation Checklist

- [ ] Use for exact collection membership.
- [ ] Ensure collection and value types match.
- [ ] Use `any()` patterns when transformation over arrays is required.
- [ ] Do not use for substring matching; use `contains` or `matches`.

---

# 12. `len()` Function

## 12.1 Definition

```text
len(String | Bytes | Array) -> Integer
```

`len()` returns:

- byte length for a string or byte value
- number of elements for an array

## 12.2 Rule-Generation Use

Use `len()` for:

- unusually long query strings
- suspiciously long header values
- oversized parameter values
- missing or too-short tokens
- array count checks
- simple request-shape validation

## 12.3 Long Query String Example

```text
len(http.request.uri.query) gt 2048
```

## 12.4 Long Parameter Value Example

```text
any(len(http.request.uri.args["q"][*])[*] gt 512)
```

## 12.5 Missing or Short Token Example

```text
not has_key(http.request.uri.args, "token")
or any(len(http.request.uri.args["token"][*])[*] lt 32)
```

## 12.6 Header Count Example

```text
len(http.request.headers.names) gt 100
```

## 12.7 `len()` Generation Checklist

- [ ] Use for length-based anomaly rules.
- [ ] Pair length rules with path or method scope.
- [ ] Use `any()` when checking arrays of values.
- [ ] Do not treat length alone as SQLi/XSS evidence unless the user asks for request-shape policy.

---

# 13. JSON Lookup Functions

## 13.1 JSON Lookup Scope

Cloudflare provides functions to extract typed values from a string representation of a JSON document.

Relevant functions:

```text
lookup_json_string()
lookup_json_integer()
```

The field must be a string containing valid JSON, such as `http.request.body.raw` when body inspection is available.

## 13.2 `lookup_json_string()`

### Definition

```text
lookup_json_string(field String, key String | Integer, key String | Integer optional, ...) -> String
```

`lookup_json_string()` returns the string value associated with a key or nested key path in a JSON document.

### Rule-generation use

Use for JSON API request bodies when a specific string field must be inspected.

### Example: top-level string

Given body:

```json
{
  "company": "cloudflare",
  "product": "rulesets"
}
```

Expression:

```text
lookup_json_string(http.request.body.raw, "company") == "cloudflare"
```

### Example: nested string

Given body:

```json
{
  "network": {
    "name": "cloudflare"
  }
}
```

Expression:

```text
lookup_json_string(http.request.body.raw, "network", "name") == "cloudflare"
```

### XSS in JSON property

```text
lower(lookup_json_string(http.request.body.raw, "comment")) contains "<script"
or lower(lookup_json_string(http.request.body.raw, "comment")) contains "onerror="
```

### SQLi in JSON property

```text
lower(lookup_json_string(http.request.body.raw, "search")) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()"
```

## 13.3 `lookup_json_integer()`

### Definition

```text
lookup_json_integer(field String, key String | Integer, key String | Integer optional, ...) -> Integer
```

`lookup_json_integer()` returns a plain integer value associated with a key or nested key path.

It does not work for floating values with a zero decimal part such as `42.0`.

### Example: top-level integer

Given body:

```json
{
  "record_id": "aed53a",
  "version": 2
}
```

Expression:

```text
lookup_json_integer(http.request.body.raw, "version") == 2
```

### Example: nested integer

Given body:

```json
{
  "product": {
    "id": 356
  }
}
```

Expression:

```text
lookup_json_integer(http.request.body.raw, "product", "id") == 356
```

### Example: JSON array

Given body:

```json
[
  "first_item",
  -234
]
```

Expression:

```text
lookup_json_integer(http.request.body.raw, 1) == -234
```

## 13.4 JSON Lookup Generation Checklist

- [ ] Use only when the source field contains valid JSON.
- [ ] Use for JSON API request bodies.
- [ ] Mention request-body inspection availability.
- [ ] Use `lookup_json_string()` for strings.
- [ ] Use `lookup_json_integer()` for plain integers only.
- [ ] Do not use for floating-point numbers.
- [ ] Scope JSON body rules by path, method, and Content-Type.

---

# 14. Base64 Functions

## 14.1 `decode_base64()`

### Definition

```text
decode_base64(source String) -> String
```

`decode_base64()` decodes a Base64-encoded string from a field.

The source must be a field, not a literal string.

Availability:

- Transform Rules
- WAF custom rules
- Rate limiting rules

## 14.2 Base64 Header Example

If a request header contains:

```text
client_id: MTIzYWJj
```

Expression:

```text
any(decode_base64(http.request.headers["client_id"][*])[*] eq "123abc")
```

## 14.3 Base64 Encoded XSS Header Example

```text
any(lower(decode_base64(http.request.headers["x-payload"][*])[*]) contains "<script")
or any(lower(decode_base64(http.request.headers["x-payload"][*])[*]) contains "onerror=")
```

Use only if the application legitimately receives Base64-encoded payloads and header inspection is appropriate.

## 14.4 `encode_base64()`

### Definition

```text
encode_base64(input String | Bytes [, flags String]) -> String
```

`encode_base64()` encodes a string or byte array to Base64 format.

Optional flags:

| Flag | Meaning |
|---|---|
| `u` | URL-safe Base64 using `-` and `_` instead of `+` and `/`. |
| `p` | Adds padding with `=` characters. |

Availability:

- Request/response header transform rules only.

## 14.5 `encode_base64()` Example

```text
encode_base64("hello world")
```

Expected value:

```text
aGVsbG8gd29ybGQ
```

With padding:

```text
encode_base64("hello world", "p")
```

Expected value:

```text
aGVsbG8gd29ybGQ=
```

## 14.6 Base64 Generation Checklist

- [ ] Use `decode_base64()` for encoded request values in custom rules when supported.
- [ ] Use `encode_base64()` only in header transform contexts.
- [ ] Do not use `encode_base64()` for ordinary WAF SQLi/XSS detection.
- [ ] Use array syntax and `any()` for header arrays.

---

# 15. `concat()` Function

## 15.1 Definition

```text
concat(String | Bytes | Array, ...) -> String | Array
```

`concat()` concatenates a comma-separated list of values into a single string or array. The return type depends on the input types.

## 15.2 Rule-Generation Use

Use `concat()` when a security function requires a single message composed from multiple fields.

Most common WAF-relevant use:

- building the `MessageMAC` argument for `is_timed_hmac_valid_v0()`
- constructing signed request inputs
- transform-rule value generation

## 15.3 HMAC Message Composition Example

```text
is_timed_hmac_valid_v0(
  "mysecretkey",
  concat(
    http.request.uri,
    http.request.headers["timestamp"][0],
    "-",
    http.request.headers["mac"][0]
  ),
  100000,
  http.request.timestamp.sec,
  0
)
```

## 15.4 `concat()` Generation Checklist

- [ ] Use when a function requires a composed string.
- [ ] Use carefully with arrays because output type can become an array.
- [ ] Avoid unnecessary `concat()` in simple WAF expressions.
- [ ] Use direct field comparisons when possible.

---

# 16. `join()` Function

## 16.1 Definition

```text
join(items Array<String>, separator String) -> String
```

`join()` concatenates strings in an array with the separator between each item.

Behavior:

- returns nil if any argument is nil
- returns empty string if the array is empty
- returns the single item if the array contains one item

Availability:

- Transform Rules
- WAF custom rules
- Custom Error Rules

## 16.2 Header Names Example

```text
join(http.request.headers.names, ",")
```

## 16.3 Rule-Generation Use

Use `join()` when the rule or transform needs a combined string representation of array values.

Do not use `join()` when `any()` is more precise for attack detection.

Better for detection:

```text
any(lower(http.request.headers.values[*])[*] contains "<script")
```

Less precise:

```text
lower(join(http.request.headers.values, ",")) contains "<script"
```

## 16.4 `join()` Generation Checklist

- [ ] Use for converting arrays into strings when necessary.
- [ ] Prefer `any()` for security detection over individual values.
- [ ] Mention availability constraints when relevant.

---

# 17. `split()` Function

## 17.1 Definition

```text
split(input String, separator String, limit Integer) -> Array<String>
```

`split()` splits a string into an array using a non-empty literal separator. The returned array contains at most `limit` elements.

Constraints:

- `separator` must be a non-empty literal string.
- `limit` is mandatory.
- `limit` must be a literal integer between 1 and 128.
- if input is nil, the result is nil.

Availability:

- response header transform rules
- Custom Error Rules

## 17.2 Example

Header:

```text
x-categories: groceries,electronics,diy,auto
```

Expression:

```text
split(http.request.headers["x-categories"][0], ",", 64)
```

Result:

```text
["groceries", "electronics", "diy", "auto"]
```

## 17.3 WAF Rule-Generation Guidance

Do not generate `split()` for ordinary request WAF SQLi/XSS blocking unless the target product/phase supports it.

Use `split()` only when:

- the user explicitly asks for response header transform or custom error rule behavior
- parsing a delimited string is necessary and supported
- the expression context allows it

---

# 18. `substring()` Function

## 18.1 Definition

```text
substring(field String | Bytes, start Integer, end Integer optional) -> String
```

`substring()` returns part of a string or byte field.

- first byte has index `0`
- `end` is optional
- negative indexes access characters from the end

## 18.2 Examples

If `http.request.body.raw` is:

```text
asdfghjk
```

Then:

```text
substring(http.request.body.raw, 2, 5)
```

returns:

```text
dfg
```

Expression:

```text
substring(http.request.body.raw, -2)
```

returns:

```text
jk
```

## 18.3 Rule-Generation Use

Use `substring()` when:

- token validation needs a fixed prefix or suffix
- HMAC validation protects a fixed-length URI prefix
- a request field contains structured fixed-position data
- a function requires a portion of a larger field

## 18.4 HMAC URI Prefix Use Case

When protecting an entire fixed-length URI path prefix with a single signature, use `substring()` to obtain the protected prefix for the `MessageMAC` argument.

Pattern:

```text
not is_timed_hmac_valid_v0(
  "mysecretkey",
  concat(substring(http.request.uri.path, 0, 12), http.request.uri.query),
  10800,
  http.request.timestamp.sec,
  0
)
```

## 18.5 `substring()` Generation Checklist

- [ ] Use for fixed-position extraction.
- [ ] Use direct `starts_with()` or `ends_with()` for simple prefix/suffix checks.
- [ ] Avoid overusing for WAF attack detection when `contains` or `matches` is clearer.
- [ ] Explain the byte-index basis.

---

# 19. `to_string()` Function

## 19.1 Definition

```text
to_string(Integer | Boolean | IP address) -> String
```

`to_string()` returns the string representation of an integer, Boolean, or IP address.

Availability:

- rewrite expressions of Transform Rules
- target URL expressions of dynamic URL redirects

## 19.2 Examples

If `cf.bot_management.score` is `5`:

```text
to_string(cf.bot_management.score)
```

returns:

```text
5
```

If `ssl` is true:

```text
to_string(ssl)
```

returns:

```text
true
```

## 19.3 Rule-Generation Use

Use `to_string()` when a transform or redirect expression must construct a string from non-string values.

Do not use `to_string()` for ordinary WAF SQLi/XSS detection.

---

# 20. IP Network Functions: `cidr()` and `cidr6()`

## 20.1 `cidr()` Definition

```text
cidr(address IP address, ipv4_network_bits Integer, ipv6_network_bits Integer) -> IP address
```

`cidr()` returns the network address corresponding to an IPv4 or IPv6 address.

Constraints:

- `address` must be a field, not a literal string.
- IPv4 network bits must be between 1 and 32.
- IPv6 network bits must be between 1 and 128.

Availability:

- custom rules
- rate limiting rules

## 20.2 `cidr()` Example

If `ip.src` is:

```text
113.10.0.2
```

Then:

```text
cidr(ip.src, 24, 24)
```

returns:

```text
113.10.0.0
```

## 20.3 `cidr6()` Definition

```text
cidr6(address IP address, ipv6_network_bits Integer) -> IP address
```

`cidr6()` returns the IPv6 network address for an IPv6 address. If the input is IPv4, it returns the IPv4 address unchanged.

Equivalent to:

```text
cidr(<address>, 32, <ipv6_network_bits>)
```

Availability:

- custom rules
- rate limiting rules

## 20.4 Rule-Generation Use

Use `cidr()` or `cidr6()` when grouping IPs into network buckets for custom rules or rate limiting.

Example:

```text
cidr(ip.src, 24, 56) in {203.0.113.0}
```

## 20.5 Simpler CIDR Matching

For normal allowlists and blocklists, prefer direct CIDR membership with `in`:

```text
ip.src in {203.0.113.0/24 2001:db8::/32}
```

Do not generate equality with CIDR:

```text
ip.src eq 203.0.113.0/24
```

## 20.6 IP Network Function Checklist

- [ ] Use `in {CIDR}` for ordinary IP range matching.
- [ ] Use `cidr()` or `cidr6()` when network address computation is specifically needed.
- [ ] Do not pass literal strings as the address argument.
- [ ] Mention availability in custom rules and rate limiting rules.

---

# 21. `regex_replace()` Function

## 21.1 Definition

```text
regex_replace(source String, regular_expression String, replacement String) -> String
```

`regex_replace()` replaces the first part of a source string matched by a regular expression and returns the resulting string.

Constraints:

- replacement can reference capture groups such as `${1}` and `${2}`
- up to eight replacement references are supported
- only the first match is replaced
- matching is case-sensitive by default
- can only be used once in an expression
- cannot be nested with `wildcard_replace()`

Availability:

- rewrite expressions of Transform Rules
- target URL expressions of dynamic URL redirects

## 21.2 Examples

Literal replace:

```text
regex_replace("/foo/bar", "/bar$", "/baz") == "/foo/baz"
```

No match:

```text
regex_replace("/x", "^/y$", "/mumble") == "/x"
```

Capture group replacement:

```text
regex_replace("/foo/a/path", "^/foo/([^/]*)/(.*)$", "/bar/${2}/${1}") == "/bar/path/a/"
```

## 21.3 WAF Rule-Generation Guidance

Do not generate `regex_replace()` for ordinary WAF custom rule SQLi/XSS detection.

Use `matches`, `contains`, `lower()`, `url_decode()`, and `any()` for detection.

Use `regex_replace()` only when:

- the user asks for URL rewrite or dynamic redirect behavior
- the target product/phase supports it
- the expression is a rewrite expression, not a WAF attack-detection expression

## 21.4 Correct Detection Alternative

Instead of:

```text
regex_replace(http.request.uri.query, ".*<script.*", "x") == "x"
```

Generate:

```text
lower(http.request.uri.query) contains "<script"
```

or:

```text
lower(http.request.uri.query) matches r"(<script|onerror\s*=|javascript:)"
```

---

# 22. `wildcard_replace()` Function

## 22.1 Definition

```text
wildcard_replace(source Bytes, wildcard_pattern Bytes, replacement Bytes, flags Bytes optional) -> String
```

`wildcard_replace()` replaces a source string matched by a wildcard pattern and returns the result.

Constraints:

- source must be a field, not a literal string
- entire source value must match the wildcard pattern
- unescaped `**` in the wildcard pattern is invalid
- escape literal `*` with `\*`
- escape `\` with `\\`
- replacement can reference captures such as `${1}`
- set flag `"s"` for case-sensitive wildcard matching
- can only be used once in an expression
- cannot be nested with `regex_replace()`

Availability:

- URL rewrite expressions
- target URL expressions of dynamic URL redirects

## 22.2 Example: URI Path Rewrite

```text
wildcard_replace(http.request.uri.path, "/*", "/apps/${1}")
```

## 22.3 WAF Rule-Generation Guidance

Do not generate `wildcard_replace()` for ordinary XSS or SQLi detection.

Use only for rewrite/redirect generation.

For wildcard-like detection, use:

- `wildcard` operator when supported
- `contains`
- `matches`
- `starts_with()`
- `ends_with()`

---

# 23. `remove_query_args()` Function

## 23.1 Definition

```text
remove_query_args(field String, query_param1 String, query_param2 String, ...) -> String
```

`remove_query_args()` removes one or more query string parameters from a URI query string.

The field must be one of:

```text
http.request.uri.query
raw.http.request.uri.query
```

The field cannot be a literal value.

Availability:

- rewrite expressions of Transform Rules

## 23.2 Examples

If `http.request.uri.query` is:

```text
order=asc&country=GB
```

Then:

```text
remove_query_args(http.request.uri.query, "country")
```

returns:

```text
order=asc
```

If `http.request.uri.query` is:

```text
category=Foo&order=desc&category=Bar
```

Then:

```text
remove_query_args(http.request.uri.query, "category")
```

returns:

```text
order=desc
```

## 23.3 Rule-Generation Guidance

Do not use `remove_query_args()` to detect attacks.

Use it only for query string rewrite behavior.

If the goal is to block requests containing dangerous parameters, generate a WAF custom rule with `has_key()` or query-field matching:

```text
has_key(http.request.uri.args, "cmd")
or has_key(http.request.uri.args, "exec")
```

---

# 24. `remove_bytes()` Function

## 24.1 Definition

```text
remove_bytes(Bytes) -> Bytes
```

`remove_bytes()` returns a byte array with specified bytes removed.

## 24.2 Example

If `http.host` is:

```text
www.cloudflare.com
```

Then a remove-byte style expression can return:

```text
cloudflarecom
```

## 24.3 WAF Rule-Generation Guidance

`remove_bytes()` is not a primary WAF custom-rule detection function for SQLi or XSS.

Prefer:

- `lower()`
- `url_decode()`
- `contains`
- `matches`
- `any()`

Use `remove_bytes()` only when the user specifically needs byte-level normalization and the target context supports it.

---

# 25. `sha256()` Function

## 25.1 Definition

```text
sha256(input String | Bytes) -> Bytes
```

`sha256()` computes a SHA-256 cryptographic hash of the input string or byte array and returns a 32-byte hash.

Availability:

- Enterprise add-on
- specific entitlement required
- rewrite expressions of Transform Rules

## 25.2 Examples

```text
sha256("my-token")
```

Combined with Base64 encoding:

```text
encode_base64(sha256("my-token"))
```

Signed request header style:

```text
encode_base64(sha256(concat(to_string(ip.src), to_string(http.request.timestamp.sec), "my-secret-key")))
```

## 25.3 Rule-Generation Guidance

Do not generate `sha256()` for ordinary WAF custom SQLi/XSS detection.

Use `sha256()` only when:

- the user asks for signed headers
- the target context is a Transform Rule
- the account has the required entitlement
- the output is used for request signing or validation workflows

For HMAC token validation in WAF custom rules, prefer `is_timed_hmac_valid_v0()`.

---

# 26. `uuidv4()` Function

## 26.1 Definition

```text
uuidv4(source Bytes) -> String
```

`uuidv4()` generates a random UUIDv4 from a source of randomness. Use `cf.random_seed` as the randomness source.

Example:

```text
uuidv4(cf.random_seed)
```

Availability:

- rewrite expressions of Transform Rules

## 26.2 Rule-Generation Guidance

Do not use `uuidv4()` for WAF SQLi/XSS detection.

Use it only for transform workflows that need a generated request ID, trace ID, or similar header value.

---

# 27. HMAC Validation with `is_timed_hmac_valid_v0()`

## 27.1 Definition

```text
is_timed_hmac_valid_v0(
  <String literal as Key>,
  <String field as MessageMAC>,
  <Integer literal as ttl>,
  <Integer as currentTimeStamp>,
  <Optional Integer literal as lengthOfSeparator, default: 0>,
  <Optional String literal as flags>
) -> Boolean
```

`is_timed_hmac_valid_v0()` validates a hash-based message authentication code (HMAC) token.

Availability:

- Cloudflare Pro, Business, or Enterprise plan.

## 27.2 Parameter Meanings

| Parameter | Type | Meaning |
|---|---|---|
| `Key` | String literal | Secret cryptographic key used to validate the HMAC. |
| `MessageMAC` | String field | Concatenation of message, separator, timestamp, and MAC. |
| `ttl` | Integer literal | Time-to-live in seconds. |
| `currentTimeStamp` | Integer field | Current timestamp, usually `http.request.timestamp.sec`. |
| `lengthOfSeparator` | Optional integer literal | Separator byte length between timestamp and message in `MessageMAC`. Default is `0`. |
| `flags` | Optional string literal | Use `'s'` for URL-safe Base64 MAC with no padding. |

## 27.3 MessageMAC Structure

A valid `MessageMAC` satisfies this pattern:

```text
(.+)(.*)(\d{10})-(.{43,})
```

Components:

| Component | Meaning | Example |
|---|---|---|
| `message` | The protected message, often a URI path or URI. | `/download/cat.jpg` |
| `separator` | Separator between message and timestamp. | `?verify=` or `&verify=` |
| `timestamp` | 10-digit UNIX timestamp in seconds. | `1484063137` |
| `mac` | Base64-encoded MAC. | `IaLGSmELTvlhfd0ItdN6PhhHTFhzx73EX8uy%2FcSDiIU%3D` |

## 27.4 Important MAC Encoding Rule

When the optional `flags` argument is not set to `'s'`, the Base64 MAC in the `MessageMAC` argument must be URL encoded.

When using URL-safe Base64 with no padding, set the optional flags argument to `'s'`.

## 27.5 Basic Token Authentication Rule

This expression blocks requests to a protected host and path that do not have a valid HMAC token:

```text
http.host eq "downloads.example.com"
and not is_timed_hmac_valid_v0(
  "mysecretkey",
  http.request.uri,
  10800,
  http.request.timestamp.sec,
  8
)
```

Recommended action:

```json
{
  "action": "block"
}
```

## 27.6 HMAC URL Example

Protected URL:

```text
/download/cat.jpg?verify=1484063787-IaLGSmELTvlhfd0ItdN6PhhHTFhzx73EX8uy%2FcSDiIU%3D
```

Mapping:

| HMAC element | Value |
|---|---|
| `message` | `/download/cat.jpg` |
| `separator` | `?verify=` |
| `timestamp` | `1484063787` |
| `mac` | `IaLGSmELTvlhfd0ItdN6PhhHTFhzx73EX8uy%2FcSDiIU%3D` |

In this case, separator length is:

```text
8
```

because:

```text
len("?verify=") == 8
```

## 27.7 Token Expiration Logic

The HMAC token is valid only if:

```text
http.request.timestamp.sec < (<TIMESTAMP_ISSUED> + ttl)
```

For a 3-hour token:

```text
ttl = 10800
```

## 27.8 Token Parameter Ordering Constraint

The authentication token parameter must be the last parameter in the query string.

Example valid pattern:

```text
/images/cat.jpg?verify=<timestamp>-<mac>
```

If there are other query parameters, the token must appear last.

## 27.9 HMAC with `concat()`

Use `concat()` when the `MessageMAC` is composed from more than one field.

```text
is_timed_hmac_valid_v0(
  "mysecretkey",
  concat(
    http.request.uri,
    http.request.headers["timestamp"][0],
    "-",
    http.request.headers["mac"][0]
  ),
  100000,
  http.request.timestamp.sec,
  0
)
```

## 27.10 HMAC Rule JSON Pattern

```json
{
  "description": "Block downloads without a valid HMAC token",
  "expression": "http.host eq \"downloads.example.com\" and not is_timed_hmac_valid_v0(\"mysecretkey\", http.request.uri, 10800, http.request.timestamp.sec, 8)",
  "action": "block",
  "enabled": true
}
```

## 27.11 HMAC Generation Checklist

- [ ] Use only for token authentication or signed URL validation.
- [ ] Use a string literal for the secret key.
- [ ] Use a string field for `MessageMAC`.
- [ ] Use an integer literal for TTL.
- [ ] Use `http.request.timestamp.sec` for current timestamp.
- [ ] Set separator length correctly.
- [ ] URL-encode the Base64 MAC unless using URL-safe no-padding mode with `'s'`.
- [ ] Ensure the token parameter is last in the query string.
- [ ] Use `block` for invalid tokens.
- [ ] Use `log` first for testing if available.

---

# 28. `lookup_json_string()` and HMAC Are Not SQLi/XSS Replacements

## 28.1 Rule-Generation Boundary

Some functions are security-related but not general SQLi/XSS detection replacements.

| Function | Security use | Not suitable as |
|---|---|---|
| `is_timed_hmac_valid_v0()` | signed URL / token authentication | generic SQLi/XSS detection |
| `lookup_json_string()` | JSON property extraction | complete body parser for arbitrary payloads |
| `sha256()` | signing / transform workflows | WAF SQLi/XSS block signal |
| `uuidv4()` | request ID generation | attack detection |
| `regex_replace()` | rewrite/redirect transformation | WAF attack matching |
| `wildcard_replace()` | rewrite/redirect transformation | WAF attack matching |
| `remove_query_args()` | query rewrite | attack detection |

## 28.2 Correct SQLi/XSS Function Choices

For SQLi/XSS WAF rule generation, prefer:

- `lower()`
- `url_decode()`
- `any()`
- `starts_with()`
- `ends_with()`
- `has_key()`
- `has_value()`
- `len()`
- `lookup_json_string()` only for known JSON body fields

---

# 29. Network Firewall Function: `bit_slice`

## 29.1 Definition

```text
bit_slice(protocol String, offset_start Number, offset_end Number) -> Number
```

`bit_slice()` matches a slice of bits in a network protocol header. It is primarily intended for use with `ip`, `udp`, and `tcp`.

Constraints:

- slice length cannot exceed 32 bits
- multiple calls can be joined with logical expressions
- offset cannot exceed 2,040 bits

## 29.2 WAF Rule-Generation Guidance

Do not generate `bit_slice()` for HTTP WAF custom rules, SQLi detection, XSS detection, Cloudflare WAF expression generation, or Ruleset Engine HTTP request rules.

Use only when the user asks for Cloudflare Network Firewall logic involving IP, UDP, or TCP bit-level matching.

---

# 30. Function-Aware XSS Rule Patterns

## 30.1 Query String XSS with Case Normalization

```json
{
  "description": "Block XSS indicators in query string",
  "expression": "lower(http.request.uri.query) contains \"<script\" or lower(http.request.uri.query) contains \"onerror=\" or lower(http.request.uri.query) contains \"javascript:\"",
  "action": "block",
  "enabled": true
}
```

Functions used:

- `lower()` for case normalization.

## 30.2 Query String XSS with URL Decoding

```json
{
  "description": "Block URL-decoded XSS indicators in query string",
  "expression": "lower(url_decode(http.request.uri.query, \"r\")) contains \"<script\" or lower(url_decode(http.request.uri.query, \"r\")) contains \"onerror=\" or lower(url_decode(http.request.uri.query, \"r\")) contains \"javascript:\"",
  "action": "block",
  "enabled": true
}
```

Functions used:

- `url_decode(..., "r")` for recursive URL decoding.
- `lower()` for case normalization.

## 30.3 Parameter-Specific XSS with `any()`

```json
{
  "description": "Block XSS indicators in q query parameter",
  "expression": "any(lower(http.request.uri.args[\"q\"][*])[*] contains \"<script\") or any(lower(http.request.uri.args[\"q\"][*])[*] contains \"onerror=\") or any(lower(http.request.uri.args[\"q\"][*])[*] contains \"javascript:\")",
  "action": "block",
  "enabled": true
}
```

Functions used:

- `any()` for repeated parameter values.
- `lower()` for case normalization.

## 30.4 Path-Scoped XSS with `starts_with()`

```json
{
  "description": "Block XSS indicators on search endpoints",
  "expression": "starts_with(http.request.uri.path, \"/search\") and (lower(http.request.uri.query) contains \"<script\" or lower(http.request.uri.query) contains \"onerror=\" or lower(http.request.uri.query) contains \"javascript:\")",
  "action": "block",
  "enabled": true
}
```

Functions used:

- `starts_with()` for endpoint scope.
- `lower()` for case normalization.

---

# 31. Function-Aware SQL Injection Rule Patterns

## 31.1 Query String SQLi with Case Normalization

```json
{
  "description": "Block SQL injection indicators in query string",
  "expression": "lower(http.request.uri.query) contains \"union select\" or lower(http.request.uri.query) contains \"or 1=1\" or lower(http.request.uri.query) contains \"sleep(\" or lower(http.request.uri.query) contains \"benchmark(\"",
  "action": "block",
  "enabled": true
}
```

Functions used:

- `lower()` for SQL keyword case normalization.

## 31.2 Query String SQLi with URL Decoding

```json
{
  "description": "Block URL-decoded SQL injection indicators in query string",
  "expression": "lower(url_decode(http.request.uri.query, \"r\")) contains \"union select\" or lower(url_decode(http.request.uri.query, \"r\")) contains \"or 1=1\" or lower(url_decode(http.request.uri.query, \"r\")) contains \"sleep(\"",
  "action": "block",
  "enabled": true
}
```

Functions used:

- `url_decode(..., "r")` for recursive URL decoding.
- `lower()` for case normalization.

## 31.3 Parameter-Specific SQLi with `any()`

```json
{
  "description": "Block SQL injection indicators in id query parameter",
  "expression": "any(lower(http.request.uri.args[\"id\"][*])[*] matches r\"(union\\s+select|or\\s+1\\s*=\\s*1|sleep\\s*\\()\")",
  "action": "block",
  "enabled": true
}
```

Functions used:

- `any()` for repeated `id` values.
- `lower()` for case normalization.

## 31.4 Length-Assisted SQLi Detection

```json
{
  "description": "Block unusually long SQLi-like search query",
  "expression": "starts_with(http.request.uri.path, \"/search\") and len(http.request.uri.query) gt 512 and lower(http.request.uri.query) matches r\"(union\\s+select|or\\s+1\\s*=\\s*1|sleep\\s*\\()\"",
  "action": "block",
  "enabled": true
}
```

Functions used:

- `starts_with()` for path scope.
- `len()` for request-shape condition.
- `lower()` for case normalization.

---

# 32. Function Availability and Phase Matrix

| Function | Good for WAF custom rules? | Main constraints |
|---|---:|---|
| `any` | Yes | Use with arrays of Booleans. |
| `all` | Conditional | Use only when every array value must match. |
| `lower` | Yes | ASCII case conversion. |
| `upper` | Conditional | Less common than `lower()`. |
| `url_decode` | Yes | Source must be a field; use options for recursive/Unicode decoding. |
| `starts_with` | Yes | Function call only, not operator syntax. |
| `ends_with` | Yes | Function call only, not operator syntax. |
| `has_key` | Yes | Use with maps. |
| `has_value` | Yes | Collection and value types must match. |
| `len` | Yes | Use for string, bytes, or array length. |
| `lookup_json_string` | Conditional | Field must be valid JSON string; body support required. |
| `lookup_json_integer` | Conditional | Plain integers only; body support required. |
| `decode_base64` | Conditional | Supported in Transform Rules, custom rules, and rate limiting rules. |
| `encode_base64` | No for WAF detection | Header transform rules only. |
| `concat` | Conditional | Useful for HMAC; avoid unnecessary use. |
| `join` | Conditional | Supported in Transform Rules, custom rules, and Custom Error Rules. |
| `split` | No for ordinary WAF | Response header transform and Custom Error Rules. |
| `substring` | Conditional | Use for fixed-position extraction or HMAC prefix workflows. |
| `to_string` | No for WAF detection | Transform Rules and dynamic redirects. |
| `cidr` | Conditional | Custom rules and rate limiting; address must be a field. |
| `cidr6` | Conditional | Custom rules and rate limiting; address must be a field. |
| `regex_replace` | No for WAF detection | Rewrite expressions and dynamic redirects only. |
| `wildcard_replace` | No for WAF detection | URL rewrites and dynamic redirects only. |
| `remove_query_args` | No for WAF detection | Transform Rule rewrite expressions only. |
| `remove_bytes` | Rare | Byte-level normalization only when supported and required. |
| `sha256` | No for WAF detection | Enterprise entitlement; Transform Rules. |
| `uuidv4` | No for WAF detection | Transform Rules. |
| `is_timed_hmac_valid_v0` | Yes for token auth | Pro/Business/Enterprise; custom rules. |
| `bit_slice` | No for HTTP WAF | Cloudflare Network Firewall only. |

---

# 33. Common Function Mistakes and Corrections

## 33.1 Incorrect: `starts_with` as Operator

Incorrect:

```text
http.request.uri.path starts_with "/api/"
```

Correct:

```text
starts_with(http.request.uri.path, "/api/")
```

## 33.2 Incorrect: Array Wildcard Without `any()`

Incorrect:

```text
http.request.headers["user-agent"][*] contains "sqlmap"
```

Correct:

```text
any(lower(http.request.headers["user-agent"][*])[*] contains "sqlmap")
```

## 33.3 Incorrect: Missing `[*]` After Array Transformation

Risky or invalid:

```text
any(lower(http.request.headers.names[*]) == "content-type")
```

Correct:

```text
any(lower(http.request.headers.names[*])[*] == "content-type")
```

## 33.4 Incorrect: Literal Passed to `url_decode()`

Incorrect:

```text
url_decode("%3cscript%3e")
```

Correct field-based expression:

```text
url_decode(http.request.uri.query) contains "<script"
```

## 33.5 Incorrect: Rewrite Function for WAF Detection

Incorrect:

```text
regex_replace(http.request.uri.query, ".*<script.*", "x") == "x"
```

Correct:

```text
lower(http.request.uri.query) contains "<script"
```

or:

```text
lower(http.request.uri.query) matches r"(<script|onerror\s*=|javascript:)"
```

## 33.6 Incorrect: `all()` for Attack Detection

Incorrect:

```text
all(lower(http.request.uri.args.values[*])[*] contains "<script")
```

Correct:

```text
any(lower(http.request.uri.args.values[*])[*] contains "<script")
```

## 33.7 Incorrect: HMAC Without Negation for Blocking Invalid Tokens

Risky:

```text
is_timed_hmac_valid_v0("mysecretkey", http.request.uri, 10800, http.request.timestamp.sec, 8)
```

If paired with `block`, this blocks valid tokens.

Correct:

```text
not is_timed_hmac_valid_v0("mysecretkey", http.request.uri, 10800, http.request.timestamp.sec, 8)
```

When paired with `block`, this blocks invalid tokens.

---

# 34. Function Decision Matrix for Rule Generation

| Observed requirement | Preferred function pattern |
|---|---|
| Case-randomized XSS or SQLi | `lower(field)` |
| Query-string XSS | `lower(http.request.uri.query)` |
| URL-encoded XSS/SQLi | `lower(url_decode(field, "r"))` or raw encoded checks |
| Known query parameter | `any(lower(http.request.uri.args["param"][*])[*] ...)` |
| Header value matching | `any(lower(http.request.headers["name"][*])[*] ...)` |
| Body form value matching | `any(lower(http.request.body.form.values[*])[*] ...)` |
| URL-decoded form values | `any(url_decode(http.request.body.form.values[*])[*] ...)` |
| Path prefix scope | `starts_with(http.request.uri.path, "/path")` |
| Path suffix or extension scope | `ends_with(http.request.uri.path, ".php")` |
| Map key existence | `has_key(map, "key")` |
| Collection exact value | `has_value(collection, value)` |
| Long payload or value | `len(field) gt N` |
| JSON body string property | `lookup_json_string(http.request.body.raw, "key")` |
| JSON body integer property | `lookup_json_integer(http.request.body.raw, "key")` |
| Base64 field payload | `decode_base64(field)` with `any()` if array |
| Signed URL protection | `not is_timed_hmac_valid_v0(...)` |
| Network range grouping | `cidr(ip.src, bits, bits)` or direct `ip.src in {CIDR}` |
| URI rewrite | `regex_replace`, `wildcard_replace`, `remove_query_args` |
| Ordinary SQLi/XSS detection | Avoid rewrite-only functions; use `lower`, `url_decode`, `any`, `contains`, `matches` |

---

# 35. Final Template for Function-Aware Cloudflare WAF Rule Generation

Use this structure when generating Cloudflare WAF rules that rely on functions.

```markdown
## Rule Objective

Describe:
- attack type
- payload location
- bypass technique
- intended action

## Selected Functions

List:
- function name
- reason for use
- field it applies to
- product/phase/plan limitation if any

## Proposed Expression

Provide the Cloudflare Rules language expression.

## Proposed Rule JSON

Provide JSON with:
- description
- expression
- action
- enabled
- action_parameters if needed

## Function Rationale

Explain:
- why `lower()`, `url_decode()`, `any()`, `starts_with()`, or other functions are used
- how the function handles the bypass
- whether arrays/maps require `[*]`, `any()`, or `has_key()`
- whether the function is valid in WAF custom rules
- whether a fallback expression is needed

## False Positive and Tuning Notes

Explain:
- broad matching risks
- path/host/method/parameter scoping
- trusted IP or verified bot exceptions
- whether to start with log/challenge/block
```

---

# 36. Final Checklist for Cloudflare Function Use

- [ ] Use `lower()` for case-insensitive XSS/SQLi matching.
- [ ] Use `url_decode()` when encoded or double-encoded payloads are observed.
- [ ] Use `url_decode(..., "r")` for recursive decoding.
- [ ] Use `url_decode(..., "u")` for Unicode percent decoding.
- [ ] Use `any()` for array-wide attack detection.
- [ ] Use `all()` only when every array element must match.
- [ ] Use `starts_with()` and `ends_with()` as functions, not operators.
- [ ] Use `has_key()` for map-key existence.
- [ ] Use `has_value()` for exact collection membership.
- [ ] Use `len()` for length-based conditions.
- [ ] Use JSON lookup functions only on valid JSON string fields.
- [ ] Use `decode_base64()` only when encoded field values are expected.
- [ ] Do not use `encode_base64()` for ordinary WAF detection.
- [ ] Do not use `regex_replace()` or `wildcard_replace()` for ordinary WAF detection.
- [ ] Do not use `remove_query_args()` for attack detection.
- [ ] Use `is_timed_hmac_valid_v0()` only for signed URL or token-authentication rules.
- [ ] For HMAC blocking, use `not is_timed_hmac_valid_v0(...)`.
- [ ] Mention plan, product, or phase restrictions.
- [ ] Keep expressions readable and scoped to reduce false positives.
