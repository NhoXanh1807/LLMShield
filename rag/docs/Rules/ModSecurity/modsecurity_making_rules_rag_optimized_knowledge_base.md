# ModSecurity Rule Authoring Knowledge Base for RAG and WAF Rule Generation
# 1. ModSecurity Rule Authoring Overview
## 1.1 ModSecurity `SecRule` Definition

A `SecRule` is a ModSecurity directive used to inspect transaction data and apply actions when a match occurs. Unlike many other directives that are evaluated at startup, each `SecRule` in the configuration is evaluated on every transaction.

A `SecRule` is composed of four main parts:

| Part | Purpose | Rule-generation meaning |
|---|---|---|
| Variables | Tell ModSecurity **where** to look. Variables are sometimes called targets. | Select the request component: URI, arguments, headers, cookies, body, files, response, or collections. |
| Operators | Tell ModSecurity **when** to trigger a match. | Select string, regex, numeric, validation, or specialized detection logic. |
| Transformations | Tell ModSecurity **how** to normalize variable data before matching. | Apply decoding, case normalization, whitespace removal, entity decoding, path normalization, or anti-evasion processing. |
| Actions | Tell ModSecurity **what** to do when a rule matches. | Set phase, rule ID, logging, blocking, status code, tags, severity, score, capture, or flow behavior. |

Canonical syntax:

```apache
SecRule VARIABLES "OPERATOR" "TRANSFORMATIONS,ACTIONS"
```

Example:

```apache
SecRule REQUEST_URI "@streq /index.php" "id:1,phase:1,t:lowercase,deny"
```

## 1.2 What the Basic Example Does

Example rule:

```apache
SecRule REQUEST_URI "@streq /index.php" "id:1,phase:1,t:lowercase,deny"
```

This rule:

1. Selects the `REQUEST_URI` variable.
2. Applies the `t:lowercase` transformation to normalize URI case.
3. Uses the `@streq` operator to compare the transformed URI to `/index.php`.
4. Runs in `phase:1`.
5. Uses `deny` as the disruptive action when the rule matches.
6. Uses `id:1` as the rule ID.

Rule-generation interpretation:

- `REQUEST_URI` is the request component.
- `@streq /index.php` is the exact-string match condition.
- `t:lowercase` is the normalization step.
- `deny` blocks/intercepts the request when matched.
- `phase:1` runs early in the request lifecycle.

## 1.3 Why `SecRule` Is Powerful

`SecRule` is effectively a rule language. It can combine:

- many variables
- collection iteration
- indexed collection access
- multiple variables with pipe `|`
- exclusions with `!`
- regex and specialized operators
- transformation pipelines
- chained rules
- capture and transaction variables
- disruptive, flow, metadata, logging, and variable actions

A WAF rule generator should treat `SecRule` as structured logic, not just a simple pattern matcher.

---

# 2. Core `SecRule` Syntax for Generation

## 2.1 Canonical Rule Structure

```apache
SecRule VARIABLES "OPERATOR" "ACTIONS"
```

Where:

```text
VARIABLES = where ModSecurity inspects
OPERATOR  = condition that triggers a match
ACTIONS   = metadata, transformations, logging, blocking, and flow behavior
```

Expanded pattern:

```apache
SecRule <VARIABLES> "<OPERATOR> <OPERATOR_ARGUMENT>" "id:<ID>,phase:<PHASE>,t:<TRANSFORMATION>,<ACTION>,status:<STATUS>,msg:'<MESSAGE>',tag:'<TAG>'"
```

## 2.2 Minimal Rule Example

```apache
SecRule ARGS "@contains test" "id:1001,phase:2,t:none,t:lowercase,deny,status:403,msg:'Detected test string in arguments'"
```

This rule:

- inspects all request arguments using `ARGS`
- checks if any argument contains `test`
- clears inherited transformations with `t:none`
- lowercases input using `t:lowercase`
- denies the request with HTTP status `403`
- assigns an ID and message

## 2.3 Required Components for Rule Generation

A generated rule should include:

| Required or strongly recommended element | Why it matters |
|---|---|
| Variable | Without a variable, ModSecurity does not know where to inspect. |
| Operator | Without an explicit operator, `@rx` is implied, but explicit operators are clearer. |
| Rule ID | `id` is required in practical rule sets and strongly recommended by ModSecurity documentation. |
| Phase | Defines when the rule runs. If omitted, defaults can apply, often `phase:2`. |
| Disruptive or non-disruptive action | Defines enforcement behavior such as `deny`, `block`, `pass`, or logging only. |
| Transformations | Optional, but essential to prevent bypass for XSS, SQLi, encoding, and whitespace evasion. |
| Message and tags | Improve audit logs, maintainability, and CRS-style classification. |

## 2.4 Safer Generated Rule Template

```apache
SecRule <VARIABLES> "<OPERATOR>" \
  "id:<UNIQUE_ID>,phase:<PHASE>,t:none,<TRANSFORMATIONS>,<DISRUPTIVE_ACTION>,status:<STATUS>,log,auditlog,msg:'<CLEAR_MESSAGE>',tag:'attack-<TYPE>',severity:'CRITICAL'"
```

Example XSS template:

```apache
SecRule ARGS|REQUEST_COOKIES|REQUEST_HEADERS "@rx (?i)<\s*script\b|onerror\s*=|javascript:" \
  "id:100100,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,t:compressWhitespace,deny,status:403,log,auditlog,msg:'XSS payload detected in request input',tag:'attack-xss',severity:'CRITICAL'"
```

Example SQLi template:

```apache
SecRule ARGS|REQUEST_COOKIES|REQUEST_HEADERS "@rx (?i)(union\s+select|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema)" \
  "id:100101,phase:2,t:none,t:urlDecodeUni,t:lowercase,t:replaceComments,t:compressWhitespace,deny,status:403,log,auditlog,msg:'SQL injection payload detected in request input',tag:'attack-sqli',severity:'CRITICAL'"
```

---

# 3. `SecRule` Components at a Glance

## 3.1 Variables

Variables tell ModSecurity where to inspect.

Common rule-generation variables:

| Variable | Meaning | Use in generated WAF rules |
|---|---|---|
| `REQUEST_URI` | Full request URI path and query. | Broad URI matching, path + query inspection. |
| `REQUEST_FILENAME` | Request URI path without query string. | Path-specific matching and path traversal checks. |
| `ARGS` | All request arguments including GET and POST arguments. | Default target for XSS/SQLi in parameters. |
| `ARGS_GET` | Query-string arguments. | GET/query-specific payload matching. |
| `ARGS_POST` | POST body arguments. | Form body parameter matching. |
| `ARGS_NAMES` | Names of request arguments. | Detect suspicious parameter names like `cmd`, `exec`, `redirect`. |
| `REQUEST_HEADERS` | Request headers as a collection. | Header payload and scanner User-Agent checks. |
| `REQUEST_HEADERS:User-Agent` | Specific User-Agent header. | Scanner, bot, or header-based payload detection. |
| `REQUEST_COOKIES` | Cookie values. | Cookie-based XSS/SQLi detection. |
| `REQUEST_COOKIES_NAMES` | Cookie names. | Suspicious cookie name detection. |
| `REQUEST_BODY` | Raw or parsed request body depending on configuration. | Body payload detection when body inspection is enabled. |
| `FILES`, `FILES_NAMES`, `FILES_TMPNAMES` | Uploaded file metadata/content variables. | Upload abuse or malicious filename checks. |
| `REMOTE_ADDR` | Client source address. | IP allowlists, blocklists, or exceptions. |
| `TX` | Transaction variables. | Chained rules, scoring, captured data, anomaly scoring. |
| `MATCHED_VAR` | Last matched variable value. | Logging and chained follow-up checks. |
| `MATCHED_VAR_NAME` | Name of matched variable. | Logging and targeted false-positive tuning. |

## 3.2 Operators

Operators tell ModSecurity when to match.

Common rule-generation operators:

| Operator | Meaning | Good use |
|---|---|---|
| `@rx` | Regular expression match. | Flexible XSS/SQLi detection. Default if no operator is listed. |
| `@contains` | Substring match. | Stable literal indicators such as `<script`, `union select`. |
| `@containsWord` | Word-boundary-aware substring match. | SQL keywords like `select` with boundaries. |
| `@streq` | Exact string equality. | Exact URI, method, fixed values. |
| `@beginsWith` | Prefix match. | Path or request-line prefix. |
| `@endsWith` | Suffix match. | Extension or suffix checks. |
| `@pm` | Phrase match against multiple phrases. | Multiple stable payload indicators. |
| `@detectXSS` | libinjection XSS detection. | Specialized XSS detection. |
| `@detectSQLi` | libinjection SQLi detection. | Specialized SQL injection detection. |
| `@validateUrlEncoding` | URL encoding validation. | Detect malformed URL encoding. |
| `@validateUtf8Encoding` | UTF-8 validation. | Detect invalid UTF-8 input. |
| `@eq`, `@gt`, `@ge`, `@lt`, `@le` | Numeric comparison. | Score thresholds, lengths, counts. |

## 3.3 Transformations

Transformations normalize data before matching.

Common rule-generation transformations:

| Transformation | Meaning | Good use |
|---|---|---|
| `t:none` | Clears inherited transformations. | Start every custom rule with explicit transformations. |
| `t:lowercase` | Converts input to lowercase. | Case-randomized XSS/SQLi. |
| `t:urlDecodeUni` | URL-decodes including Unicode encodings. | Encoded XSS/SQLi payloads. |
| `t:htmlEntityDecode` | Decodes HTML entities. | XSS payloads using `&lt;script&gt;`. |
| `t:compressWhitespace` | Compresses whitespace. | SQLi or XSS with extra whitespace. |
| `t:removeWhitespace` | Removes whitespace. | XSS tag bypass such as `<sCript >`. Use carefully because it may alter benign content. |
| `t:removeNulls` | Removes null bytes. | Null-byte obfuscation. |
| `t:replaceComments` | Replaces SQL comments. | SQLi using comments such as `/**/`. |
| `t:normalisePath` / `t:normalizePath` | Normalizes path. | Path traversal and path canonicalization. |
| `t:jsDecode` | Decodes JavaScript escapes. | XSS with JS escape sequences. |
| `t:cssDecode` | Decodes CSS escapes. | XSS in CSS contexts. |
| `t:base64Decode` | Decodes Base64. | Payloads transported in Base64 fields. |

## 3.4 Actions

Actions tell ModSecurity what to do when a rule matches.

Common rule-generation actions:

| Action category | Examples | Use |
|---|---|---|
| Disruptive actions | `deny`, `block`, `drop`, `proxy`, `redirect`, `allow` | Enforce, block, intercept, or alter transaction handling. |
| Flow actions | `chain`, `skip`, `skipAfter` | Build multi-condition logic or skip sections. |
| Metadata actions | `id`, `phase`, `msg`, `severity`, `tag`, `rev` | Identify, classify, and document the rule. |
| Variable actions | `setvar`, `capture`, `initcol` | Store captures, scores, and transaction state. |
| Logging actions | `log`, `auditlog`, `nolog`, `sanitiseArg` | Control security logs and audit data. |
| Miscellaneous actions | `ctl`, `multiMatch`, `exec`, `pause`, `append`, `prepend` | Advanced controls and integrations. |

---

# 4. Essential Rule Authoring Rules

## 4.1 Mandatory and Implied Rule Parts

When generating or reviewing a `SecRule`, remember:

1. Every `SecRule` must have a variable.
2. Every `SecRule` must have an operator. If no operator is listed, `@rx` is implied.
3. Every `SecRule` must have an action list. The only strictly required action is `id`, but other actions are often inherited from `SecDefaultAction`.
4. Every rule should have a `phase` action. If omitted, a default phase can apply, commonly `phase:2`.
5. Every enforcement rule should have a disruptive action such as `deny`, `block`, or `drop`. If no disruptive action is included, the default can be `pass`.
6. Transformations are optional but should be used to prevent bypass.
7. For generated rules, start with `t:none` and then add only the transformations required for the attack surface.
8. Prefer explicit behavior over relying on `SecDefaultAction`.

## 4.2 Why Transformations Should Be Explicit

Transformations can be inherited from `SecDefaultAction`. Relying on inherited transformations creates maintenance risk and can make rules behave differently across deployments.

Recommended pattern:

```apache
SecRule ARGS "@rx (?i)<script" "id:100200,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,deny,status:403,log,msg:'XSS payload detected'"
```

Avoid:

```apache
SecRule ARGS "@rx (?i)<script" "id:100200,deny"
```

The second rule depends on hidden defaults and may fail to normalize evasive payloads.

## 4.3 Rule-Generation Checklist

- [ ] Use a clear target variable or collection.
- [ ] Use an explicit operator.
- [ ] Include a unique `id`.
- [ ] Include an explicit `phase`.
- [ ] Include a clear action: `deny`, `block`, `pass`, `log`, or scoring.
- [ ] Include `t:none`.
- [ ] Add appropriate transformations for the bypass class.
- [ ] Add `msg`, `tag`, and `severity`.
- [ ] Include `status:403` or another response status when using `deny`.
- [ ] Avoid overbroad targets if the payload location is known.

---

# 5. Variable Categories for Rule Generation

## 5.1 Request Variables

Request variables are the most important category for XSS and SQL injection WAF rules.

Examples:

```text
ARGS
ARGS_GET
ARGS_POST
ARGS_NAMES
REQUEST_URI
REQUEST_FILENAME
REQUEST_HEADERS
REQUEST_COOKIES
REQUEST_BODY
FILES
```

Use request variables when the payload appears in:

- URL query string
- GET parameter
- POST form parameter
- JSON/form body
- cookie
- request header
- User-Agent
- path
- uploaded filename or file content

## 5.2 Response Variables

Response variables inspect server response data.

Examples:

```text
RESPONSE_HEADERS
RESPONSE_BODY
```

Use response variables for:

- detecting sensitive data leakage
- missing security headers
- response-side policy checks
- virtual patching involving response content

Do not use response variables for ordinary request-side XSS or SQLi blocking unless the rule intentionally inspects responses.

## 5.3 Server Variables

Server variables represent server-side request context.

Examples:

```text
REMOTE_ADDR
AUTH_TYPE
```

Use server variables for:

- IP allowlists or blocklists
- authentication-state-aware rules
- environment-specific exceptions

## 5.4 Time Variables

Time variables are useful for time-based logic.

Examples:

```text
TIME
TIME_EPOCH
TIME_HOUR
```

Use time variables for:

- temporary rules
- time-windowed policy
- business-hour controls
- logging or scoring logic

## 5.5 Collection Variables

Collection variables store transaction, session, IP, or geolocation state.

Examples:

```text
TX
IP
SESSION
GEO
```

Use collection variables for:

- chained rule scoring
- anomaly scoring
- per-IP counters
- session-based rules
- storing captured values

## 5.6 Miscellaneous Variables

Examples:

```text
HIGHEST_SEVERITY
MATCHED_VAR
MATCHED_VAR_NAME
MATCHED_VARS
```

Use miscellaneous variables for:

- logging which variable matched
- chained follow-up logic
- tuning false positives
- anomaly score aggregation

---

# 6. Advanced Variable Usage

## 6.1 Collections

Some ModSecurity variables are collections. A collection is similar to a dictionary or map. It stores key-value pairs.

Example request:

```text
http://www.example.com?x=test&y=test2
```

Conceptual collection:

```text
ARGS_GET = {
  "x": "test",
  "y": "test2"
}
```

When a collection is used directly in a `SecRule`, ModSecurity iterates over each value in the collection. It applies transformations and operators to each value until it finds a match. If it finds a match, it stops processing that rule and performs the actions.

Example:

```apache
SecRule ARGS_GET "@contains test" "id:200001,phase:1,t:none,t:lowercase,deny,status:403,msg:'Blocked test value in GET arguments'"
```

Rule-generation meaning:

- `ARGS_GET` checks all GET parameter values.
- A single matching parameter value is enough to trigger the rule.
- This is useful for broad query-string detection.

## 6.2 Specific Collection Key Access with `:`

Use the colon `:` to access a specific key inside a collection.

Example:

```apache
SecRule ARGS_GET:username "@contains admin" "id:200002,phase:1,t:none,t:lowercase,deny,status:403,msg:'Blocked admin value in username parameter'"
```

This checks only the `username` parameter in the `ARGS_GET` collection.

Use specific key access when:

- the vulnerable parameter is known
- broad matching causes false positives
- the rule should only inspect one input field
- an exception needs to exclude or include one collection member

## 6.3 Combine Variables with Pipe `|`

Use pipe `|` to combine multiple variables into one rule target list.

Example:

```apache
SecRule ARGS_GET|ARGS_POST|REQUEST_COOKIES "@rx hello\s\d{1,3}" "id:200003,phase:2,t:none,t:lowercase,deny,status:403,msg:'Pattern detected in GET, POST, or cookies'"
```

This checks:

- GET arguments
- POST arguments
- request cookies

Use pipe `|` when the same attack pattern may appear in multiple request components.

Important note:

- `ARGS` already combines request arguments in many practical contexts, so `ARGS_GET|ARGS_POST` may be unnecessary if `ARGS` is sufficient.
- Use explicit variables when you need separate behavior or clearer documentation.

## 6.4 Remove a Collection Key with `!`

Use `!` to remove a specific collection member from the target list.

Example:

```apache
SecRule ARGS|!ARGS:password "@rx (admin|administrator)" "id:200004,phase:2,t:none,t:lowercase,deny,status:403,msg:'Admin keyword detected outside password parameter'"
```

This inspects all arguments except the `password` parameter.

Use `!` exclusions when:

- one parameter causes known false positives
- a field legitimately contains patterns that look malicious
- the rest of the collection should still be inspected
- a precise false-positive exception is safer than disabling the whole rule

## 6.5 Variable Targeting Decision Matrix

| Payload location | Recommended target |
|---|---|
| Any parameter | `ARGS` |
| Query string parameter values | `ARGS_GET` |
| POST parameter values | `ARGS_POST` |
| Specific parameter | `ARGS:param_name` or `ARGS_GET:param_name` |
| Argument names | `ARGS_NAMES` |
| Request URI | `REQUEST_URI` |
| URI path / filename | `REQUEST_FILENAME` |
| Any request header | `REQUEST_HEADERS` |
| Specific header | `REQUEST_HEADERS:Header-Name` |
| Cookies | `REQUEST_COOKIES` |
| Specific cookie | `REQUEST_COOKIES:cookie_name` |
| Request body | `REQUEST_BODY` |
| Source IP | `REMOTE_ADDR` |
| Captured prior match | `TX:0`, `MATCHED_VAR`, `MATCHED_VAR_NAME` |

## 6.6 Variable Targeting Checklist

- [ ] Use collections when the attack may occur in many inputs.
- [ ] Use specific collection keys for known vulnerable parameters.
- [ ] Use pipe `|` for multiple target variables.
- [ ] Use `!` exclusions for narrow false-positive handling.
- [ ] Avoid excluding entire collections when one key is the problem.
- [ ] Use `ARGS_NAMES` for parameter-name attacks.
- [ ] Use `REQUEST_HEADERS:User-Agent` for scanner User-Agent rules.

---

# 7. Transformation Pipelines

## 7.1 Transformation Definition

Transformations normalize data before operators are applied. Transformations do not modify the original request data. ModSecurity creates a transformed copy of the input value and applies the operator to that transformed copy.

A transformation pipeline is defined by multiple `t:` actions in order.

Example:

```apache
t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,t:compressWhitespace
```

## 7.2 Why Transformation Order Matters

Transformation order can determine whether a rule detects a bypass or misses it.

Example:

```apache
SecRule ARGS "(asfunction|javascript|vbscript|data|mocha|livescript):" \
  "id:300001,phase:2,t:none,t:htmlEntityDecode,t:lowercase,t:removeNulls,t:removeWhitespace,deny,status:403,msg:'Script URI scheme detected'"
```

If transformations are applied in a poor order, an attacker may encode payloads so that later transformations do not expose the malicious pattern.

Rule-generation requirement:

> Always choose transformations based on the bypass technique and put decoding before normalization where appropriate.

## 7.3 Recommended Transformation Baselines

### XSS Baseline

Use for XSS in parameters, headers, cookies, or body fields:

```apache
t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,t:lowercase,t:compressWhitespace
```

Use when detecting:

- `%3Cscript%3E`
- `&lt;script&gt;`
- mixed-case tags
- event handlers such as `onerror=`
- JavaScript or CSS escape sequences

### SQLi Baseline

Use for SQL injection in parameters, cookies, headers, or body fields:

```apache
t:none,t:urlDecodeUni,t:replaceComments,t:compressWhitespace,t:lowercase
```

Use when detecting:

- `UNION SELECT`
- `UN/**/ION SEL/**/ECT`
- `OR 1=1`
- `SLEEP(5)`
- encoded quotes such as `%27`

### Path Traversal Baseline

Use for path traversal in URI, filename, or path-like parameters:

```apache
t:none,t:urlDecodeUni,t:normalisePath,t:lowercase
```

Use when detecting:

- `../`
- `..%2f`
- `%2e%2e%2f`
- `/etc/passwd`
- path canonicalization bypasses

## 7.4 Transformation Checklist

- [ ] Start custom rules with `t:none`.
- [ ] Decode before matching encoded payloads.
- [ ] Lowercase before case-insensitive string matching.
- [ ] Use `t:htmlEntityDecode` for HTML entity XSS.
- [ ] Use `t:replaceComments` and `t:compressWhitespace` for SQLi comment/spacing bypass.
- [ ] Use path normalization for traversal attacks.
- [ ] Avoid unnecessary transformations that increase false positives.
- [ ] Do not rely on hidden `SecDefaultAction` transformations.

---

# 8. XSS Rule Evolution and Bypass Handling

## 8.1 Naive XSS Rule

Initial attempt:

```apache
SecRule ARGS "@contains <script>" "id:400001,deny,status:403"
```

Problem:

- This only matches the exact lowercase substring `<script>`.
- It can be bypassed with mixed case.

Bypass:

```text
?x=<sCript>alert(1);</script>
```

## 8.2 Add Lowercase Transformation

Improved rule:

```apache
SecRule ARGS "@contains <script>" "id:400002,phase:2,t:none,t:lowercase,deny,status:403,msg:'XSS script tag detected'"
```

This handles:

```text
<sCript>
<SCRIPT>
<ScRiPt>
```

Remaining problem:

- The attacker can insert whitespace.

Bypass:

```text
?x=<sCript >alert(1);</script>
```

## 8.3 Add Whitespace Handling

Improved rule:

```apache
SecRule ARGS "@contains <script>" "id:400003,phase:2,t:none,t:lowercase,t:removeWhitespace,deny,status:403,msg:'XSS script tag detected with whitespace normalization'"
```

This handles:

```text
<sCript >
< script >
```

Caution:

- `t:removeWhitespace` may increase false positives or alter benign rich-text content.
- Prefer regex with whitespace flexibility when appropriate.

Regex alternative:

```apache
SecRule ARGS "@rx <\s*script\b" "id:400004,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,t:compressWhitespace,deny,status:403,msg:'XSS script tag detected with regex whitespace handling'"
```

## 8.4 Add HTML Entity Decoding

HTML entity bypass:

```html
&lt;sCript &gt;alert(1);&lt;/script&gt;
```

Improved rule:

```apache
SecRule ARGS "@contains <script>" "id:400005,phase:2,t:none,t:lowercase,t:removeWhitespace,t:htmlEntityDecode,deny,status:403,msg:'XSS script tag detected after HTML entity decoding'"
```

Better transformation order:

```apache
SecRule ARGS "@rx <\s*script\b|onerror\s*=|javascript:" \
  "id:400006,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,t:lowercase,t:compressWhitespace,deny,status:403,log,auditlog,msg:'XSS payload detected after decoding and normalization',tag:'attack-xss',severity:'CRITICAL'"
```

## 8.5 XSS Rule Generation Pattern

Recommended XSS rule for request inputs:

```apache
SecRule ARGS|REQUEST_COOKIES|REQUEST_HEADERS "@rx <\s*script\b|onerror\s*=|onload\s*=|javascript:|<\s*svg\b|<\s*img\b" \
  "id:400100,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,t:lowercase,t:compressWhitespace,deny,status:403,log,auditlog,msg:'XSS payload detected in request input',tag:'attack-xss',severity:'CRITICAL'"
```

For specific parameter:

```apache
SecRule ARGS:comment "@rx <\s*script\b|onerror\s*=|onload\s*=|javascript:" \
  "id:400101,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,t:lowercase,t:compressWhitespace,deny,status:403,log,auditlog,msg:'XSS payload detected in comment parameter',tag:'attack-xss',severity:'CRITICAL'"
```

## 8.6 XSS Target Selection

| Observed XSS location | Recommended target |
|---|---|
| Any query/body parameter | `ARGS` |
| Query only | `ARGS_GET` |
| POST form only | `ARGS_POST` |
| Known parameter | `ARGS:param` |
| Header | `REQUEST_HEADERS` or `REQUEST_HEADERS:Header-Name` |
| Cookie | `REQUEST_COOKIES` |
| URI path | `REQUEST_FILENAME` or `REQUEST_URI` |
| Raw body | `REQUEST_BODY` if body inspection is enabled |

## 8.7 XSS False Positive Notes

XSS rules can false positive on:

- CMS rich-text editors
- Markdown or HTML input fields
- code examples
- developer documentation pages
- admin tools
- support forms that accept HTML snippets

Tuning options:

```apache
SecRule ARGS|!ARGS:content "@rx <\s*script\b|onerror\s*=" "id:400102,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,deny,status:403,msg:'XSS outside content field'"
```

Use `!ARGS:content` only if `content` legitimately accepts HTML and the risk is understood.

---

# 9. SQL Injection Rule Generation

## 9.1 SQLi Payload Signals

Common SQL injection indicators include:

```text
union select
or 1=1
and 1=1
sleep(
benchmark(
information_schema
load_file(
xp_cmdshell
-- 
#
/**/
%27
%22
```

## 9.2 Basic SQLi Rule

```apache
SecRule ARGS "@rx (?i)(union\s+select|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema)" \
  "id:500001,phase:2,t:none,t:urlDecodeUni,t:replaceComments,t:compressWhitespace,t:lowercase,deny,status:403,log,auditlog,msg:'SQL injection payload detected in request arguments',tag:'attack-sqli',severity:'CRITICAL'"
```

## 9.3 SQLi Rule for Specific Parameter

```apache
SecRule ARGS:id "@rx (union\s+select|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema)" \
  "id:500002,phase:2,t:none,t:urlDecodeUni,t:replaceComments,t:compressWhitespace,t:lowercase,deny,status:403,log,auditlog,msg:'SQL injection payload detected in id parameter',tag:'attack-sqli',severity:'CRITICAL'"
```

## 9.4 SQLi Rule for Headers and Cookies

```apache
SecRule REQUEST_HEADERS|REQUEST_COOKIES "@rx (union\s+select|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema)" \
  "id:500003,phase:2,t:none,t:urlDecodeUni,t:replaceComments,t:compressWhitespace,t:lowercase,deny,status:403,log,auditlog,msg:'SQL injection payload detected in headers or cookies',tag:'attack-sqli',severity:'CRITICAL'"
```

## 9.5 SQL Comment and Whitespace Handling

SQLi bypasses often use comments and whitespace variations:

```text
UN/**/ION/**/SELECT
UNION%0ASELECT
OR/**/1/**/=/**/1
```

Recommended transformations:

```apache
t:none,t:urlDecodeUni,t:replaceComments,t:compressWhitespace,t:lowercase
```

Recommended regex:

```apache
@rx (union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\()
```

## 9.6 SQLi False Positive Notes

SQLi rules can false positive on:

- search boxes
- developer tools
- SQL tutorial pages
- reporting interfaces
- database administration panels
- log search systems
- documentation containing SQL snippets

Tuning options:

- target specific vulnerable parameters
- exclude known safe parameters
- add path scope
- log first before deny
- use anomaly scoring instead of immediate block

Example with parameter exclusion:

```apache
SecRule ARGS|!ARGS:sql_example "@rx (union\s+select|or\s+1\s*=\s*1|sleep\s*\()" \
  "id:500004,phase:2,t:none,t:urlDecodeUni,t:replaceComments,t:compressWhitespace,t:lowercase,deny,status:403,msg:'SQLi outside sql_example parameter'"
```

---

# 10. Operator Usage Guidance

## 10.1 Operator Selection Matrix

| Need | Recommended operator |
|---|---|
| Exact value | `@streq` |
| Substring literal | `@contains` |
| Word-boundary literal | `@containsWord` |
| Prefix | `@beginsWith` |
| Suffix | `@endsWith` |
| Flexible pattern | `@rx` |
| Multiple phrase match | `@pm` |
| Specialized XSS | `@detectXSS` |
| Specialized SQLi | `@detectSQLi` |
| URL encoding validation | `@validateUrlEncoding` |
| UTF-8 validation | `@validateUtf8Encoding` |
| Numeric comparison | `@eq`, `@gt`, `@ge`, `@lt`, `@le` |

## 10.2 Default Operator `@rx`

If no operator is specified, `@rx` is implied. However, generated rules should usually specify the operator explicitly for clarity.

Risky implicit style:

```apache
SecRule ARGS "union\s+select" "id:600001,phase:2,deny"
```

Clear explicit style:

```apache
SecRule ARGS "@rx union\s+select" "id:600001,phase:2,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,msg:'SQLi union select detected'"
```

## 10.3 Regex Guidelines for Security Rules

When writing regex for ModSecurity rules, follow these security-specific guidelines:

1. Avoid relying heavily on `^` and `$` anchors when input can contain injected prefixes or suffixes.
2. Make regex effectively case-insensitive using transformations such as `t:lowercase` or inline flags when appropriate.
3. Avoid broad dot `.` usage because newline and alternative characters can bypass or overmatch depending on context.
4. Be careful with repetition counts such as `{1,3}`; attackers may vary counts to evade rules.
5. Prefer `t:urlDecodeUni` over `t:urlDecode` for broader URL/Unicode decoding in ModSecurity contexts.
6. Use `+` only when one-or-more is required; `*` may be appropriate for optional spacing but can overmatch.
7. Use wildcard-like regex reasonably; newline alternatives and whitespace variants can create bypasses.
8. Apply regex to the correct scope: argument values, argument names, cookie names/values, header names/values, file argument names, and file content.
9. Do not use only `%20` as a whitespace separator; attackers can use `%0d`, `%0a`, tabs, vertical tabs, and other whitespace.
10. Consider greediness. Bad greedy regex can increase false positives and log flooding, which can lead operators to disable the rule.

## 10.4 Regex Examples

XSS regex:

```apache
@rx <\s*script\b|onerror\s*=|onload\s*=|javascript:|<\s*svg\b|<\s*img\b
```

SQLi regex:

```apache
@rx union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema
```

Path traversal regex:

```apache
@rx \.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c|/etc/passwd
```

## 10.5 Operator Checklist

- [ ] Use explicit operators.
- [ ] Use `@contains` for stable literals.
- [ ] Use `@rx` for flexible variants.
- [ ] Use `@detectXSS` or `@detectSQLi` only when libinjection-based detection is intended.
- [ ] Use validation operators for malformed encoding or schema validation.
- [ ] Pair regex with correct transformations.
- [ ] Avoid overbroad single-token regex patterns.

---

# 11. Action Usage Guidance

## 11.1 Disruptive Actions

Disruptive actions decide what happens to a matching request.

Common actions:

```text
deny
block
drop
pass
allow
redirect
proxy
```

Use:

- `deny` or `block` for high-confidence attacks.
- `pass` for logging/scoring-only rules.
- `drop` for severe cases where closing the connection is acceptable.
- `allow` very carefully because it can bypass further checks depending on configuration and context.

Example block rule:

```apache
SecRule ARGS "@rx <\s*script\b" "id:700001,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,deny,status:403,log,auditlog,msg:'XSS script tag detected'"
```

## 11.2 Metadata Actions

Metadata actions identify and document a rule.

Recommended metadata:

```apache
id:700002
phase:2
msg:'SQL injection payload detected'
tag:'attack-sqli'
severity:'CRITICAL'
```

A generated rule should almost always include:

- `id`
- `phase`
- `msg`
- `tag`
- `severity`

## 11.3 Logging Actions

Use logging to make the rule observable.

Common logging actions:

```text
log
auditlog
nolog
```

Examples:

```apache
SecRule ARGS "@contains union select" "id:700003,phase:2,t:none,t:urlDecodeUni,t:lowercase,log,auditlog,pass,msg:'SQLi indicator observed'"
```

Use log-only rules when testing a new expression:

```apache
SecRule ARGS "@rx <\s*script\b|onerror\s*=" "id:700004,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,log,auditlog,pass,msg:'Potential XSS observed - monitoring only'"
```

## 11.4 Variable Actions and Scoring

Use `setvar` to modify transaction variables such as anomaly scores.

Example CRS-style scoring pattern:

```apache
SecRule ARGS "@rx <\s*script\b|onerror\s*=" \
  "id:700005,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,pass,log,auditlog,capture,msg:'XSS payload detected',tag:'attack-xss',severity:'CRITICAL',setvar:'tx.xss_score=+%{tx.critical_anomaly_score}',setvar:'tx.anomaly_score=+%{tx.critical_anomaly_score}'"
```

Use scoring when:

- building CRS-compatible anomaly rules
- multiple weak signals should contribute to a final block
- immediate blocking would be too aggressive
- staged evaluation is needed

## 11.5 Flow Actions and Chaining

Use `chain` to require multiple conditions.

Example:

```apache
SecRule REQUEST_URI "@beginsWith /admin" \
  "id:700006,phase:2,t:none,chain,deny,status:403,log,msg:'Suspicious admin access with SQLi payload'"
  SecRule ARGS "@rx union\s+select|or\s+1\s*=\s*1" "t:none,t:urlDecodeUni,t:replaceComments,t:compressWhitespace,t:lowercase"
```

This blocks only when:

1. URI starts with `/admin`
2. arguments contain SQLi indicators

Use chains for:

- path + payload matching
- method + body matching
- header + parameter correlation
- reducing false positives

## 11.6 Action Checklist

- [ ] Use `deny` or `block` only for high-confidence matches.
- [ ] Use `pass,log,auditlog` for monitoring or scoring.
- [ ] Add `status:403` when denying requests.
- [ ] Add `msg`, `tag`, and `severity`.
- [ ] Use `chain` for multi-condition logic.
- [ ] Use `setvar` for anomaly scoring.
- [ ] Avoid broad `allow` or `skip` unless precisely scoped.

---

# 12. Rule Phase Selection

## 12.1 Phase Overview

`phase` defines when the rule runs.

Common phase choices:

| Phase | Typical use |
|---|---|
| `phase:1` | Request headers and early request-line checks. |
| `phase:2` | Request body and request arguments after request body processing. |
| `phase:3` | Response headers. |
| `phase:4` | Response body. |
| `phase:5` | Logging phase. |

## 12.2 Phase Selection Matrix

| Payload location | Recommended phase |
|---|---|
| URI path | `phase:1` or `phase:2` |
| Query string | `phase:1` or `phase:2` |
| Request headers | `phase:1` |
| Cookies | `phase:1` or `phase:2` |
| POST form arguments | `phase:2` |
| Request body | `phase:2` |
| Uploaded files | `phase:2` |
| Response headers | `phase:3` |
| Response body | `phase:4` |

## 12.3 Practical Guidance

- Use `phase:1` for early blocking on headers, URI, User-Agent, and IP.
- Use `phase:2` when rules need parsed body arguments or request body content.
- Use response phases only for response inspection, not request attack blocking.
- If unsure for request parameters, use `phase:2` because it has more complete request data.
- If performance or early blocking is important and body data is not needed, use `phase:1`.

## 12.4 Phase Example

Header scanner rule:

```apache
SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(sqlmap|nikto|acunetix)" \
  "id:800001,phase:1,t:none,t:lowercase,deny,status:403,log,msg:'Scanner User-Agent detected'"
```

POST body argument rule:

```apache
SecRule ARGS_POST "@rx <\s*script\b|onerror\s*=" \
  "id:800002,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,deny,status:403,log,msg:'XSS detected in POST arguments'"
```

---

# 13. Rule Examples by Attack Type and Request Component

## 13.1 XSS in Any Argument

```apache
SecRule ARGS "@rx <\s*script\b|onerror\s*=|onload\s*=|javascript:" \
  "id:900001,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,t:lowercase,t:compressWhitespace,deny,status:403,log,auditlog,msg:'XSS payload detected in arguments',tag:'attack-xss',severity:'CRITICAL'"
```

## 13.2 XSS in Known Parameter

```apache
SecRule ARGS:q "@rx <\s*script\b|onerror\s*=|onload\s*=|javascript:" \
  "id:900002,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,t:lowercase,t:compressWhitespace,deny,status:403,log,auditlog,msg:'XSS payload detected in q parameter',tag:'attack-xss',severity:'CRITICAL'"
```

## 13.3 XSS in Headers

```apache
SecRule REQUEST_HEADERS "@rx <\s*script\b|onerror\s*=|javascript:" \
  "id:900003,phase:1,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,t:compressWhitespace,deny,status:403,log,auditlog,msg:'XSS payload detected in request headers',tag:'attack-xss',severity:'CRITICAL'"
```

## 13.4 SQLi in Any Argument

```apache
SecRule ARGS "@rx union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema" \
  "id:900004,phase:2,t:none,t:urlDecodeUni,t:replaceComments,t:compressWhitespace,t:lowercase,deny,status:403,log,auditlog,msg:'SQL injection payload detected in arguments',tag:'attack-sqli',severity:'CRITICAL'"
```

## 13.5 SQLi in Known Parameter

```apache
SecRule ARGS:id "@rx union\s+select|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(" \
  "id:900005,phase:2,t:none,t:urlDecodeUni,t:replaceComments,t:compressWhitespace,t:lowercase,deny,status:403,log,auditlog,msg:'SQL injection payload detected in id parameter',tag:'attack-sqli',severity:'CRITICAL'"
```

## 13.6 Scanner User-Agent

```apache
SecRule REQUEST_HEADERS:User-Agent "@rx (sqlmap|nikto|acunetix|masscan|nuclei)" \
  "id:900006,phase:1,t:none,t:lowercase,deny,status:403,log,auditlog,msg:'Known scanner User-Agent detected',tag:'automation-scanner',severity:'WARNING'"
```

## 13.7 Path Traversal

```apache
SecRule REQUEST_URI "@rx \.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c|/etc/passwd|boot\.ini" \
  "id:900007,phase:1,t:none,t:urlDecodeUni,t:normalisePath,t:lowercase,deny,status:403,log,auditlog,msg:'Path traversal payload detected',tag:'attack-lfi',severity:'CRITICAL'"
```

## 13.8 Parameter Name Attack

```apache
SecRule ARGS_NAMES "@rx ^(cmd|exec|command|shell|redirect|url)$" \
  "id:900008,phase:2,t:none,t:lowercase,deny,status:403,log,auditlog,msg:'Suspicious argument name detected',tag:'attack-generic',severity:'WARNING'"
```

---

# 14. Rule Examples with False-Positive Tuning

## 14.1 Exclude a Known Safe Parameter

Problem:

- `ARGS:content` legitimately contains HTML.
- A broad XSS rule false positives.

Tuned rule:

```apache
SecRule ARGS|!ARGS:content "@rx <\s*script\b|onerror\s*=|javascript:" \
  "id:910001,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,t:compressWhitespace,deny,status:403,log,auditlog,msg:'XSS detected outside content parameter',tag:'attack-xss',severity:'CRITICAL'"
```

## 14.2 Path-Scoped Rule with Chain

Problem:

- SQL-like search text appears on many pages.
- Only `/api/products` is vulnerable.

Tuned chained rule:

```apache
SecRule REQUEST_URI "@beginsWith /api/products" \
  "id:910002,phase:2,t:none,chain,deny,status:403,log,auditlog,msg:'SQLi detected on products API',tag:'attack-sqli',severity:'CRITICAL'"
  SecRule ARGS:id "@rx union\s+select|or\s+1\s*=\s*1|sleep\s*\(" "t:none,t:urlDecodeUni,t:replaceComments,t:compressWhitespace,t:lowercase"
```

## 14.3 Log-Only Validation Rule

Use this before production blocking when false positives are unknown:

```apache
SecRule ARGS "@rx <\s*script\b|onerror\s*=|javascript:" \
  "id:910003,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,t:compressWhitespace,pass,log,auditlog,msg:'Potential XSS detected - monitoring only',tag:'attack-xss',severity:'NOTICE'"
```

## 14.4 Scoring Instead of Immediate Blocking

```apache
SecRule ARGS "@rx union\s+select|or\s+1\s*=\s*1|sleep\s*\(" \
  "id:910004,phase:2,t:none,t:urlDecodeUni,t:replaceComments,t:compressWhitespace,t:lowercase,pass,log,auditlog,capture,msg:'SQLi indicator detected',tag:'attack-sqli',severity:'CRITICAL',setvar:'tx.sqli_score=+5',setvar:'tx.anomaly_score=+5'"
```

Use when multiple signals should contribute to a blocking decision.

---

# 15. CRS Rule Authoring Requirements

## 15.1 Regression Tests

All rules intended for CRS should include at least one regression test.

More regression tests increase the chance that a pull request will be accepted.

Rule-generation implication:

> If generating CRS-style rules, also generate at least one positive test and one negative test where possible.

## 15.2 Regex Source Documentation

If a rule combines data sources into a single regular expression for performance reasons, document use of the `regexp-assemble` command in comments above the rule.

The independent source patterns should be included in the utility/source directory so that future maintainers can regenerate and verify the assembled regex.

## 15.3 CRS-Style Comment Pattern

```apache
# Rule purpose:
# - Detect SQL injection keyword and boolean tautology patterns in request arguments.
# Regex source:
# - This pattern should be generated from independent sources using regexp-assemble if expanded.
# Test coverage:
# - Include positive tests for union select, or 1=1, and sleep().
# - Include negative tests for benign search strings and documentation pages.
SecRule ARGS "@rx union\s+select|or\s+1\s*=\s*1|sleep\s*\(" \
  "id:920001,phase:2,t:none,t:urlDecodeUni,t:replaceComments,t:compressWhitespace,t:lowercase,pass,log,auditlog,capture,msg:'SQL injection indicator detected',tag:'application-multi',tag:'language-multi',tag:'platform-multi',tag:'attack-sqli',severity:'CRITICAL',setvar:'tx.anomaly_score=+%{tx.critical_anomaly_score}'"
```

## 15.4 CRS Checklist

- [ ] Include regression tests.
- [ ] Include more than one test when practical.
- [ ] Document generated or assembled regex sources.
- [ ] Include independent regex source files if using `regexp-assemble`.
- [ ] Use comments for maintainability.
- [ ] Prefer anomaly scoring patterns for CRS compatibility.
- [ ] Include tags and severity.
- [ ] Avoid overly broad regex that causes log flooding or false positives.

---

# 16. RAG-Oriented Rule Generation Decision Matrix

## 16.1 From Payload Location to Rule Target

| Payload evidence | Target variable |
|---|---|
| Query parameter value | `ARGS_GET` or `ARGS:param` |
| POST form value | `ARGS_POST` or `ARGS:param` |
| Any request argument | `ARGS` |
| Argument name | `ARGS_NAMES` |
| User-Agent payload | `REQUEST_HEADERS:User-Agent` |
| Header payload | `REQUEST_HEADERS` or `REQUEST_HEADERS:Header-Name` |
| Cookie payload | `REQUEST_COOKIES` |
| Cookie name | `REQUEST_COOKIES_NAMES` |
| URI path | `REQUEST_FILENAME` or `REQUEST_URI` |
| Full URI | `REQUEST_URI` |
| Body payload | `REQUEST_BODY` or parsed arguments if available |
| File upload | `FILES`, `FILES_NAMES`, file-related variables |
| Client IP | `REMOTE_ADDR` |

## 16.2 From Bypass Technique to Transformation

| Bypass technique | Transformation strategy |
|---|---|
| Mixed case | `t:lowercase` |
| URL encoding | `t:urlDecodeUni` |
| Double/complex URL encoding | Consider repeated decoding behavior and test carefully; use `t:urlDecodeUni` as baseline. |
| HTML entities | `t:htmlEntityDecode` |
| SQL comments | `t:replaceComments` |
| Extra whitespace | `t:compressWhitespace` or carefully `t:removeWhitespace` |
| Null bytes | `t:removeNulls` |
| JavaScript escapes | `t:jsDecode` |
| CSS escapes | `t:cssDecode` |
| Path traversal | `t:normalisePath` / `t:normalizePath`, `t:urlDecodeUni`, `t:lowercase` |
| Base64 payload | `t:base64Decode` when the target field is expected to be Base64 |

## 16.3 From Attack Type to Operator

| Attack type | Recommended operators |
|---|---|
| XSS | `@rx`, `@contains`, `@detectXSS` |
| SQLi | `@rx`, `@contains`, `@containsWord`, `@detectSQLi` |
| Path traversal/LFI | `@rx`, `@contains`, `@beginsWith`, `@endsWith` |
| Scanner User-Agent | `@rx`, `@pm`, `@contains` |
| Exact path policy | `@streq`, `@beginsWith`, `@endsWith` |
| Encoding validation | `@validateUrlEncoding`, `@validateUtf8Encoding` |
| Numeric threshold | `@gt`, `@ge`, `@lt`, `@le`, `@eq` |

## 16.4 From Confidence to Action

| Confidence | Recommended action |
|---|---|
| High-confidence payload match | `deny,status:403,log,auditlog` |
| Medium-confidence suspicious signal | `pass,log,auditlog,setvar:tx.anomaly_score=+N` |
| Tuning or validation | `pass,log,auditlog` |
| Known-safe exception | target exclusion with `!` or separate `ctl`/skip logic depending on deployment |
| CRS-style rule | anomaly scoring with `setvar`, tags, severity, tests |

---

# 17. Common Mistakes and Corrections

## 17.1 Missing `t:none`

Risky:

```apache
SecRule ARGS "@rx <script" "id:100,phase:2,t:lowercase,deny"
```

Better:

```apache
SecRule ARGS "@rx <script" "id:100,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,deny,status:403"
```

## 17.2 Broad XSS Literal Without Normalization

Risky:

```apache
SecRule ARGS "@contains <script>" "id:101,deny"
```

Better:

```apache
SecRule ARGS "@rx <\s*script\b|onerror\s*=|javascript:" \
  "id:101,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,t:compressWhitespace,deny,status:403,msg:'XSS payload detected'"
```

## 17.3 Broad SQL Term

Risky:

```apache
SecRule ARGS "@contains select" "id:102,deny"
```

Better:

```apache
SecRule ARGS "@rx union\s+select|or\s+1\s*=\s*1|sleep\s*\(" \
  "id:102,phase:2,t:none,t:urlDecodeUni,t:replaceComments,t:compressWhitespace,t:lowercase,deny,status:403,msg:'SQLi payload detected'"
```

## 17.4 Wrong Target Scope

Risky:

```apache
SecRule REQUEST_URI "@rx union\s+select" "id:103,deny"
```

Better if SQLi is in parameter `id`:

```apache
SecRule ARGS:id "@rx union\s+select|or\s+1\s*=\s*1" \
  "id:103,phase:2,t:none,t:urlDecodeUni,t:replaceComments,t:compressWhitespace,t:lowercase,deny,status:403,msg:'SQLi in id parameter'"
```

## 17.5 Excluding Too Much

Risky:

```apache
SecRule !ARGS "@rx <script" "id:104,deny"
```

Better:

```apache
SecRule ARGS|!ARGS:content "@rx <\s*script\b|onerror\s*=" \
  "id:104,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,deny,status:403,msg:'XSS outside content parameter'"
```

## 17.6 No Message or Tags

Weak:

```apache
SecRule ARGS "@rx <script" "id:105,phase:2,deny"
```

Better:

```apache
SecRule ARGS "@rx <\s*script\b" \
  "id:105,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,deny,status:403,log,auditlog,msg:'XSS script tag detected',tag:'attack-xss',severity:'CRITICAL'"
```

## 17.7 Immediate Block for Unknown False-Positive Risk

Risky:

```apache
SecRule ARGS "@rx select" "id:106,phase:2,deny"
```

Safer monitoring version:

```apache
SecRule ARGS "@rx union\s+select|or\s+1\s*=\s*1" \
  "id:106,phase:2,t:none,t:urlDecodeUni,t:replaceComments,t:compressWhitespace,t:lowercase,pass,log,auditlog,msg:'Potential SQLi observed - monitoring only',tag:'attack-sqli',severity:'NOTICE'"
```

---

# 18. Final Template for LLM ModSecurity Rule Generation

Use this output structure when generating a ModSecurity rule.

```markdown
## Rule Objective

Describe:
- attack type
- payload location
- bypass technique
- desired enforcement action

## Selected Variables

List:
- primary variable or collection
- specific collection keys if known
- excluded keys if needed
- combined variables using `|` if needed

## Selected Operator

Explain:
- why `@rx`, `@contains`, `@detectXSS`, `@detectSQLi`, or another operator was chosen
- whether regex is necessary
- what the operator argument matches

## Selected Transformations

List:
- `t:none`
- decoding transformations
- normalization transformations
- whitespace/comment/entity handling
- why the order is chosen

## Proposed Rule

Provide the complete `SecRule`.

## Rule Rationale

Explain:
- how the rule matches the bypass
- where it inspects
- why transformations defeat the observed evasion
- why the action is appropriate

## False Positives and Tuning

Explain:
- expected false positives
- parameter or path exclusions
- log-only testing option
- scoring option
- CRS regression tests if applicable
```

## 18.1 Example Generated Output for XSS

```apache
SecRule ARGS:q "@rx <\s*script\b|onerror\s*=|onload\s*=|javascript:" \
  "id:930001,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,t:lowercase,t:compressWhitespace,deny,status:403,log,auditlog,msg:'XSS payload detected in q parameter',tag:'attack-xss',severity:'CRITICAL'"
```

Rationale:

- `ARGS:q` targets the known vulnerable parameter.
- `@rx` handles multiple XSS indicators.
- `t:urlDecodeUni` handles URL encoding.
- `t:htmlEntityDecode` handles HTML entities.
- `t:lowercase` handles mixed case.
- `t:compressWhitespace` handles whitespace variations.
- `deny,status:403` blocks high-confidence matches.

## 18.2 Example Generated Output for SQLi

```apache
SecRule ARGS:id "@rx union\s+select|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(" \
  "id:930002,phase:2,t:none,t:urlDecodeUni,t:replaceComments,t:compressWhitespace,t:lowercase,deny,status:403,log,auditlog,msg:'SQL injection payload detected in id parameter',tag:'attack-sqli',severity:'CRITICAL'"
```

Rationale:

- `ARGS:id` targets the known SQLi parameter.
- `@rx` captures whitespace-flexible SQLi variants.
- `t:urlDecodeUni` handles encoded quotes and encoded spaces.
- `t:replaceComments` handles SQL comment obfuscation.
- `t:compressWhitespace` normalizes whitespace.
- `t:lowercase` handles case-randomized SQL keywords.

---

# 19. Final Checklist for ModSecurity Rule Generation

- [ ] Does the rule have a target variable?
- [ ] Does the variable match the payload location?
- [ ] Is a specific collection key used when the vulnerable parameter is known?
- [ ] Are false-positive-prone keys excluded with `!` only when justified?
- [ ] Does the rule use an explicit operator?
- [ ] Is `@rx` used only when flexible matching is required?
- [ ] Are transformations explicit and started with `t:none`?
- [ ] Are decoding transformations included for encoded payloads?
- [ ] Is `t:lowercase` included for case-randomized payloads?
- [ ] Is whitespace/comment/entity normalization included where needed?
- [ ] Does the rule have a unique `id`?
- [ ] Does the rule include an explicit `phase`?
- [ ] Does the rule include the correct action?
- [ ] Does an enforcement rule include `deny` or `block` and a status code?
- [ ] Does a testing rule use `pass,log,auditlog`?
- [ ] Does the rule include `msg`, `tag`, and `severity`?
- [ ] Are expected false positives documented?
- [ ] Is there a narrower target or path scope available?
- [ ] If CRS-style, are regression tests included?
- [ ] If regex is assembled, are sources documented?
- [ ] Is the rule maintainable and not overly broad?
