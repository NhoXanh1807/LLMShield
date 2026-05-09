# Kemp LoadMaster ModSecurity Custom WAF Rule Writing Knowledge Base for RAG and Rule Generation
# 1. Progress Kemp LoadMaster WAF Overview
## 1.1 LoadMaster WAF Purpose

Progress Kemp LoadMaster includes Web Application Firewall services that are integrated into the LoadMaster platform. The WAF protects published web applications against layer 7 application attacks while preserving the core load-balancing and application-delivery functions of LoadMaster.

LoadMaster WAF can use:

- Progress Kemp-provided OWASP Core Rule Set rules
- custom ModSecurity rules uploaded by the administrator
- a combination of OWASP CRS and custom rules

The Progress Kemp-provided OWASP CRS rule set provides generic attack detection for common web application attacks. Custom rules are used when the application requires specific virtual patching, allow-listing, false-positive handling, attack blocking, or application-specific logic.

## 1.2 When to Write Custom WAF Rules

Write a custom ModSecurity rule for LoadMaster when:

- OWASP CRS does not cover the exact payload or endpoint
- a virtual patch is needed for a known application weakness
- a false positive requires an allow-list or exclusion
- a custom header, request path, parameter, cookie, or body value must be inspected
- a known safe IP address must bypass the ModSecurity engine
- a custom rule must run before CRS using the LoadMaster `Run First` option
- a targeted rule is safer than modifying Progress Kemp-provided CRS files

## 1.3 Rule-Generation Implication

When generating a LoadMaster custom WAF rule, produce both:

1. the ModSecurity `SecRule` or related directive
2. the LoadMaster deployment guidance:
   - upload as `.conf` or `tar.gz`
   - assign to a Virtual Service
   - decide whether to enable `Run First`
   - test for WAF misconfiguration
   - back up the LoadMaster configuration after successful deployment

---

# 2. Core ModSecurity `SecRule` Model

## 2.1 `SecRule` Is the Main Rule-Writing Directive

The main directive for writing custom ModSecurity WAF rules is:

```apache
SecRule
```

A `SecRule` creates a rule that inspects selected transactional data and applies actions when the operator matches.

Canonical syntax:

```apache
SecRule VARIABLES OPERATOR [TRANSFORMATION_FUNCTIONS,ACTIONS]
```

Expanded rule-generation model:

```apache
SecRule <VARIABLES> "<OPERATOR> <OPERATOR_ARGUMENT>" \
  "id:<UNIQUE_ID>,\
  phase:<PHASE>,\
  <DISRUPTIVE_OR_FLOW_ACTION>,\
  t:none,<TRANSFORMATION_FUNCTIONS>,\
  msg:'<LOG_MESSAGE>',\
  logdata:'<LOG_DATA>',\
  status:<HTTP_STATUS>"
```

## 2.2 Four Parts of a ModSecurity Rule

| Part | Meaning | Rule-generation role |
|---|---|---|
| `VARIABLES` | Tells the WAF engine where to look in HTTP request or response data. | Select the inspected request component: URI, args, headers, body, IP, cookies. |
| `OPERATOR` | Tells the WAF engine how to match or process the selected variable data. | Choose regex, keyword, exact string, IP match, or specialized operator. |
| `TRANSFORMATION_FUNCTIONS` | Tells the WAF engine how to normalize data before matching. | Apply anti-evasion decoding and normalization such as `t:urlDecodeUni`, `t:lowercase`, `t:removeNulls`. |
| `ACTIONS` | Tells the WAF engine what to do if the rule matches. | Block, deny, pass, log, set variables, chain, skip, or alter transaction handling. |

## 2.3 Minimal Rule Example

```apache
SecRule REQUEST_URI "@rx <script>"
```

Meaning:

- `REQUEST_URI` is the inspected variable.
- `@rx <script>` is a regular expression operator that looks for the `<script>` pattern.
- No explicit actions are supplied, so defaults from `SecDefaultAction` apply.

## 2.4 Practical Rule Example with Explicit Actions

```apache
SecRule ARGS|REQUEST_HEADERS "@rx <script>" \
  "id:101,\
  deny,\
  status:404,\
  msg:'XSS Attack'"
```

Meaning:

- Inspect request parameters and request headers.
- Match the regex pattern `<script>`.
- If matched, deny the transaction.
- Return HTTP status `404`.
- Log message: `XSS Attack`.

---

# 3. Rule Syntax Best Practices for Maintainable Custom Rules

## 3.1 General Syntax Best Practices

When writing a new custom rule for LoadMaster, keep it clear and maintainable:

- Comment clearly what the rule does and why.
- Put each rule action on a separate line.
- Use a backslash `\` at the end of a line to escape the newline.
- Indent rule actions consistently.
- Keep actions in the same order across rules to avoid mistakes.
- Use a clear `msg` value so logs explain the match.
- Include a unique `id`.
- Include an explicit `phase`.
- Include `t:none` before transformations to avoid unexpected inherited transformations.
- Use targeted variables when possible to reduce false positives.

## 3.2 Recommended Action Order

Use a consistent order like this:

1. `id`
2. `phase`
3. disruptive or flow action: `deny`, `block`, `pass`, `allow`, `chain`
4. transformations: `t:none`, then decoding/normalization transformations
5. status code if blocking with `deny`
6. logging controls: `log`, `auditlog`, `nolog`
7. message: `msg`
8. log data: `logdata`
9. tags / metadata
10. control actions such as `ctl`

Recommended template:

```apache
#
# -- <Rule Purpose>
# Explain why this rule exists and what request component it protects.
#
SecRule <VARIABLES> "<OPERATOR>" \
  "id:<ID>,\
  phase:<PHASE>,\
  deny,\
  status:403,\
  t:none,<TRANSFORMATIONS>,\
  log,\
  msg:'<Clear message>',\
  logdata:'%{MATCHED_VAR}'"
```

## 3.3 Long Rule Line Splitting

To split a long ModSecurity line, use a single backslash followed by a newline.

Example:

```apache
SecRule ARGS KEYWORD \
  phase:1,t:none,block
```

For rule-generation, prefer the quoted action-list form:

```apache
SecRule ARGS "KEYWORD" \
  "id:1001,\
  phase:1,\
  block,\
  t:none,\
  msg:'Keyword detected'"
```

## 3.4 Multiple Variables in One Rule

Multiple variables can be inspected in the same rule using the pipe character `|`.

Example:

```apache
SecRule REQUEST_URI|REQUEST_PROTOCOL "@rx <script>"
```

Rule-generation meaning:

- The operator is applied to `REQUEST_URI`.
- The operator is also applied to `REQUEST_PROTOCOL`.
- A match in any selected variable can trigger the rule.

Use multiple variables when the same payload pattern may appear in several request components.

---

# 4. Variables: Where the WAF Looks

## 4.1 Variable Definition

Variables specify which part of the HTTP transaction ModSecurity inspects.

A rule generator should select variables based on where the bypass payload appears.

## 4.2 Common Variables from the LoadMaster Guide

| Variable | Meaning | Best rule-generation use |
|---|---|---|
| `ARGS` | All request arguments, including POST payload arguments. | Default for XSS, SQLi, and parameter payloads. |
| `ARGS:username` | Specific request parameter named `username`. | Target known vulnerable parameter and reduce false positives. |
| `REQUEST_METHOD` | HTTP method used in the transaction. | Restrict rules to `GET`, `POST`, etc. |
| `REQUEST_HEADERS` | All request headers. | Detect header-based payloads or broad header attacks. |
| `REQUEST_HEADERS:User-Agent` | Specific User-Agent header. | Detect scanner or IoT client validation logic. |
| `REQUEST_HEADERS_NAMES` | Names of request headers. | Detect malicious or abnormal header names. |
| `REQUEST_URI` | Request URI. | Detect payloads in URI path or query. |
| `REQUEST_LINE` | Complete request line including method and HTTP version. | Shellshock and request-line payload checks. |
| `REQUEST_BODY` | Full request body. | Detect body-based attacks such as Shellshock in POST body. |
| `REQUEST_PROTOCOL` | HTTP protocol string. | Rare protocol validation or anomaly rules. |
| `REMOTE_ADDR` | Remote client IP address. | IP allow-listing or IP-based exceptions. |
| `MATCHED_VAR` | Matched variable value. | Logging matched content. |

## 4.3 Variable Selection Matrix

| Observed payload location | Recommended variable |
|---|---|
| Any query or form parameter | `ARGS` |
| A known parameter such as `username`, `id`, `q`, `search` | `ARGS:<name>` |
| User-Agent payload or scanner identity | `REQUEST_HEADERS:User-Agent` |
| Any header payload | `REQUEST_HEADERS` |
| Header name payload | `REQUEST_HEADERS_NAMES` |
| URI path or query payload | `REQUEST_URI` |
| Request line payload | `REQUEST_LINE` |
| Raw or parsed request body | `REQUEST_BODY` |
| Source IP allow-list or block-list | `REMOTE_ADDR` |
| Method-specific policy | `REQUEST_METHOD` |

## 4.4 Variable Targeting Guidance

Prefer the narrowest variable that still covers the attack:

- Use `ARGS:q` instead of `ARGS` when only `q` is vulnerable.
- Use `REQUEST_HEADERS:User-Agent` instead of `REQUEST_HEADERS` when the rule is only about User-Agent.
- Use `REQUEST_BODY` only when body inspection is required.
- Use `REQUEST_LINE|REQUEST_HEADERS|REQUEST_HEADERS_NAMES` for Shellshock-like environment-variable injection attempts in early request components.
- Use `REMOTE_ADDR` for IP allow-list logic.

---

# 5. Operators: How the WAF Matches Data

## 5.1 Operator Definition

The operator specifies the pattern, keyword, comparison, or matching method applied to the selected variable data.

Operators begin with the `@` character.

## 5.2 Operators Used in the Source Guide

| Operator | Meaning | Example |
|---|---|---|
| `@rx` | Regular expression match. | `@rx <script>` |
| `@beginsWith` | Match if input begins with a string. | `!@beginsWith acmewidget/` |
| `@ipMatch` | IPv4 or IPv6 address match. | `@ipMatch 192.168.1.101` |
| `@streq` | String equality. | `@streq admin` |
| `!@streq` | Negated string equality. | `!@streq 192.168.1.111` |
| `@contains` | Substring match. | `@contains () {` |

## 5.3 Operator Selection Matrix

| Rule intent | Recommended operator |
|---|---|
| XSS script pattern | `@rx` |
| Header must begin with required prefix | `!@beginsWith` |
| IP allow-list | `@ipMatch` |
| Exact username or method match | `@streq` |
| Reject if value does not equal expected value | `!@streq` |
| Stable literal string such as Shellshock `() {` | `@contains` |
| Complex evasion pattern | `@rx` with transformations |

## 5.4 Negating Operators

The `!` character negates the operator.

Example:

```apache
SecRule REQUEST_HEADERS:User-Agent "!@beginsWith acmewidget/" \
  "id:1000,\
  phase:1,\
  deny,\
  t:none,t:lowercase,\
  msg:'Legitimate AcmeWidget User-Agent header required',\
  logdata:'%{MATCHED_VAR}'"
```

Meaning:

- Deny the request if `User-Agent` does **not** begin with `acmewidget/`.
- Apply `t:lowercase` so the comparison is case-insensitive.
- This is useful for API clients that must identify with a fixed prefix.

---

# 6. Transformation Functions: How the WAF Normalizes Data

## 6.1 Transformation Definition

Transformation functions normalize a copy of variable data before the operator is applied. They are used to reduce bypass risk from encoding, case variation, whitespace tricks, null bytes, comments, and other evasions.

Transformations are specified as actions using `t:<name>`.

Example:

```apache
t:none,t:utf8toUnicode,t:urlDecodeUni,t:compressWhitespace
```

## 6.2 Transformation Categories

| Category | Examples | Use |
|---|---|---|
| Anti-evasion | `lowercase`, `normalisePath`, `removeNulls`, `replaceComments`, `compressWhitespace` | Normalize common bypass tricks. |
| Decoding | `base64Decode`, `hexDecode`, `jsDecode`, `urlDecodeUni` | Decode encoded payloads before matching. |
| Encoding | `base64Encode`, `hexEncode` | Rare in detection rules; more useful for transformations or specialized logic. |
| Hashing | `sha1`, `md5` | Specialized matching or comparison workflows. |

## 6.3 Important Transformations for Rule Generation

| Transformation | Meaning | Best use |
|---|---|---|
| `t:none` | Clears inherited transformations. | Start custom rules with this. |
| `t:lowercase` | Converts value to lowercase. | Case-insensitive matching such as User-Agent or XSS tokens. |
| `t:utf8toUnicode` | Converts UTF-8 sequences to Unicode. | Input normalization for encoded attacks. |
| `t:urlDecodeUni` | Decodes URL encoding and Microsoft `%u` encoding. | URL-encoded XSS, SQLi, Shellshock, path traversal. |
| `t:compressWhitespace` | Converts many whitespace characters to spaces and compresses repeated spaces. | Shellshock, SQLi, whitespace-evasion payloads. |
| `t:removeNulls` | Removes null bytes. | Null-byte evasion. |
| `t:replaceComments` | Replaces comments. | SQL comment bypasses. |
| `t:normalisePath` / `t:normalizePath` | Normalizes path traversal patterns. | LFI/path traversal. |
| `t:base64Decode` | Decodes Base64. | Base64-encoded payload fields. |
| `t:hexDecode` | Decodes hexadecimal. | Hex-encoded payloads. |
| `t:jsDecode` | Decodes JavaScript escapes. | XSS payloads with JS escaping. |

## 6.4 Transformation Ordering Rule

Transformation order matters. Decode first, normalize second, then match.

Good ordering for Shellshock and generic request normalization:

```apache
t:none,t:utf8toUnicode,t:urlDecodeUni,t:compressWhitespace
```

Good ordering for XSS:

```apache
t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:removeNulls,t:lowercase
```

Good ordering for SQLi:

```apache
t:none,t:urlDecodeUni,t:replaceComments,t:compressWhitespace,t:lowercase
```

## 6.5 Why `t:none` Should Be Explicit

If no transformations are listed, transformations may be inherited from `SecDefaultAction` or other defaults in some contexts. A generated custom rule should avoid hidden behavior by explicitly starting with:

```apache
t:none
```

Then add only the transformations required for the attack.

---

# 7. Actions: What the WAF Does When a Rule Matches

## 7.1 Action Definition

Actions define what ModSecurity does after a successful match.

The LoadMaster guide groups actions into seven categories:

| Category | Purpose | Examples |
|---|---|---|
| Disruptive | Allows ModSecurity to take an enforcement action. | `allow`, `block`, `deny`, `pass` |
| Flow | Affects rule processing flow. | `skip`, `chain` |
| Meta-data | Provides information about rules. | `id`, `phase`, `msg`, `severity`, `tag` |
| Variable | Sets, changes, or removes variables. | `setvar`, `ctl` |
| Logging | Controls logs. | `log`, `auditlog`, `nolog` |
| Special | Provides access to other special functionality. | `ctl` |
| Miscellaneous | Actions not belonging to other groups. | Depends on ModSecurity support. |

## 7.2 Action Selection Matrix

| Desired behavior | Recommended action pattern |
|---|---|
| Block high-confidence attack | `deny,status:403,log,auditlog` |
| Use default blocking behavior | `block` |
| Allow or pass safe traffic | `pass` or carefully scoped `allow` |
| Disable engine for a specific IP transaction | `pass,nolog,ctl:ruleEngine=off` |
| Log only | `pass,log,auditlog` |
| Chain multiple checks | `chain` in the first rule |
| Suppress logs for safe allow-list rule | `nolog` |
| Add category or CVE metadata | `tag:'...'` |
| Add useful log message | `msg:'...'` |
| Include matched data in log | `logdata:'%{MATCHED_VAR}'` |

## 7.3 Default Actions

If no actions are provided, `SecDefaultAction` applies.

The source guide gives this equivalence:

```apache
SecRule ARGS "@rx D1"
```

is equivalent to:

```apache
SecRule ARGS "@rx D1" "phase:2,log,auditlog,pass"
```

Rule-generation implication:

- Do not rely on defaults when generating enforcement rules.
- Always specify `phase`.
- Always specify whether the rule should `deny`, `block`, `pass`, or log only.

## 7.4 Phases

A rule can run in one of five phases:

| Phase | Name | Best use |
|---|---|---|
| `phase:1` | Request Headers | URI, headers, request line, client IP, early blocking. |
| `phase:2` | Request Body | Arguments, POST payload, request body, most attack payload checks. |
| `phase:3` | Response Headers | Response header inspection. |
| `phase:4` | Response Body | Response body inspection. |
| `phase:5` | Logging | Final logging logic. |

Phase-selection guidance:

- Use `phase:1` for `REQUEST_HEADERS`, `REQUEST_LINE`, `REMOTE_ADDR`, and early decisions.
- Use `phase:2` for `ARGS`, `REQUEST_BODY`, POST data, and request-body-dependent checks.
- Use `phase:3` and `phase:4` only for response-side rules.
- Place the most selective check first in a chained rule to reduce unnecessary processing.

---

# 8. Rule Example: Validate User-Agent Header

## 8.1 Rule Objective

Only allow API clients whose `User-Agent` begins with a known IoT device prefix:

```text
AcmeWidget/1.2.34-r56
```

Deny requests that do not send a legitimate-looking User-Agent.

## 8.2 Source Rule Pattern

```apache
#
# -- Validate User-Agent Header
#
# The only legitimate access to our API is by IoT devices that we have deployed
# in the field. These will always identify themselves with a user agent that
# looks like:
# AcmeWidget/1.2.34-r56
# Deny any request that *does not* send a legitimate-looking user agent.
# Make the match case insensitive by using a 't:lowercase' transformation.
#
SecRule REQUEST_HEADERS:User-Agent "!@beginsWith acmewidget/" \
  "id:1000,\
  phase:1,\
  deny,\
  t:none,t:lowercase,\
  msg:'Legitimate AcmeWidget User-Agent header required',\
  logdata:'%{MATCHED_VAR}'"
```

## 8.3 Rule Explanation

| Component | Meaning |
|---|---|
| `REQUEST_HEADERS:User-Agent` | Inspect only the User-Agent header. |
| `!@beginsWith acmewidget/` | Match when the header does not begin with the expected prefix. |
| `phase:1` | Run early during request-header processing. |
| `deny` | Intercept the transaction. |
| `t:none,t:lowercase` | Clear inherited transformations and lowercase input before comparison. |
| `msg` | Add a clear message to the log. |
| `logdata:'%{MATCHED_VAR}'` | Log the matched value. |

## 8.4 Rule-Generation Use

Use this pattern for:

- IoT API allow-listing by User-Agent prefix
- scanner or bot rejection
- strict API client validation
- header-based policy enforcement

False-positive risk:

- User-Agent headers can be spoofed.
- Do not treat this as a cryptographic identity signal.
- Prefer this as a supplementary control, not as sole authentication.

---

# 9. Rule Example: Cross-Site Scripting (XSS)

## 9.1 Rule Objective

Detect a simple XSS attack by checking request parameters and headers for the `<script>` pattern.

## 9.2 Source Rule Pattern

```apache
SecRule ARGS|REQUEST_HEADERS "@rx <script>" \
  "id:101,\
  deny,\
  status:404,\
  msg:'XSS Attack'"
```

## 9.3 Source Rule Explanation

| Component | Meaning |
|---|---|
| `ARGS` | Request parameters. |
| `REQUEST_HEADERS` | All request headers. |
| `@rx <script>` | Regular expression match for `<script>`. |
| `id:101` | Unique rule ID. |
| `deny` | Stop rule processing and intercept the transaction. |
| `status:404` | Return HTTP response status `404`. |
| `msg:'XSS Attack'` | Log message. |

## 9.4 RAG-Optimized Safer XSS Rule

The source rule is intentionally simple. For rule generation, add explicit phase and transformations so encoded and case-varied payloads are less likely to bypass detection.

```apache
#
# -- Detect basic XSS script tag in parameters or headers
#
SecRule ARGS|REQUEST_HEADERS "@rx <\s*script\b" \
  "id:100101,\
  phase:2,\
  deny,\
  status:403,\
  t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:removeNulls,t:lowercase,\
  log,\
  auditlog,\
  msg:'XSS script tag detected in request parameters or headers',\
  logdata:'%{MATCHED_VAR}',\
  tag:'attack-xss'"
```

## 9.5 XSS Rule-Generation Guidance

Use this section when payloads contain:

```text
<script>
%3Cscript%3E
&lt;script&gt;
<ScRiPt>
```

Recommended variable selection:

| Payload location | Variable |
|---|---|
| Any parameter | `ARGS` |
| Specific parameter | `ARGS:<name>` |
| Header payload | `REQUEST_HEADERS` |
| User-Agent payload | `REQUEST_HEADERS:User-Agent` |
| URI payload | `REQUEST_URI` |

Recommended transformations:

```apache
t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:removeNulls,t:lowercase
```

False-positive notes:

- This can false positive on documentation, rich-text fields, code examples, or CMS editors.
- Narrow to `ARGS:<field>` if the vulnerable parameter is known.
- Use `pass,log,auditlog` before `deny` if production false-positive risk is unknown.

---

# 10. Rule Example: Allow-List an IP Address

## 10.1 Rule Objective

Allow-list a specific remote IP address by switching the ModSecurity rule engine off for transactions from that IP.

## 10.2 Source Rule Pattern

```apache
SecRule REMOTE_ADDR "@ipMatch 192.168.1.101" \
  "id:102,\
  phase:1,\
  pass,\
  t:none,\
  nolog,\
  ctl:ruleEngine=off"
```

## 10.3 Rule Explanation

| Component | Meaning |
|---|---|
| `REMOTE_ADDR` | The remote client IP address. |
| `@ipMatch 192.168.1.101` | Match IPv4 or IPv6 address against the allow-listed IP. |
| `phase:1` | Run early in request processing. |
| `pass` | Continue processing with the next rule after match. |
| `t:none` | Do not transform the IP address value. |
| `nolog` | Do not log the allow-list match. |
| `ctl:ruleEngine=off` | Turn off ModSecurity rule engine for the current transaction. |

## 10.4 LoadMaster Upload Constraint

> **Important:** Rules listing IP addresses with the `/32` subnet mask are not supported and will not upload successfully on LoadMaster.

Use:

```apache
@ipMatch 192.168.1.101
```

Avoid:

```apache
@ipMatch 192.168.1.101/32
```

## 10.5 Rule-Generation Guidance

Use this pattern for:

- trusted internal scanners
- monitoring systems
- specific internal clients
- emergency false-positive bypass for one known IP

Security warning:

- `ctl:ruleEngine=off` disables ModSecurity for the matched transaction.
- Scope allow-list rules carefully.
- Prefer narrower exceptions when possible.
- Consider using `Run First` if this allow-list must apply before CRS.

---

# 11. Rule Example: Chaining Rules

## 11.1 Chained Rule Definition

Chained rules allow multiple conditions to be combined. Conceptually, a rule chain behaves like an `AND` condition.

The disruptive action in the first rule is triggered only if all rules in the chain match.

If any chained condition is false, the whole chain is treated as false.

## 11.2 Source Chained Rule Scenario

The first rule checks whether:

```text
ARGS:username == admin
```

If true, the second rule checks whether:

```text
REMOTE_ADDR != 192.168.1.111
```

If both are true, the transaction is denied.

## 11.3 Source Rule Pattern

```apache
SecRule ARGS:username "@streq admin" \
  "id:103,\
  phase:2,\
  deny,\
  t:none,\
  log,\
  chain"
SecRule REMOTE_ADDR "!@streq 192.168.1.111"
```

## 11.4 Rule Explanation

| Component | Meaning |
|---|---|
| `ARGS:username` | Inspect only the `username` parameter. |
| `@streq admin` | Match if username equals `admin`. |
| `chain` | Require the next rule to match too. |
| `REMOTE_ADDR` | Inspect client IP. |
| `!@streq 192.168.1.111` | Match if remote IP is not the allowed IP. |
| `deny` | Deny only if both conditions match. |

## 11.5 Chaining Best Practice

The most unique or selective condition should appear first in the chain. This reduces the number of normal requests that need to be evaluated against later chain members.

Good first condition:

```apache
SecRule ARGS:username "@streq admin" ...
```

Good second condition:

```apache
SecRule REMOTE_ADDR "!@streq 192.168.1.111"
```

## 11.6 Rule-Generation Use

Use chaining for:

- endpoint + payload
- username + IP
- method + body payload
- path + suspicious header
- request component + exception condition

Example path-scoped XSS chain:

```apache
SecRule REQUEST_URI "@beginsWith /search" \
  "id:100103,\
  phase:2,\
  deny,\
  status:403,\
  t:none,\
  log,\
  chain,\
  msg:'XSS payload detected on search endpoint'"
SecRule ARGS:q "@rx <\s*script\b|onerror\s*=" \
  "t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase"
```

---

# 12. Rule Example: Shellshock Bash Attack

## 12.1 Rule Objective

Mitigate Shellshock Bash environment-variable injection by detecting the function-definition pattern:

```text
() {
```

Shellshock payloads often place `() {` in request headers, header names, request line, or request body.

## 12.2 First Rule: Request Line, Headers, and Header Names

```apache
SecRule REQUEST_LINE|REQUEST_HEADERS|REQUEST_HEADERS_NAMES "@contains () {" \
  "id:2100080,\
  phase:1,\
  block,\
  t:none,t:utf8toUnicode,t:urlDecodeUni,t:compressWhitespace,\
  msg:'SLR: Bash ENV Variable Injection Attack',\
  tag:'CVE-2014-6271',\
  tag:'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271',\
  tag:'https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/'"
```

## 12.3 First Rule Explanation

| Component | Meaning |
|---|---|
| `REQUEST_LINE` | Complete request line including method and HTTP version. |
| `REQUEST_HEADERS` | All request headers. |
| `REQUEST_HEADERS_NAMES` | Names of request headers. |
| `@contains () {` | Match Shellshock function-definition string. |
| `phase:1` | Run in request-header phase. |
| `block` | Use the configured blocking behavior. |
| `t:utf8toUnicode,t:urlDecodeUni,t:compressWhitespace` | Normalize Unicode, URL encoding, and whitespace. |
| `tag:'CVE-2014-6271'` | Categorize the event as Shellshock. |

## 12.4 Second Rule: Request Body

```apache
SecRule REQUEST_BODY "@contains () {" \
  "id:2100081,\
  phase:2,\
  block,\
  t:none,t:utf8toUnicode,t:urlDecodeUni,t:compressWhitespace,\
  msg:'SLR: Bash ENV Variable Injection Attack',\
  tag:'CVE-2014-6271',\
  tag:'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271',\
  tag:'https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/'"
```

## 12.5 Second Rule Explanation

| Component | Meaning |
|---|---|
| `REQUEST_BODY` | Inspect the request body. |
| `@contains () {` | Match Shellshock function-definition string. |
| `phase:2` | Request body is available in phase 2. |
| `block` | Apply blocking behavior from defaults. |
| `t:utf8toUnicode,t:urlDecodeUni,t:compressWhitespace` | Normalize encoded and whitespace-obfuscated payloads. |

## 12.6 Shellshock Rule-Generation Guidance

Use this section when attack type is:

```text
RCE
command injection
Shellshock
Bash environment variable injection
CVE-2014-6271
```

Recommended two-rule strategy:

1. `phase:1` for request line, headers, and header names
2. `phase:2` for request body

Recommended operator:

```apache
@contains () {
```

Recommended transformations:

```apache
t:none,t:utf8toUnicode,t:urlDecodeUni,t:compressWhitespace
```

Recommended tags:

```apache
tag:'CVE-2014-6271'
tag:'attack-rce'
tag:'attack-shellshock'
```

## 12.7 Shellshock False-Positive Notes

The string `() {` is unusual in normal HTTP requests, so high-confidence blocking is reasonable. Still check:

- developer documentation endpoints
- code-upload APIs
- endpoints that legitimately accept shell scripts
- log shipping endpoints that may contain raw attack traffic

If false positives are possible, scope the rule by path or target field.

---

# 13. `block`, `deny`, `pass`, and `SecDefaultAction`

## 13.1 `SecDefaultAction`

`SecDefaultAction` defines default actions inherited by later rules in the same phase and configuration context.

Default behavior shown in the source guide:

```apache
phase:2,log,auditlog,pass
```

A generated rule should not rely on this unless the goal is explicitly to inherit default behavior.

## 13.2 `block` Action

The `block` action is a placeholder. It requests a blocking action without specifying how blocking is performed.

The actual blocking behavior comes from the most recent applicable `SecDefaultAction` in the same context.

## 13.3 Block Example 1: Default Action Is Deny

```apache
SecDefaultAction phase:2,deny,id:101,status:403,log,auditlog

SecRule ARGS attack2 phase:2,pass,id:103

SecRule ARGS attack1 phase:2,block,id:102
```

Meaning:

- The `SecDefaultAction` is set to `deny`.
- The rule with `block` will behave as `deny`.
- The rule with `pass` explicitly passes.

## 13.4 Block Example 2: Override with `SecRuleUpdateActionById`

```apache
SecDefaultAction phase:2,pass,log,auditlog

SecRule ARGS attack1 phase:2,deny,id:1

SecRuleUpdateActionById 1 block
```

Meaning:

- The default action is `pass`.
- The first rule originally says `deny`.
- `SecRuleUpdateActionById 1 block` changes rule ID `1` to use `block`.
- Because the active default action is `pass`, the rule effectively passes rather than denies.

## 13.5 Rule-Generation Guidance for `block`

Use `block` when:

- writing CRS-compatible or default-action-driven rules
- deployment intentionally controls enforcement through `SecDefaultAction`
- the rule should follow global blocking configuration

Use `deny,status:403` when:

- generating a standalone custom rule that must block clearly
- the desired response status should be explicit
- avoiding ambiguity matters more than inheriting defaults

Use `pass,log,auditlog` when:

- testing a new rule
- monitoring false positives
- generating a non-blocking validation rule

---

# 14. LoadMaster WUI Settings Relevant to Custom Rules

## 14.1 WAF Settings Per Virtual Service

In the LoadMaster Web User Interface, WAF settings are configured for each individual Virtual Service.

Relevant WUI concepts include:

- WAF enablement per Virtual Service
- OWASP CRS enablement
- audit mode
- anomaly scoring threshold
- paranoia level
- Manage Rules list
- Rule Filter
- Run First for custom rules
- Apply / Reset behavior

## 14.2 Rule-Generation Implication

A generated custom rule is not complete operationally until it is:

1. uploaded to LoadMaster
2. assigned to a Virtual Service
3. enabled in the WAF section
4. ordered correctly relative to CRS
5. tested for misconfiguration
6. applied and backed up

---

# 15. Managing Custom WAF Rules in LoadMaster

## 15.1 Add a Custom Rule

To add custom WAF rules in LoadMaster WUI:

1. In the main menu, select **Web Application Firewall > Custom Rules**.
2. In the **Installed Rules** section, click **Choose File**.
3. Browse to and select the rule file.
4. Click **Add Ruleset**.
5. If the rule has associated data files, go to **Custom Rule Data**.
6. Click **Choose File**.
7. Browse to and select the data file.
8. Click **Add Data File**.

After upload, the rules become available in the Virtual Services modify screen:

```text
Virtual Services > View/Modify Services > Modify
```

## 15.2 Supported Rule File Packaging

Individual custom rules can be uploaded as:

```text
.conf
```

Packages of rules can be uploaded as:

```text
tar.gz
```

Rules and associated data files can be packaged together in a tarball.

## 15.3 Filename Constraints

The uploaded rule filename must follow these constraints:

| Constraint | Requirement |
|---|---|
| First character | Must be an alphabetic character or underscore `_`. |
| Other characters | May include letters, numbers, full stops `.`, and dashes `-`. |
| Unsupported IP syntax note | Rules listing IP addresses with `/32` subnet mask are not supported and will not upload successfully. |

Good filenames:

```text
custom_xss_rules.conf
```

```text
app-shellshock-rules.conf
```

```text
custom_rules_package.tar.gz
```

Risky filename:

```text
1-custom-rule.conf
```

Reason:

```text
The first character is not alphabetic or underscore.
```

## 15.4 Custom Rule Data Files

Use **Custom Rule Data** for associated files used by custom rules.

Examples:

```text
ipMatchFrom.txt
owasp_cust.data
test_blacklist.txt
```

Use data files when:

- the rule references external IP lists
- the rule references phrase lists
- the rule uses custom data collections
- the rule package is distributed with dependent lookup files

## 15.5 Delete or Download a Custom Rule or Data File

Custom rules and data files can be deleted or downloaded using the relevant WUI buttons.

> **Important:** If a rule is assigned to a Virtual Service, it is not available for deletion.

Rule-generation deployment guidance should include:

- unassign the rule from Virtual Services before deleting it
- download a backup copy before changing production rules
- check Virtual Service assignments before cleanup

---

# 16. Assigning Custom Rules to a Virtual Service

## 16.1 Precondition

Before assigning a custom rule to a Virtual Service, the rule must already be installed on LoadMaster.

## 16.2 Assignment Workflow

To assign a custom rule to a Virtual Service:

1. In the main menu, select **Virtual Services > View/Modify Services**.
2. Click **Modify** on the relevant Virtual Service.
3. Expand the **WAF** section.
4. Select **Enabled**.
5. In **Manage Rules**, select the custom rules or rulesets to assign.
6. Enable or disable individual rules per ruleset by selecting or unselecting check boxes.
7. Use **Rule Filter** to filter rules by a search term.
8. Use **Clear All** to disable all rules for the selected ruleset.
9. Use **Set All** to enable all rules for the selected ruleset.
10. Use **Reset** to disable all rules and rulesets.
11. Click **Apply**.

## 16.3 WAF Enablement Limit

When enabling WAF for a Virtual Service, LoadMaster displays how many WAF-enabled Virtual Services exist and the maximum number allowed.

If the maximum number of WAF-enabled Virtual Services has been reached, the **Enabled** check box becomes greyed out.

## 16.4 Run First Ordering

LoadMaster provides a **Run First** check box for custom rules.

| Run First setting | Behavior |
|---|---|
| Enabled | Custom rule runs before OWASP Core Rule Set. |
| Disabled | Custom rule runs after OWASP Core Rule Set. |
| Default | Disabled. |

Use `Run First` when:

- an allow-list or exclusion must apply before CRS
- a custom emergency block should trigger before CRS
- a custom rule must reduce false positives before CRS processing
- an app-specific rule should override generic CRS behavior

Do not use `Run First` casually. Running custom rules before CRS can affect security behavior.

## 16.5 Assignment Checklist

- [ ] Rule file is installed.
- [ ] WAF is enabled for the target Virtual Service.
- [ ] Correct custom ruleset is selected in Manage Rules.
- [ ] Individual rules are enabled as required.
- [ ] Rule Filter is cleared before final review.
- [ ] `Run First` is enabled only if needed.
- [ ] Click **Apply** after changes.
- [ ] Test the Virtual Service after applying.

---

# 17. WAF Misconfigured State

## 17.1 Definition

On the LoadMaster **View/Modify Services** screen, the status of each Virtual Service is displayed.

If the WAF for a Virtual Service is misconfigured, for example because of a rule file issue, the status changes to:

```text
WAF Misconfigured
```

The status turns red.

## 17.2 Operational Impact

If a Virtual Service enters `WAF Misconfigured` state:

> **All traffic is blocked.**

This is critical for deployment workflows.

## 17.3 Troubleshooting Guidance

If a Virtual Service is in `WAF Misconfigured` state:

1. Disable WAF for that Virtual Service if needed to stop traffic from being blocked while troubleshooting.
2. Review recently uploaded custom rule files.
3. Check syntax, rule IDs, quoting, line continuations, and unsupported `/32` IP mask usage.
4. Confirm associated data files were uploaded.
5. Remove or fix the faulty custom ruleset.
6. Re-enable WAF and apply after validation.
7. Back up the configuration after a successful fix.

## 17.4 Rule-Generation Warning

Generated rules should avoid syntax that may fail upload or trigger misconfiguration:

- invalid line continuations
- missing quotes around complex action lists
- unsupported `/32` IP mask
- duplicate rule IDs
- missing associated data files
- malformed tarball packaging
- invalid ModSecurity action syntax
- unsupported directives in LoadMaster’s ModSecurity environment

---

# 18. Backup and Restore of WAF Configuration

## 18.1 Backup Workflow

A backup of the LoadMaster configuration can be created by going to:

```text
System Administration > Backup/Restore
```

Then click:

```text
Create Backup File
```

## 18.2 Restore Workflow

Configuration can be restored from the same Backup/Restore screen.

Important restore selections:

| Restore option | Meaning |
|---|---|
| `VS Configuration` | Restores Virtual Service settings. |
| `LoadMaster Base Configuration` | Restores rules. |

## 18.3 License Constraint

> **Important:** A WAF configuration can only be restored onto a LoadMaster with a WAF license.

## 18.4 Deployment Guidance

After deploying or changing custom WAF rules:

- create a backup
- document which Virtual Services use the rules
- document whether `Run First` is enabled
- include rule files and data files in operational records
- keep a rollback plan for WAF Misconfigured state

---

# 19. Rule-Generation Templates

## 19.1 Standalone Blocking Rule Template

```apache
#
# -- <Rule objective>
#
SecRule <VARIABLES> "<OPERATOR>" \
  "id:<ID>,\
  phase:<PHASE>,\
  deny,\
  status:403,\
  t:none,<TRANSFORMATIONS>,\
  log,\
  auditlog,\
  msg:'<Clear attack-specific message>',\
  logdata:'%{MATCHED_VAR}',\
  tag:'<attack-tag>'"
```

Use when:

- the match is high confidence
- enforcement should be explicit
- the rule should not depend on `SecDefaultAction`

## 19.2 Default-Action Blocking Rule Template

```apache
#
# -- <Rule objective>
#
SecRule <VARIABLES> "<OPERATOR>" \
  "id:<ID>,\
  phase:<PHASE>,\
  block,\
  t:none,<TRANSFORMATIONS>,\
  log,\
  auditlog,\
  msg:'<Clear attack-specific message>',\
  logdata:'%{MATCHED_VAR}',\
  tag:'<attack-tag>'"
```

Use when:

- deployment intentionally controls blocking through `SecDefaultAction`
- CRS-compatible behavior is preferred
- `block` should follow global policy

## 19.3 Monitoring-Only Rule Template

```apache
#
# -- Monitor <attack/policy> before blocking
#
SecRule <VARIABLES> "<OPERATOR>" \
  "id:<ID>,\
  phase:<PHASE>,\
  pass,\
  t:none,<TRANSFORMATIONS>,\
  log,\
  auditlog,\
  msg:'Potential <attack/policy> observed - monitoring only',\
  logdata:'%{MATCHED_VAR}'"
```

Use when:

- false-positive risk is unknown
- production impact must be measured first
- rule should be tuned before enforcement

## 19.4 IP Allow-List Template

```apache
#
# -- Allow-list trusted client IP
#
SecRule REMOTE_ADDR "@ipMatch <IP_ADDRESS>" \
  "id:<ID>,\
  phase:1,\
  pass,\
  t:none,\
  nolog,\
  ctl:ruleEngine=off"
```

LoadMaster constraint:

```text
Do not use /32 subnet mask in IP allow-list rules uploaded to LoadMaster.
```

## 19.5 Chained Rule Template

```apache
#
# -- <Rule objective>
#
SecRule <MOST_SELECTIVE_VARIABLE> "<FIRST_OPERATOR>" \
  "id:<ID>,\
  phase:<PHASE>,\
  deny,\
  status:403,\
  t:none,\
  log,\
  chain,\
  msg:'<Clear message>'"
SecRule <SECOND_VARIABLE> "<SECOND_OPERATOR>" \
  "t:none,<TRANSFORMATIONS>"
```

Use when:

- two or more conditions must be true
- a path or user condition should scope an attack payload
- false positives can be reduced by requiring multiple signals

---

# 20. Attack-Specific Rule Guidance

## 20.1 XSS Rule Guidance

Use this pattern for XSS in request parameters or headers:

```apache
SecRule ARGS|REQUEST_HEADERS "@rx <\s*script\b|onerror\s*=|onload\s*=|javascript:" \
  "id:200101,\
  phase:2,\
  deny,\
  status:403,\
  t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:removeNulls,t:lowercase,\
  log,\
  auditlog,\
  msg:'XSS payload detected in request input',\
  logdata:'%{MATCHED_VAR}',\
  tag:'attack-xss'"
```

Use narrower target if known:

```apache
SecRule ARGS:q "@rx <\s*script\b|onerror\s*=|javascript:" \
  "id:200102,\
  phase:2,\
  deny,\
  status:403,\
  t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:removeNulls,t:lowercase,\
  log,\
  auditlog,\
  msg:'XSS payload detected in q parameter',\
  logdata:'%{MATCHED_VAR}',\
  tag:'attack-xss'"
```

## 20.2 SQL Injection Rule Guidance

This LoadMaster guide does not provide a dedicated SQLi signature. For SQLi rule generation, prefer a CRS 942 SQLi knowledge base. If only this document is retrieved, use its ModSecurity mechanics and produce a conservative rule.

Generic SQLi rule:

```apache
SecRule ARGS "@rx union\s+select|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema" \
  "id:200201,\
  phase:2,\
  deny,\
  status:403,\
  t:none,t:urlDecodeUni,t:replaceComments,t:compressWhitespace,t:lowercase,\
  log,\
  auditlog,\
  msg:'SQL injection payload detected in request arguments',\
  logdata:'%{MATCHED_VAR}',\
  tag:'attack-sqli'"
```

Use a specific parameter if known:

```apache
SecRule ARGS:id "@rx union\s+select|or\s+1\s*=\s*1|sleep\s*\(" \
  "id:200202,\
  phase:2,\
  deny,\
  status:403,\
  t:none,t:urlDecodeUni,t:replaceComments,t:compressWhitespace,t:lowercase,\
  log,\
  auditlog,\
  msg:'SQL injection payload detected in id parameter',\
  logdata:'%{MATCHED_VAR}',\
  tag:'attack-sqli'"
```

## 20.3 Shellshock / Bash RCE Rule Guidance

Use the two-rule pattern from the source guide:

```apache
SecRule REQUEST_LINE|REQUEST_HEADERS|REQUEST_HEADERS_NAMES "@contains () {" \
  "id:2100080,\
  phase:1,\
  block,\
  t:none,t:utf8toUnicode,t:urlDecodeUni,t:compressWhitespace,\
  msg:'SLR: Bash ENV Variable Injection Attack',\
  tag:'CVE-2014-6271',\
  tag:'attack-rce'"
```

```apache
SecRule REQUEST_BODY "@contains () {" \
  "id:2100081,\
  phase:2,\
  block,\
  t:none,t:utf8toUnicode,t:urlDecodeUni,t:compressWhitespace,\
  msg:'SLR: Bash ENV Variable Injection Attack',\
  tag:'CVE-2014-6271',\
  tag:'attack-rce'"
```

## 20.4 Scanner or User-Agent Rule Guidance

Block known scanner strings:

```apache
SecRule REQUEST_HEADERS:User-Agent "@rx sqlmap|nikto|acunetix|nuclei" \
  "id:200301,\
  phase:1,\
  deny,\
  status:403,\
  t:none,t:lowercase,\
  log,\
  auditlog,\
  msg:'Known scanner User-Agent detected',\
  logdata:'%{MATCHED_VAR}',\
  tag:'automation-scanner'"
```

Require a known User-Agent prefix:

```apache
SecRule REQUEST_HEADERS:User-Agent "!@beginsWith acmewidget/" \
  "id:200302,\
  phase:1,\
  deny,\
  status:403,\
  t:none,t:lowercase,\
  log,\
  msg:'Legitimate AcmeWidget User-Agent header required',\
  logdata:'%{MATCHED_VAR}'"
```

## 20.5 IP Exception Rule Guidance

```apache
SecRule REMOTE_ADDR "@ipMatch 192.168.1.101" \
  "id:200401,\
  phase:1,\
  pass,\
  t:none,\
  nolog,\
  ctl:ruleEngine=off"
```

Do not use:

```apache
@ipMatch 192.168.1.101/32
```

because LoadMaster upload does not support IP rules with `/32` subnet mask.

---

# 21. False Positives and Tuning

## 21.1 General Tuning Principles

- Prefer specific variables over broad variables.
- Use chaining to require multiple conditions.
- Use `pass,log,auditlog` before blocking risky rules.
- Use `Run First` only when the custom rule must run before CRS.
- Avoid disabling the entire rule engine unless the match is highly trusted.
- Do not use broad regexes against all headers unless necessary.
- Keep custom rules readable and commented.

## 21.2 XSS False Positive Sources

XSS rules can false positive on:

- CMS editors
- rich-text fields
- HTML documentation
- code snippets
- browser testing tools
- developer APIs

Tuning options:

- target a specific parameter such as `ARGS:q`
- exclude known safe fields in a separate tuning rule if supported
- log first before blocking
- chain with path or method

## 21.3 SQLi False Positive Sources

SQLi rules can false positive on:

- search fields
- SQL documentation
- database admin interfaces
- logging dashboards
- developer tools

Tuning options:

- target known vulnerable parameters
- use stricter SQLi signatures from CRS 942
- require multiple SQLi signals using chain or anomaly scoring
- log first before blocking

## 21.4 Allow-List Risk

Allow-list rules using:

```apache
ctl:ruleEngine=off
```

are powerful and risky because they disable ModSecurity processing for the matched transaction.

Use only when:

- the IP is trusted
- the IP is stable
- the business risk is accepted
- the rule is documented
- the rule is tested
- the rule is reviewed periodically

---

# 22. LoadMaster Deployment Checklist for Generated Rules

## 22.1 Pre-Upload Rule Checklist

- [ ] Rule has a unique `id`.
- [ ] Rule has an explicit `phase`.
- [ ] Rule has an explicit action: `deny`, `block`, `pass`, or `allow`.
- [ ] Rule starts transformations with `t:none`.
- [ ] Rule uses transformations appropriate to the bypass.
- [ ] Rule has a clear `msg`.
- [ ] Long lines use backslash correctly.
- [ ] Quotes are balanced.
- [ ] Regex is valid.
- [ ] IP rules do not use unsupported `/32` subnet mask.
- [ ] Associated data files are included if required.
- [ ] File name starts with an alphabetic character or `_`.
- [ ] File extension/package is `.conf` or `tar.gz`.

## 22.2 Upload Checklist

- [ ] Go to `Web Application Firewall > Custom Rules`.
- [ ] Upload rules in **Installed Rules**.
- [ ] Click **Add Ruleset**.
- [ ] Upload associated data files under **Custom Rule Data**.
- [ ] Click **Add Data File** if needed.
- [ ] Confirm rules appear in the installed list.

## 22.3 Assignment Checklist

- [ ] Go to `Virtual Services > View/Modify Services`.
- [ ] Modify the target Virtual Service.
- [ ] Expand **WAF**.
- [ ] Select **Enabled**.
- [ ] Assign custom rules in **Manage Rules**.
- [ ] Enable relevant individual rules.
- [ ] Decide whether `Run First` is needed.
- [ ] Click **Apply**.
- [ ] Confirm service does not enter `WAF Misconfigured` state.

## 22.4 Post-Deployment Checklist

- [ ] Test malicious payloads.
- [ ] Test benign traffic.
- [ ] Check logs.
- [ ] Monitor false positives.
- [ ] Back up configuration.
- [ ] Document rule IDs and Virtual Services using them.
- [ ] Create rollback steps.

---

# 23. RAG Retrieval Keywords

Use these keywords naturally in retrieval queries for this document.

## 23.1 LoadMaster and Deployment Keywords

```text
Progress Kemp LoadMaster WAF
custom rules
Web Application Firewall Custom Rules
Installed Rules
Custom Rule Data
Add Ruleset
Add Data File
Virtual Services View Modify Services
Manage Rules
Run First
WAF Misconfigured
Backup Restore
LoadMaster Base Configuration
VS Configuration
```

## 23.2 ModSecurity Rule Keywords

```text
SecRule
SecDefaultAction
SecRuleUpdateActionById
VARIABLES OPERATOR TRANSFORMATION_FUNCTIONS ACTIONS
ARGS
REQUEST_HEADERS
REQUEST_HEADERS:User-Agent
REQUEST_HEADERS_NAMES
REQUEST_URI
REQUEST_LINE
REQUEST_BODY
REMOTE_ADDR
@rx
@beginsWith
@ipMatch
@streq
@contains
deny
block
pass
nolog
ctl:ruleEngine=off
chain
phase:1
phase:2
t:none
t:lowercase
t:utf8toUnicode
t:urlDecodeUni
t:compressWhitespace
```

## 23.3 Attack Keywords

```text
XSS
Cross Site Scripting
<script>
Shellshock
Bash ENV Variable Injection Attack
CVE-2014-6271
command injection
RCE
scanner User-Agent
SQL injection
allow-list IP address
```

---

# 24. Final Output Template for LLM Rule Generation

When this document is retrieved, generate output in the following structure:

```markdown
## Rule Objective

- WAF platform: Progress Kemp LoadMaster
- Rule language: ModSecurity
- Attack or policy:
- Payload location:
- Desired action:

## Proposed ModSecurity Rule

```apache
SecRule ...
```

## Why This Rule Matches

Explain:
- selected variables
- selected operator
- transformations
- action
- phase

## LoadMaster Deployment Steps

1. Save the rule as a valid `.conf` file.
2. Go to Web Application Firewall > Custom Rules.
3. Upload the rule under Installed Rules.
4. Add any Custom Rule Data files if required.
5. Assign the rule to the correct Virtual Service.
6. Decide whether Run First is required.
7. Click Apply.
8. Confirm the Virtual Service does not show WAF Misconfigured.

## False Positives and Tuning

Explain:
- expected false positives
- narrower target alternatives
- log-only test mode
- whether `Run First` should be enabled
- rollback plan
```

---

# 25. Final Rule Authoring Checklist

- [ ] Select the correct variable for the payload location.
- [ ] Select the correct operator.
- [ ] Use explicit transformations.
- [ ] Start transformations with `t:none`.
- [ ] Include `id`.
- [ ] Include `phase`.
- [ ] Include `msg`.
- [ ] Include logging or intentionally suppress logs.
- [ ] Use `deny,status:403` for explicit standalone blocking.
- [ ] Use `block` only when default-action behavior is desired.
- [ ] Use `pass,log,auditlog` for monitoring.
- [ ] Use `chain` when multiple conditions are required.
- [ ] Use `ctl:ruleEngine=off` only for trusted and narrow allow-listing.
- [ ] Avoid unsupported `/32` IP subnet rules on LoadMaster.
- [ ] Upload as `.conf` or package as `tar.gz`.
- [ ] Assign the custom rule to a Virtual Service.
- [ ] Use `Run First` only when the custom rule must run before CRS.
- [ ] Watch for `WAF Misconfigured` state after deployment.
- [ ] Back up the configuration after successful deployment.
