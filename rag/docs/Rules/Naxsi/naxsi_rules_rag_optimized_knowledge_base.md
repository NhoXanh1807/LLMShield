# Naxsi Rules Knowledge Base for RAG and WAF Rule Generation
# 1. Naxsi Rule Model
## 1.1 Definition

A Naxsi rule is a search pattern applied to an HTTP request to detect malicious behavior.

A Naxsi rule is defined by:

```text
MainRule or BasicRule
+ rule id
+ score
+ search parameter
+ matchzone
+ optional description
```

The source document defines a rule as a search pattern that is applied to a request to detect malicious behaviour.

## 1.2 Rule Components

| Component | Required? | Format | Purpose |
|---|---:|---|---|
| Directive | Yes | `MainRule` or `BasicRule` | Defines whether the rule is global or location-specific. |
| Rule ID | Yes | `id:<positive_integer>` | Identifies triggered rules in logs and whitelists. |
| Score | Yes | `"s:$<name>:<value>"` | Increments a score counter used by `CheckRule`. |
| Search parameter | Yes | `"str:<string>"` or `"rx:<regex>"` | Defines the literal or regex pattern to search for. |
| Matchzone | Yes | `"mz:<zone>"` | Defines where in the request the rule searches. |
| Description | Optional | `"msg:<description>"` | Explains what the rule does for logs and human operators. |

## 1.3 Canonical Rule Syntax

Global rule:

```nginx
MainRule id:<ID> "s:$<SCORE>:<POINTS>" "str:<CASE_INSENSITIVE_STRING>" "mz:<MATCHZONE>" "msg:<DESCRIPTION>";
```

Location-specific rule:

```nginx
BasicRule id:<ID> "s:$<SCORE>:<POINTS>" "rx:<CASE_INSENSITIVE_PCRE_REGEX>" "mz:<MATCHZONE>" "msg:<DESCRIPTION>";
```

## 1.4 Source Examples

String rule:

```nginx
MainRule id:12345 "s:$FOO:8,$BAR:4" "str:malicious" "mz:URL" "msg:string rule description";
```

Regex rule:

```nginx
BasicRule id:67890 "s:$TOO:4" "rx:[a-z]{5}" "mz:ARGS" "msg:regex rule description";
```

## 1.5 Rule-Generation Principle

When generating a Naxsi rule, always produce:

1. a valid `MainRule` or `BasicRule`
2. a custom ID greater than `999`
3. one or more score increments
4. a `str:` or `rx:` search parameter
5. a precise `mz:` matchzone
6. a useful `msg:`
7. a matching `CheckRule` in the protected `location`

A score-producing rule without a matching `CheckRule` will not trigger an action for user-defined rules.

---

# 2. `MainRule` and `BasicRule`

## 2.1 Two Rule Directives

Naxsi has two kinds of rules:

| Directive | Scope | Meaning |
|---|---|---|
| `MainRule` | `http` block | Global rule or global whitelist. |
| `BasicRule` | `location` block | Location-specific rule or location-specific whitelist. |

Both directives are mandatory for defining a Naxsi rule. A rule must use one of them.

## 2.2 `MainRule` for Global Rules

Use `MainRule` when the detection rule should apply globally.

Example:

```nginx
http {
    MainRule id:500100 "s:$UWA:8" "str:nmap" "mz:$HEADERS_VAR:User-Agent" "msg:nmap scanner in user-agent";
}
```

A global `MainRule` still needs a `CheckRule` inside each protected `location` where the score should trigger an action:

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";
    CheckRule "$UWA >= 8" BLOCK;
}
```

## 2.3 `BasicRule` for Location-Specific Rules

Use `BasicRule` when the detection rule should apply only in a specific NGINX `location`.

Example:

```nginx
location /api/ {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:500101 "s:$SQL:8" "rx:union\s+select|or\s+1\s*=\s*1" "mz:ARGS|BODY" "msg:custom SQLi indicators for API";

    CheckRule "$SQL >= 8" BLOCK;
}
```

## 2.4 MainRule vs BasicRule Decision Matrix

| Requirement | Use |
|---|---|
| Detection should apply to every protected location | `MainRule` |
| Detection should apply only to one endpoint or path | `BasicRule` |
| Global scanner User-Agent detection | `MainRule` |
| Endpoint-specific virtual patch | `BasicRule` |
| Global whitelist | `MainRule` |
| Narrow false-positive tuning | `BasicRule` |
| Known application whitelist inside one location | `BasicRule` |

## 2.5 Common Scope Mistake

Incorrect:

```nginx
location / {
    MainRule id:500100 "s:$UWA:8" "str:nmap" "mz:$HEADERS_VAR:User-Agent" "msg:nmap";
}
```

Correct:

```nginx
http {
    MainRule id:500100 "s:$UWA:8" "str:nmap" "mz:$HEADERS_VAR:User-Agent" "msg:nmap";
}
```

Incorrect:

```nginx
http {
    BasicRule id:500101 "s:$SQL:8" "rx:union\s+select" "mz:ARGS" "msg:sqli";
}
```

Correct:

```nginx
location / {
    BasicRule id:500101 "s:$SQL:8" "rx:union\s+select" "mz:ARGS" "msg:sqli";
}
```

## 2.6 Rule-Generation Checklist for Directive Choice

- [ ] Use `MainRule` for global rule.
- [ ] Use `BasicRule` for location-specific rule.
- [ ] Do not put `MainRule` inside `location`.
- [ ] Do not put `BasicRule` inside `http`.
- [ ] Ensure a matching `CheckRule` exists in the location.
- [ ] Prefer `BasicRule` for virtual patches and false-positive tuning.

---

# 3. Rule ID

## 3.1 Rule ID Definition

The rule identifier identifies triggered rules for blocked requests, logs, and whitelists.

Format:

```text
id:<number>
```

Example:

```nginx
id:12345
```

## 3.2 Custom Rule ID Requirement

A user-defined Naxsi rule ID must be:

```text
a positive integer greater than 999
```

Correct:

```nginx
BasicRule id:500200 "s:$SQL:8" "rx:union\s+select" "mz:ARGS" "msg:custom SQLi rule";
```

Incorrect:

```nginx
BasicRule id:99 "s:$SQL:8" "rx:union\s+select" "mz:ARGS" "msg:invalid custom SQLi rule";
```

Reason:

```text
ID 99 is within the reserved internal rule range.
```

## 3.3 Reserved Internal Rule IDs

Naxsi has internal rules hardcoded inside the WAF. These rules use reserved IDs.

The source document states that internal rules are defined by reserved IDs from:

```text
1 to 1000
```

Rule-generation safety policy:

```text
Do not generate custom rule IDs from 1 through 1000.
Use IDs greater than 1000 for generated custom rules.
```

This stricter policy avoids collisions with the reserved range and avoids ambiguity around the boundary value `1000`.

## 3.4 Duplicate Rule IDs

The source states that it is possible to use the same rule ID multiple times, but it is not suggested.

Reason:

```text
Rule IDs are used for logging and whitelisting.
```

If the same ID appears on multiple rules:

- logs become ambiguous
- whitelists may affect more than intended
- debugging becomes harder
- retrieval evidence may be harder to map to the generated rule
- automated tooling may misinterpret which rule fired

## 3.5 Recommended ID Ranges for Generated Rules

For generated project-specific rules, use a high, dedicated range.

Example policy:

| Range | Purpose |
|---:|---|
| `500000-509999` | Generated Naxsi SQLi rules |
| `510000-519999` | Generated Naxsi XSS rules |
| `520000-529999` | Generated traversal/LFI rules |
| `530000-539999` | Generated RFI rules |
| `540000-549999` | Generated upload rules |
| `550000-559999` | Generated scanner/UWA rules |
| `560000-569999` | Generated evasion rules |
| `570000-579999` | Generated application-specific virtual patches |

## 3.6 Rule ID Checklist

- [ ] Use `id:<number>`.
- [ ] Use a positive integer.
- [ ] Use an ID greater than `1000` for generated custom rules.
- [ ] Do not use IDs from `1` to `1000`.
- [ ] Avoid duplicate IDs.
- [ ] Keep ID ranges documented.
- [ ] Use internal rule IDs only in whitelist directives such as `wl:<id>`, not as custom detection rule IDs.

---

# 4. Rule Score

## 4.1 Score Definition

Each Naxsi rule must define a score. The score increases a `CheckRule` counter for each request.

Format:

```text
"s:$<name>:<value>"
```

Example:

```nginx
"s:$SQL:8"
```

Meaning:

- increment `$SQL`
- by `8`

## 4.2 Multiple Scores

A single rule can assign multiple scores by separating score values with commas.

Format:

```text
"s:$<name>:<value>,$<name>:<value>,..."
```

Source example format:

```nginx
"s:$FOO:8,$BAR:4,$BAZ:4"
```

Example generated multi-score rule:

```nginx
BasicRule id:500300 "s:$SQL:8,$EVADE:4" "rx:union\s*/\*.*\*/\s*select" "mz:ARGS|BODY" "msg:SQLi with comment-based evasion";
```

This rule increments:

```text
$SQL by 8
$EVADE by 4
```

## 4.3 Score Requires CheckRule

If no `CheckRule` is defined for a given variable, the user-defined rule will never trigger an action.

Example ineffective configuration:

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:500301 "s:$SQL:8" "rx:union\s+select" "mz:ARGS" "msg:SQLi";

    # Missing CheckRule "$SQL >= 8" BLOCK;
}
```

Correct configuration:

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:500301 "s:$SQL:8" "rx:union\s+select" "mz:ARGS" "msg:SQLi";

    CheckRule "$SQL >= 8" BLOCK;
}
```

## 4.4 Common Score Variables

| Score | Attack category | Typical threshold |
|---|---|---:|
| `$SQL` | SQL injection | `8` |
| `$XSS` | Cross-site scripting | `8` |
| `$RFI` | Remote File Inclusion | `8` |
| `$TRAVERSAL` | Path traversal / LFI | `5` |
| `$UPLOAD` | Malicious upload | `5` |
| `$UWA` | Unwanted access / scanners | `8` |
| `$EVADE` | Evasion and obfuscation | `8` |
| `$LIBINJECTION_SQL` | libinjection SQLi | `8` or tuned value |
| `$LIBINJECTION_XSS` | libinjection XSS | `8` or tuned value |

## 4.5 Score Design Matrix for Rule Generation

| Rule intent | Recommended score |
|---|---|
| SQLi signature | `$SQL:8` |
| XSS signature | `$XSS:8` |
| RFI signature | `$RFI:8` |
| Directory traversal or LFI | `$TRAVERSAL:5` |
| Upload abuse | `$UPLOAD:5` |
| Scanner or unwanted access | `$UWA:8` |
| Encoding or obfuscation evasion | `$EVADE:8` |
| SQLi with evasion | `$SQL:8,$EVADE:4` |
| XSS with evasion | `$XSS:8,$EVADE:4` |
| Scanner with attack payload | `$UWA:8,$SQL:4` or `$UWA:8,$XSS:4` |

## 4.6 Score Checklist

- [ ] Every generated rule has a score.
- [ ] Score format is `"s:$NAME:VALUE"`.
- [ ] Use comma-separated scores for multi-category payloads.
- [ ] Define matching `CheckRule` for every score family.
- [ ] Do not create unused score variables unless the configuration also defines a `CheckRule`.
- [ ] Prefer standard score names when possible: `$SQL`, `$XSS`, `$RFI`, `$TRAVERSAL`, `$UPLOAD`, `$UWA`, `$EVADE`.

---

# 5. Search Parameter

## 5.1 Search Parameter Definition

Each rule must define a search parameter.

A search parameter can be:

| Search type | Format | Meaning |
|---|---|---|
| String | `"str:<string>"` | Case-insensitive literal string search. |
| Regex | `"rx:<regex>"` | Case-insensitive multiline PCRE regex search. |

## 5.2 String Search with `str:`

String search format:

```nginx
"str:<string>"
```

Example:

```nginx
"str:malicious"
```

Source example:

```nginx
MainRule id:12345 "s:$FOO:8,$BAR:4" "str:malicious" "mz:URL" "msg:string rule description";
```

## 5.3 String Matching Is Case-Insensitive

Naxsi strings are always case-insensitive.

Example:

```nginx
"str:foo"
```

matches:

```text
foo
FoO
FOO
```

## 5.4 String Search Generation Use

Use `str:` when:

- the payload indicator is stable
- the target literal is short and meaningful
- regex is unnecessary
- you want simpler, safer matching
- the string should be matched case-insensitively

Examples:

```nginx
BasicRule id:500400 "s:$UWA:8" "str:nmap" "mz:$HEADERS_VAR:User-Agent" "msg:nmap scanner user-agent";
```

```nginx
BasicRule id:500401 "s:$SQL:8" "str:union select" "mz:ARGS|BODY" "msg:SQLi union select literal";
```

## 5.5 Regex Search with `rx:`

Regex search format:

```nginx
"rx:<regex>"
```

Source example:

```nginx
BasicRule id:67890 "s:$TOO:4" "rx:[a-z]{5}" "mz:ARGS" "msg:regex rule description";
```

## 5.6 Regex Matching Is Case-Insensitive and Multiline

Naxsi regexes are always:

```text
case-insensitive
multiline
```

Example:

```nginx
"rx:[a-z]+"
```

matches:

```text
foo
FoO
FOO
```

Because regexes are case-insensitive by default, do not add unnecessary case variants.

## 5.7 Regex Format

Naxsi regexes follow the PCRE format.

Generation implications:

- Use PCRE-compatible syntax.
- Escape characters when NGINX config parsing requires it.
- Keep regexes as simple as possible.
- Avoid catastrophic backtracking patterns.
- Prefer anchored or scoped matchzones when possible.
- Test NGINX config after writing regexes.

Validation command:

```bash
nginx -t
```

## 5.8 NGINX Escaping Warning

Regular expressions may require escaping because NGINX parses configuration files before the regex is passed to Naxsi.

Common escaping concerns:

| Character or sequence | Reason to review |
|---|---|
| `\` | NGINX and regex escaping may interact. |
| `"` | The regex is inside quoted config strings. |
| `$` | NGINX variable parsing may treat it specially. |
| `{}` | Regex quantifiers should remain valid. |
| `;` | Ends NGINX directives; keep inside quotes. |

Example with escaped backslash for digit class:

```nginx
BasicRule id:500402 "s:$SQL:8" "rx:[^\d]+" "mz:$ARGS_VAR:id" "msg:non-digit id value";
```

Depending on deployment and parser behavior, additional escaping may be required. Always test with:

```bash
nginx -t
```

## 5.9 Search Parameter Selection Matrix

| Payload pattern | Recommended search parameter |
|---|---|
| Stable literal like `nmap` | `str:nmap` |
| Stable literal like `union select` | `str:union select` |
| Flexible SQLi such as `union ... select` | `rx:union\s+select` |
| Boolean SQLi such as `or 1=1` | `rx:or\s+1\s*=\s*1` |
| XSS event handler | `rx:on[a-z]+\s*=` |
| Script tag | `rx:<\s*script\b` |
| Traversal | `rx:\.\./|\.\.\\` |
| Null-byte evasion | `rx:%00|\\x00|0x00` |
| Scanner User-Agent | `str:nmap` or `rx:sqlmap|nikto|nmap` |

## 5.10 Search Parameter Checklist

- [ ] Use exactly one search parameter per rule.
- [ ] Use `str:` for stable literal indicators.
- [ ] Use `rx:` for flexible patterns.
- [ ] Remember strings are case-insensitive.
- [ ] Remember regexes are case-insensitive and multiline.
- [ ] Write search patterns against decoded payload content.
- [ ] Escape regex syntax as needed for NGINX config parsing.
- [ ] Validate with `nginx -t`.

---

# 6. Decoding and Canonicalization

## 6.1 Important Naxsi Decoding Behavior

Naxsi decodes:

```text
url-encoded sequences
hexadecimal sequences
```

before matching.

This applies to:

```text
URLs
request data inspected by rules
```

## 6.2 Rule-Generation Meaning

The string or regex in a Naxsi rule should search for the decoded content, not the encoded input form.

Example encoded input:

```text
1%20UnioN%20SeLEct%201
```

Naxsi decodes it to:

```text
1 UnioN SeLEct 1
```

This decoded value matches:

```nginx
"str:union select"
```

and:

```nginx
"rx:union|select"
```

## 6.3 Do Not Match Only the Encoded Form

Less useful:

```nginx
BasicRule id:500500 "s:$SQL:8" "str:%20union%20select" "mz:ARGS" "msg:encoded SQLi";
```

Better:

```nginx
BasicRule id:500501 "s:$SQL:8" "str:union select" "mz:ARGS" "msg:decoded SQLi union select";
```

or:

```nginx
BasicRule id:500502 "s:$SQL:8" "rx:union\s+select" "mz:ARGS" "msg:decoded SQLi union select";
```

## 6.4 Case Randomization Bypass

Because string and regex matching are case-insensitive, Naxsi rules do not need explicit case variants for payloads such as:

```text
UnioN SeLEct
UNION SELECT
union select
```

A single string rule is enough:

```nginx
BasicRule id:500503 "s:$SQL:8" "str:union select" "mz:ARGS" "msg:SQLi union select";
```

## 6.5 URL-Decoding Examples for Retrieval

| Raw payload | Decoded content | Good Naxsi search |
|---|---|---|
| `1%20UnioN%20SeLEct%201` | `1 UnioN SeLEct 1` | `"str:union select"` |
| `%3Cscript%3Ealert(1)%3C/script%3E` | `<script>alert(1)</script>` | `"rx:<\s*script\b"` |
| `%2e%2e%2fetc%2fpasswd` | `../etc/passwd` | `"rx:\.\./|/etc/passwd"` |
| `%00` | null byte / decoded null indicator | internal rule or `"rx:%00|\\x00|0x00"` if raw evidence is needed |
| `or%201%3D1` | `or 1=1` | `"rx:or\s+1\s*=\s*1"` |

## 6.6 Decoding Checklist

- [ ] Write search patterns for decoded payloads.
- [ ] Do not rely only on raw percent-encoded tokens.
- [ ] Use `str:` for decoded literal tokens.
- [ ] Use `rx:` for flexible decoded patterns.
- [ ] Remember URL matching is also against decoded content.
- [ ] Still include evasion rules for raw indicators when operational logs show that raw tokens survive into inspected zones.

---

# 7. Matchzone

## 7.1 Matchzone Definition

A matchzone defines where the search parameter is applied for each rule.

Format:

```nginx
"mz:<MATCHZONE>"
```

The source document refers to the Matchzones chapter for full matchzone syntax.

This document includes practical matchzone usage patterns for generation.

## 7.2 Common Matchzones

| Matchzone | Meaning | Best use |
|---|---|---|
| `URL` | URL / URI zone | URI path and URL-based payloads. |
| `ARGS` | Request arguments | Query or form parameter payloads. |
| `BODY` | Request body | Body payloads, JSON/form data depending on parsing. |
| `HEADERS` | Request headers | General header payloads. |
| `$HEADERS_VAR:User-Agent` | Specific User-Agent header | Scanner, bot, or header-based payloads. |
| `$ARGS_VAR:id` | Specific argument named `id` | Parameter-specific virtual patch. |
| `$BODY_VAR:name` | Specific body variable | Body parameter tuning or matching. |
| `$URL:/path` | Specific URL path scope | Endpoint-specific virtual patch or whitelist. |

## 7.3 Matchzone Selection Matrix

| Observed payload location | Recommended matchzone |
|---|---|
| Any query or form argument | `ARGS` |
| Specific argument `id` | `$ARGS_VAR:id` |
| Request body | `BODY` |
| Specific body variable | `$BODY_VAR:<name>` |
| URL path | `URL` |
| Specific endpoint | `$URL:/specific/path` |
| User-Agent header | `$HEADERS_VAR:User-Agent` |
| Any request header | `HEADERS` |
| Endpoint + parameter | `$URL:/path|$ARGS_VAR:param` |

## 7.4 Endpoint-Specific Virtual Patch

Example: only `/vuln_page.php` with parameter `id` is vulnerable.

```nginx
BasicRule id:500600 "s:$SQL:8" "rx:[^\d]+" "mz:$URL:/vuln_page.php|$ARGS_VAR:id" "msg:virtual patch for numeric id SQLi";
```

Meaning:

- Apply only to `/vuln_page.php`.
- Inspect only argument `id`.
- Match non-digit content.
- Increment `$SQL` by `8`.

Required `CheckRule`:

```nginx
CheckRule "$SQL >= 8" BLOCK;
```

## 7.5 Header-Specific Rule

Example: detect scanner User-Agent.

```nginx
BasicRule id:500601 "s:$UWA:8" "rx:sqlmap|nikto|nmap|nuclei" "mz:$HEADERS_VAR:User-Agent" "msg:known scanner user-agent";
```

Required `CheckRule`:

```nginx
CheckRule "$UWA >= 8" BLOCK;
```

## 7.6 Matchzone Tuning Principle

Prefer the narrowest matchzone that still covers the attack.

Broad:

```nginx
"mz:ARGS|BODY|HEADERS"
```

Narrow:

```nginx
"mz:$URL:/search|$ARGS_VAR:q"
```

Use broad matchzones for generic detection. Use narrow matchzones for application-specific virtual patches or false-positive tuning.

---

# 8. Optional Description with `msg:`

## 8.1 Definition

Each rule can have an optional description using:

```text
"msg:<description>"
```

Example:

```nginx
"msg:Example of description"
```

## 8.2 Description Is Not Used by Naxsi

The source states:

```text
Descriptions are not used by Naxsi, but can be used to explain what the rule does.
```

This means `msg:` does not affect matching, scoring, blocking, or whitelisting behavior.

## 8.3 Why `msg:` Still Matters

Even though `msg:` is not used by Naxsi for enforcement, it is valuable for:

- operator understanding
- log analysis
- incident review
- rule maintenance
- false-positive tuning
- mapping generated rules to attack types
- explaining why a rule exists
- allowing retrieval/reranking to identify useful rule sections

## 8.4 Good `msg:` Examples

```nginx
"msg:custom SQLi union select indicator in request arguments"
```

```nginx
"msg:XSS script tag or event handler indicator in request input"
```

```nginx
"msg:known scanner user-agent"
```

```nginx
"msg:virtual patch for numeric id parameter on /vuln_page.php"
```

## 8.5 Weak `msg:` Examples

```nginx
"msg:bad"
```

```nginx
"msg:block"
```

```nginx
"msg:rule"
```

## 8.6 `msg:` Checklist

- [ ] Include `msg:` in generated rules.
- [ ] Mention attack category.
- [ ] Mention important payload family.
- [ ] Mention important target or endpoint if scoped.
- [ ] Keep the message concise.
- [ ] Do not rely on `msg:` for enforcement logic.

---

# 9. Complete Rule Authoring Pattern

## 9.1 Minimal Valid User-Defined Rule

A minimal user-defined rule needs:

```nginx
BasicRule id:500700 "s:$UWA:8" "str:nmap" "mz:$HEADERS_VAR:User-Agent" "msg:nmap scanner user-agent";
```

But this alone does not block unless a matching `CheckRule` exists.

## 9.2 Minimal Enforced Location-Specific Rule

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:500700 "s:$UWA:8" "str:nmap" "mz:$HEADERS_VAR:User-Agent" "msg:nmap scanner user-agent";

    CheckRule "$UWA >= 8" BLOCK;
}

location /RequestDenied {
    internal;
    return 403;
}
```

## 9.3 Global Rule with Local Enforcement

```nginx
http {
    MainRule id:500701 "s:$UWA:8" "str:nmap" "mz:$HEADERS_VAR:User-Agent" "msg:nmap scanner user-agent";

    server {
        location / {
            SecRulesEnabled;
            DeniedUrl "/RequestDenied";

            CheckRule "$UWA >= 8" BLOCK;
        }

        location /RequestDenied {
            internal;
            return 403;
        }
    }
}
```

## 9.4 Full Rule-Generation Template

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:<ID> "s:$<SCORE>:<POINTS>" "<str:... or rx:...>" "mz:<MATCHZONE>" "msg:<DESCRIPTION>";

    CheckRule "$<SCORE> >= <THRESHOLD>" BLOCK;
}

location /RequestDenied {
    internal;
    return 403;
}
```

---

# 10. SQL Injection Rule Generation

## 10.1 SQLi Rule Generation Inputs

Use this section when attack type is:

```text
SQL injection
SQLi
union select
or 1=1
sleep
benchmark
information_schema
database injection
```

## 10.2 Basic SQLi Literal Rule

Use `str:` for stable decoded strings such as `union select`.

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:500800 "s:$SQL:8" "str:union select" "mz:ARGS|BODY" "msg:SQLi union select literal";

    CheckRule "$SQL >= 8" BLOCK;
}
```

## 10.3 Flexible SQLi Regex Rule

Use `rx:` when whitespace, comments, or optional syntax may vary.

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:500801 "s:$SQL:8" "rx:union\s+select|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(" "mz:ARGS|BODY" "msg:custom SQLi indicators";

    CheckRule "$SQL >= 8" BLOCK;
}
```

## 10.4 SQLi with Evasion Score

Use multiple scores when SQLi is combined with evasion.

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:500802 "s:$SQL:8,$EVADE:4" "rx:union\s*/\*.*\*/\s*select|or\s+1\s*=\s*1" "mz:ARGS|BODY" "msg:SQLi with comment-based evasion";

    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$EVADE >= 8" BLOCK;
}
```

## 10.5 Parameter-Specific SQLi Virtual Patch

If only parameter `id` should be numeric:

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:500803 "s:$SQL:8" "rx:[^\d]+" "mz:$URL:/vuln_page.php|$ARGS_VAR:id" "msg:virtual patch for numeric id SQLi";

    CheckRule "$SQL >= 8" BLOCK;
}
```

## 10.6 SQLi Rule-Generation Notes

- Naxsi decodes URL encoding before matching, so `1%20UnioN%20SeLEct%201` should be matched by `str:union select` or `rx:union\s+select`.
- Strings and regexes are case-insensitive, so no case variants are needed.
- Use `$SQL` for SQLi score.
- Include `CheckRule "$SQL >= 8" BLOCK;`.
- Add `$EVADE` only if the pattern detects evasion techniques.
- Scope to `$ARGS_VAR:<name>` or `$URL:/path|$ARGS_VAR:<name>` when the vulnerable parameter is known.

---

# 11. XSS Rule Generation

## 11.1 XSS Rule Generation Inputs

Use this section when attack type is:

```text
XSS
cross-site scripting
script tag
onerror
onload
onclick
javascript:
HTML injection
SVG payload
IMG onerror
```

## 11.2 Basic XSS Script Tag Rule

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:510800 "s:$XSS:8" "rx:<\s*script\b" "mz:ARGS|BODY|HEADERS" "msg:XSS script tag indicator";

    CheckRule "$XSS >= 8" BLOCK;
}
```

## 11.3 XSS Event Handler and JavaScript URI Rule

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:510801 "s:$XSS:8" "rx:on[a-z]+\s*=|javascript\s*:" "mz:ARGS|BODY|HEADERS" "msg:XSS event handler or javascript URI indicator";

    CheckRule "$XSS >= 8" BLOCK;
}
```

## 11.4 XSS with Evasion Score

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:510802 "s:$XSS:8,$EVADE:4" "rx:<\s*script\b|on[a-z]+\s*=|javascript\s*:" "mz:ARGS|BODY|HEADERS" "msg:XSS indicator with possible evasion";

    CheckRule "$XSS >= 8" BLOCK;
    CheckRule "$EVADE >= 8" BLOCK;
}
```

## 11.5 Parameter-Specific XSS Virtual Patch

If only parameter `q` is vulnerable:

```nginx
location /search {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:510803 "s:$XSS:8" "rx:<\s*script\b|on[a-z]+\s*=|javascript\s*:" "mz:$URL:/search|$ARGS_VAR:q" "msg:XSS virtual patch for q parameter";

    CheckRule "$XSS >= 8" BLOCK;
}
```

## 11.6 XSS Rule-Generation Notes

- Naxsi decodes URL and hexadecimal encodings, so `%3Cscript%3E` is matched by a decoded `<script` regex.
- Strings and regexes are case-insensitive.
- Use `$XSS` for XSS score.
- Include `CheckRule "$XSS >= 8" BLOCK;`.
- Use `$EVADE` as an additional score only if the rule detects evasion or obfuscation behavior.
- Use specific matchzones for rich-text editors and CMS fields to reduce false positives.

---

# 12. Scanner and Unwanted Access Rule Generation

## 12.1 Scanner Rule Generation Inputs

Use this section when attack type or evidence includes:

```text
scanner
nmap
sqlmap
nikto
nuclei
acunetix
user-agent
unwanted access
UWA
```

## 12.2 Literal Scanner Rule

```nginx
http {
    MainRule id:550800 "s:$UWA:8" "str:nmap" "mz:$HEADERS_VAR:User-Agent" "msg:nmap in user-agent";
}
```

Required protected location:

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    CheckRule "$UWA >= 8" BLOCK;
}
```

## 12.3 Regex Scanner Rule

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:550801 "s:$UWA:8" "rx:sqlmap|nikto|acunetix|nmap|nuclei" "mz:$HEADERS_VAR:User-Agent" "msg:known scanner user-agent";

    CheckRule "$UWA >= 8" BLOCK;
}
```

## 12.4 Scanner Rule-Generation Notes

- Use `$UWA` for unwanted access and scanner detection.
- User-Agent can be spoofed; do not treat it as authentication.
- `str:nmap` is enough for a single scanner token.
- `rx:sqlmap|nikto|acunetix|nmap|nuclei` is useful for multiple scanner families.
- Use `$HEADERS_VAR:User-Agent` rather than all headers when only User-Agent is relevant.

---

# 13. Traversal and LFI Rule Generation

## 13.1 Traversal Rule Generation Inputs

Use this section when attack type or evidence includes:

```text
path traversal
directory traversal
LFI
../
..\
/etc/passwd
%2e%2e%2f
```

## 13.2 Generic Traversal Rule

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:520800 "s:$TRAVERSAL:5" "rx:\.\./|\.\.\\|/etc/passwd" "mz:URL|ARGS|BODY" "msg:path traversal or LFI indicator";

    CheckRule "$TRAVERSAL >= 5" BLOCK;
}
```

## 13.3 Parameter-Specific Traversal Virtual Patch

```nginx
location /download {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:520801 "s:$TRAVERSAL:5" "rx:\.\./|\.\.\\|/etc/passwd" "mz:$URL:/download|$ARGS_VAR:file" "msg:path traversal in file parameter";

    CheckRule "$TRAVERSAL >= 5" BLOCK;
}
```

## 13.4 Traversal Rule-Generation Notes

- Naxsi decodes URL encoding before matching, so `%2e%2e%2f` should be matched by decoded traversal regex.
- Use `$TRAVERSAL` score.
- Typical threshold is `5`.
- Scope to file/path parameters when known.
- Avoid broad false positives on applications that legitimately accept path-like input unless logs justify blocking.

---

# 14. Remote File Inclusion Rule Generation

## 14.1 RFI Rule Generation Inputs

Use this section when attack type or evidence includes:

```text
RFI
remote file inclusion
http://
https://
php://
data://
external URL parameter
```

## 14.2 Generic RFI Rule

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:530800 "s:$RFI:8" "rx:https?://|php://|data://" "mz:ARGS|BODY" "msg:remote file inclusion indicator";

    CheckRule "$RFI >= 8" BLOCK;
}
```

## 14.3 Parameter-Specific RFI Rule

```nginx
location /include {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:530801 "s:$RFI:8" "rx:https?://|php://|data://" "mz:$URL:/include|$ARGS_VAR:page" "msg:RFI in page parameter";

    CheckRule "$RFI >= 8" BLOCK;
}
```

## 14.4 RFI Rule-Generation Notes

- Use `$RFI` score.
- Typical threshold is `8`.
- Many applications legitimately accept URLs for callbacks, webhooks, or imports.
- Scope RFI rules to known vulnerable parameters when possible.
- Use `LearningMode` before enforcing broad URL-like pattern rules.

---

# 15. Upload Abuse Rule Generation

## 15.1 Upload Rule Generation Inputs

Use this section when attack type or evidence includes:

```text
upload abuse
malicious upload
web shell
.php upload
.jsp upload
.asp upload
file extension
```

## 15.2 Upload Extension Rule

```nginx
location /upload {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:540800 "s:$UPLOAD:5" "rx:\.(php|phtml|jsp|jspx|asp|aspx)$" "mz:ARGS|BODY" "msg:dangerous upload extension indicator";

    CheckRule "$UPLOAD >= 5" BLOCK;
}
```

## 15.3 Upload Rule-Generation Notes

- Use `$UPLOAD` score.
- Typical threshold is `5`.
- Confirm exact upload-related matchzones available in the deployment.
- Scope to upload endpoints.
- Avoid breaking legitimate upload workflows.
- Use logs and `LearningMode` before blocking broad upload rules.

---

# 16. Evasion Rule Generation

## 16.1 Evasion Rule Generation Inputs

Use this section when attack evidence includes:

```text
evasion
obfuscation
encoded payload
null byte
%00
hexadecimal sequence
comment obfuscation
double encoding
```

## 16.2 Generic Evasion Rule

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:560800 "s:$EVADE:8" "rx:%00|\\x00|0x00|/\*.*\*/" "mz:ARGS|BODY|URL" "msg:evasion or obfuscation indicator";

    CheckRule "$EVADE >= 8" BLOCK;
}
```

## 16.3 SQLi with Evasion Rule

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:560801 "s:$SQL:8,$EVADE:4" "rx:union\s*/\*.*\*/\s*select|or\s+1\s*=\s*1" "mz:ARGS|BODY" "msg:SQLi with comment evasion";

    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$EVADE >= 8" BLOCK;
}
```

## 16.4 Evasion Rule-Generation Notes

- Use `$EVADE` for generic evasion signals.
- Use multi-score rules when evasion is tied to SQLi, XSS, traversal, or upload payloads.
- Naxsi already decodes URL and hexadecimal sequences before matching, so write main attack patterns against decoded content.
- Use raw evasion indicators only when they are useful as independent suspicious signals.

---

# 17. Whitelist Rule Generation

## 17.1 Whitelist Relationship to Rule IDs

Rule IDs are used for whitelisting. This is one reason duplicate IDs are not recommended.

Global whitelist with `MainRule`:

```nginx
MainRule wl:<RULE_ID> "mz:<MATCHZONE>";
```

Location-specific whitelist with `BasicRule`:

```nginx
BasicRule wl:<RULE_ID> "mz:<MATCHZONE>";
```

## 17.2 Location-Specific Whitelist Example

```nginx
location /search {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule wl:500803 "mz:$URL:/search|$ARGS_VAR:q";

    CheckRule "$XSS >= 8" BLOCK;
}
```

## 17.3 Internal Rule Whitelist Example

Internal rule IDs can be whitelisted only when a false positive is validated.

Example: malformed JSON false positive on one legacy endpoint:

```nginx
location /api/legacy-json {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule wl:15 "mz:$URL:/api/legacy-json|BODY";

    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$XSS >= 8" BLOCK;
}
```

## 17.4 Whitelist Safety Rules

- Prefer `BasicRule` whitelists over global `MainRule` whitelists.
- Whitelist only the specific rule ID that false-positives.
- Scope the whitelist to a URL, argument, body field, or header.
- Do not reuse duplicate rule IDs across unrelated detections.
- Do not globally whitelist broad attack categories.
- Re-test malicious payloads after adding the whitelist.

---

# 18. Complete Production-Oriented Examples

## 18.1 Complete SQLi Location-Specific Rule

```nginx
load_module /etc/nginx/modules/ngx_http_naxsi_module.so;

http {
    server {
        listen 80;
        server_name example.com;

        location / {
            SecRulesEnabled;
            DeniedUrl "/RequestDenied";

            BasicRule id:500900 "s:$SQL:8" "rx:union\s+select|or\s+1\s*=\s*1|sleep\s*\(" "mz:ARGS|BODY" "msg:custom SQLi indicators";

            CheckRule "$SQL >= 8" BLOCK;
        }

        location /RequestDenied {
            internal;
            return 403;
        }
    }
}
```

## 18.2 Complete XSS Location-Specific Rule

```nginx
load_module /etc/nginx/modules/ngx_http_naxsi_module.so;

http {
    server {
        listen 80;
        server_name example.com;

        location / {
            SecRulesEnabled;
            DeniedUrl "/RequestDenied";

            BasicRule id:510900 "s:$XSS:8" "rx:<\s*script\b|on[a-z]+\s*=|javascript\s*:" "mz:ARGS|BODY|HEADERS" "msg:custom XSS indicators";

            CheckRule "$XSS >= 8" BLOCK;
        }

        location /RequestDenied {
            internal;
            return 403;
        }
    }
}
```

## 18.3 Complete Scanner Global Rule

```nginx
load_module /etc/nginx/modules/ngx_http_naxsi_module.so;

http {
    MainRule id:550900 "s:$UWA:8" "rx:sqlmap|nikto|acunetix|nmap|nuclei" "mz:$HEADERS_VAR:User-Agent" "msg:known scanner user-agent";

    server {
        listen 80;
        server_name example.com;

        location / {
            SecRulesEnabled;
            DeniedUrl "/RequestDenied";

            CheckRule "$UWA >= 8" BLOCK;
        }

        location /RequestDenied {
            internal;
            return 403;
        }
    }
}
```

## 18.4 Complete LearningMode Tuning Example

```nginx
load_module /etc/nginx/modules/ngx_http_naxsi_module.so;

http {
    server {
        listen 80;
        server_name example.com;

        set $naxsi_json_log 1;

        location / {
            SecRulesEnabled;
            LearningMode;
            DeniedUrl "/RequestDenied";

            BasicRule id:500901 "s:$SQL:8" "rx:union\s+select|or\s+1\s*=\s*1" "mz:ARGS|BODY" "msg:custom SQLi indicators";
            BasicRule id:510901 "s:$XSS:8" "rx:<\s*script\b|on[a-z]+\s*=" "mz:ARGS|BODY|HEADERS" "msg:custom XSS indicators";

            CheckRule "$SQL >= 8" BLOCK;
            CheckRule "$XSS >= 8" BLOCK;
        }

        location /RequestDenied {
            internal;
            return 403;
        }
    }
}
```

---

# 19. False Positives and Tuning

## 19.1 General False-Positive Strategy

A Naxsi rule false positive should usually be tuned by:

1. checking the rule ID
2. checking the score
3. checking the matchzone
4. checking URL, parameter, body field, or header
5. creating a narrow `BasicRule wl:<id>` whitelist
6. re-testing malicious payloads

## 19.2 SQLi False-Positive Sources

SQLi rules can false positive on:

- SQL training pages
- database admin tools
- search boxes
- documentation pages
- logs containing SQL statements
- JSON fields containing query text

Tuning example:

```nginx
BasicRule wl:500801 "mz:$URL:/docs/sql|$ARGS_VAR:q";
```

## 19.3 XSS False-Positive Sources

XSS rules can false positive on:

- CMS editors
- rich text fields
- documentation pages
- code examples
- frontend template fields
- HTML email editors

Tuning example:

```nginx
BasicRule wl:510801 "mz:$URL:/admin/editor|$ARGS_VAR:html";
```

## 19.4 Scanner Rule False Positives

Scanner User-Agent rules may false positive if internal tools use scanner-like tokens.

Tuning example:

```nginx
BasicRule wl:550801 "mz:$URL:/internal/health|$HEADERS_VAR:User-Agent";
```

## 19.5 Tuning Checklist

- [ ] Avoid broad `MainRule wl:<id>` unless the exception is truly global.
- [ ] Prefer `BasicRule wl:<id>` inside the affected `location`.
- [ ] Scope by URL and variable when possible.
- [ ] Avoid duplicate IDs so whitelists do not unintentionally suppress multiple rules.
- [ ] Test malicious examples after whitelisting.
- [ ] Use `LearningMode` and JSON logs during initial rollout.

---

# 20. RAG Retrieval Keywords

## 20.1 Naxsi Rule Syntax Keywords

```text
Naxsi Rules
Naxsi rule
search pattern
malicious behaviour
MainRule
BasicRule
rule id
id:<number>
score
s:$FOO:8
search parameter
str:
rx:
matchzone
mz:
optional description
msg:
CheckRule counter
```

## 20.2 Rule ID Keywords

```text
positive integer greater than 999
reserved ids 1 to 1000
internal rules
duplicate rule ids not suggested
logging
whitelisting
wl:
```

## 20.3 Score Keywords

```text
score
s:$SQL:8
s:$XSS:8
s:$RFI:8
s:$TRAVERSAL:5
s:$UPLOAD:5
s:$UWA:8
s:$EVADE:8
multiple scores
CheckRule
counter
rule never trigger action
```

## 20.4 Search Parameter Keywords

```text
str:string
rx:regex
case insensitive string
case insensitive regex
multiline regex
PCRE
nginx escaping
url-encoded
hexadecimal sequence
decoded content
union select
regex union select
```

## 20.5 Matchzone Keywords

```text
matchzone
mz:URL
mz:ARGS
mz:BODY
mz:HEADERS
$ARGS_VAR
$BODY_VAR
$HEADERS_VAR
$URL
User-Agent
```

## 20.6 Attack Keywords

```text
SQL injection
SQLi
union select
or 1=1
sleep
benchmark
XSS
cross-site scripting
script tag
onerror
onload
javascript
path traversal
LFI
RFI
upload abuse
scanner user-agent
nmap
sqlmap
evasion
obfuscation
```

---

# 21. Output Template for LLM Rule Generation

When this document is retrieved, generate output in this structure:

```markdown
## Rule Objective

- WAF: Naxsi
- Attack type:
- Payload evidence:
- Payload location:
- Desired action:
- Scope: global or location-specific

## Proposed Naxsi Rule

```nginx
BasicRule id:<ID> "s:$<SCORE>:<POINTS>" "<str:... or rx:...>" "mz:<MATCHZONE>" "msg:<DESCRIPTION>";
CheckRule "$<SCORE> >= <THRESHOLD>" BLOCK;
```

## Why This Rule Works

Explain:
- why `MainRule` or `BasicRule` was selected
- why the ID is valid
- what score is incremented
- why the search parameter uses `str:` or `rx:`
- how Naxsi decoding affects the match
- why the matchzone is correct
- why a matching `CheckRule` is required

## False Positives and Tuning

Explain:
- likely false positives
- whether `LearningMode` should be used
- how to write a narrow `BasicRule wl:<id>` whitelist
- why duplicate IDs should be avoided
```

---

# 22. Common Mistakes and Corrections

## 22.1 Mistake: Custom Rule ID Too Low

Incorrect:

```nginx
BasicRule id:900 "s:$SQL:8" "str:union select" "mz:ARGS" "msg:SQLi";
```

Correct:

```nginx
BasicRule id:500900 "s:$SQL:8" "str:union select" "mz:ARGS" "msg:SQLi";
```

## 22.2 Mistake: Rule Without CheckRule

Incorrect:

```nginx
location / {
    SecRulesEnabled;
    BasicRule id:500901 "s:$SQL:8" "str:union select" "mz:ARGS" "msg:SQLi";
}
```

Correct:

```nginx
location / {
    SecRulesEnabled;
    BasicRule id:500901 "s:$SQL:8" "str:union select" "mz:ARGS" "msg:SQLi";
    CheckRule "$SQL >= 8" BLOCK;
}
```

## 22.3 Mistake: Matching Encoded Payload Instead of Decoded Content

Less useful:

```nginx
BasicRule id:500902 "s:$SQL:8" "str:%20union%20select" "mz:ARGS" "msg:encoded SQLi";
```

Better:

```nginx
BasicRule id:500902 "s:$SQL:8" "str:union select" "mz:ARGS" "msg:decoded SQLi";
```

## 22.4 Mistake: Duplicate Rule IDs

Risky:

```nginx
BasicRule id:500903 "s:$SQL:8" "str:union select" "mz:ARGS" "msg:SQLi";
BasicRule id:500903 "s:$XSS:8" "rx:<script" "mz:ARGS" "msg:XSS";
```

Better:

```nginx
BasicRule id:500903 "s:$SQL:8" "str:union select" "mz:ARGS" "msg:SQLi";
BasicRule id:510903 "s:$XSS:8" "rx:<script" "mz:ARGS" "msg:XSS";
```

## 22.5 Mistake: Regex When String Is Enough

Overcomplicated:

```nginx
BasicRule id:550904 "s:$UWA:8" "rx:n[mM][aA][pP]" "mz:$HEADERS_VAR:User-Agent" "msg:nmap";
```

Better:

```nginx
BasicRule id:550904 "s:$UWA:8" "str:nmap" "mz:$HEADERS_VAR:User-Agent" "msg:nmap";
```

Reason:

```text
Naxsi string matching is already case-insensitive.
```

## 22.6 Mistake: Broad Matchzone for Specific Virtual Patch

Broad:

```nginx
BasicRule id:500905 "s:$SQL:8" "rx:[^\d]+" "mz:ARGS" "msg:numeric id";
```

Better:

```nginx
BasicRule id:500905 "s:$SQL:8" "rx:[^\d]+" "mz:$URL:/vuln_page.php|$ARGS_VAR:id" "msg:numeric id virtual patch";
```

---

# 23. Final Checklist for Naxsi Rule-Aware Generation

- [ ] Use `MainRule` for global rules.
- [ ] Use `BasicRule` for location-specific rules.
- [ ] Include a valid custom rule ID greater than `1000`.
- [ ] Avoid duplicate rule IDs.
- [ ] Use `"s:$SCORE:VALUE"` score format.
- [ ] Use multiple comma-separated scores when needed.
- [ ] Include matching `CheckRule` for every score used.
- [ ] Use `"str:<string>"` for stable literal indicators.
- [ ] Use `"rx:<regex>"` for flexible PCRE patterns.
- [ ] Remember strings are case-insensitive.
- [ ] Remember regexes are case-insensitive and multiline.
- [ ] Write search patterns against decoded content.
- [ ] Do not match only URL-encoded payloads when decoded pattern is more appropriate.
- [ ] Use `"mz:<MATCHZONE>"`.
- [ ] Scope matchzone narrowly for virtual patches.
- [ ] Include useful `"msg:<description>"`.
- [ ] Prefer `BasicRule wl:<id>` for false-positive tuning.
- [ ] Validate generated configuration with `nginx -t`.
