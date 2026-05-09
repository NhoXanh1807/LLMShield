# Naxsi Internal Rules Knowledge Base for RAG and WAF Rule Generation
# 1. Naxsi Internal Rules Overview
## 1.1 Definition

Naxsi has internal rules that are hardcoded inside the WAF engine. These internal rules are identified by rule IDs lower than:

```text
1000
```

Internal rules are not ordinary user-defined `MainRule` or `BasicRule` rules. They are built into Naxsi and detect parser-level, protocol-level, request-format, body-format, and libinjection-related conditions.

## 1.2 Critical ID Constraint

> **Warning:** No user-defined Naxsi rule should be defined with an ID lower than `1000`.

Reserved range:

```text
1-999
```

Safe custom rule ID range:

```text
1000 and above
```

Recommended custom ID strategy:

```text
500000-599999 for project-specific generated rules
```

Example valid custom rule:

```nginx
BasicRule id:500100 "s:$XSS:8" "rx:<\s*script|onerror\s*=" "mz:ARGS|BODY|HEADERS" "msg:custom XSS indicators";
```

Example invalid custom rule:

```nginx
BasicRule id:17 "s:$SQL:8" "rx:union\s+select" "mz:ARGS" "msg:invalid custom SQLi rule";
```

Reason:

```text
Rule ID 17 is reserved for Naxsi internal libinjection SQLi.
```

## 1.3 Internal Blocking Rules Can Be Whitelisted

Naxsi internal blocking rules can be whitelisted.

This means a false positive from an internal rule can be handled by a `MainRule` or `BasicRule` whitelist that references the internal rule ID.

Example location-specific whitelist:

```nginx
BasicRule wl:11 "mz:$URL:/api/upload|$HEADERS_VAR:Content-Type";
```

Use this only when:

- the internal rule hit is proven to be a false positive
- the exception is scoped narrowly by URL, parameter, header, or body variable
- malicious payloads are still blocked elsewhere
- logs confirm that the whitelist does not create a broad bypass

## 1.4 Internal Rules and LearningMode

`LearningMode` makes normal `BLOCK` `CheckRule` actions behave like `LOG`, but internal rules are special.

Important operational guidance:

- Internal rules with IDs below `1000` may still block or drop requests even when `LearningMode` is enabled.
- Internal parser/protocol rules often indicate malformed or abnormal traffic.
- Do not assume `LearningMode` prevents every block.
- Use internal rule whitelisting only after validating the false positive.

## 1.5 Internal Rules Categories

| Category | Rule IDs | Typical effect |
|---|---:|---|
| Request parser failures | `1`, `12` | `BLOCK` |
| Request/body size or mismatch | `2` | `BLOCK` |
| Encoded null bytes | `10` | `BLOCK` |
| Content-Type problems | `11` | `BLOCK` |
| Multipart/Form POST format problems | `13`, `14` | `BLOCK` |
| JSON parsing problems | `15` | `BLOCK` |
| Empty POST body | `16` | `BLOCK` |
| Libinjection SQLi/XSS detections | `17`, `18` | increment scores, not direct block |
| No rules loaded | `19` | `DROP` |
| Malformed UTF-8 | `20` | `DROP` |
| Illegal Host header IP | `21` | `DROP` |

---

# 2. Internal Rule Inventory Table

| Internal rule ID | Name | Direct action or score | Main meaning | Rule-generation use |
|---:|---|---|---|---|
| `1` | Weird Request | `BLOCK` | Request failed to be parsed by Naxsi. Deprecated. | Explain abnormal parser failure; avoid generating custom rule ID `1`. |
| `2` | Big Request | `BLOCK` | Request too large to parse, temporary file creation, or content-size mismatch. | Tune NGINX/body limits or whitelist only a narrow upload endpoint if safe. |
| `10` | Null-Byte Hex Encoding | `BLOCK` | Request contains hex encoded null bytes such as `0x00` or `\x00`. | Treat as evasion or payload obfuscation; whitelist only with extreme caution. |
| `11` | Uncommon Content Type | `BLOCK` | Missing or unsupported `Content-Type` on POST or body-bearing requests. | Fix clients or whitelist specific API endpoints/content types if intentional. |
| `12` | Invalid formatted URL | `BLOCK` | HTTP request contains an invalid URL. | Treat as malformed request; often should remain blocked. |
| `13` | Malformed POST Format | `BLOCK` | Multipart or POST body has malformed structure. | Fix client multipart/body formatting; narrow whitelist only if application intentionally accepts unusual bodies. |
| `14` | Malformed POST Boundary | `BLOCK` | Multipart boundary is malformed. | Fix client boundary generation; avoid broad whitelist. |
| `15` | Malformed JSON | `BLOCK` | JSON body is malformed. | Fix client JSON; tune only for endpoints that intentionally accept non-standard JSON-like data. |
| `16` | Empty POST Body | `BLOCK` | POST request contains an empty body. | Fix method/body usage; whitelist only for endpoints where empty POST is legitimate. |
| `17` | libinjection SQLi | increments `$LIBINJECTION_SQL` by `1` | libinjection detected SQL injection. | Requires `LibInjectionSql` and `CheckRule "$LIBINJECTION_SQL >= ..."` for enforcement. |
| `18` | libinjection XSS | increments `$LIBINJECTION_XSS` by `1` | libinjection detected XSS. | Requires `LibInjectionXss` and `CheckRule "$LIBINJECTION_XSS >= ..."` for enforcement. |
| `19` | No Rules Loaded | `DROP` | WAF is enabled but no global or location-specific rules are loaded. | Fix configuration by including rules or adding at least one `MainRule`/`BasicRule`. |
| `20` | Malformed UTF-8 | `DROP` | Request contains malformed UTF-8. | Treat as protocol/body encoding abuse; whitelist only if binary/non-UTF8 endpoint is expected and safe. |
| `21` | Illegal Host in Header | `DROP` | Host header contains an illegal IP range. | Keep blocked; fix clients/proxies sending illegal Host values. |

---

# 3. Rule ID Policy for Generated Naxsi Rules

## 3.1 Custom Rule ID Requirement

All generated Naxsi custom rules must use IDs greater than or equal to `1000`.

Correct:

```nginx
BasicRule id:500201 "s:$SQL:8" "rx:union\s+select|or\s+1\s*=\s*1" "mz:ARGS|BODY" "msg:custom SQLi indicators";
```

Incorrect:

```nginx
BasicRule id:21 "s:$SQL:8" "rx:union\s+select" "mz:ARGS" "msg:bad rule id";
```

Reason:

```text
ID 21 belongs to the internal Illegal Host in Header rule.
```

## 3.2 Rule ID Generation Checklist

- [ ] Never generate `id:1` through `id:999` for custom rules.
- [ ] Prefer a project-specific high range, such as `id:500000+`.
- [ ] Use unique IDs for generated rules.
- [ ] Use internal IDs only in whitelist directives, never as custom rule IDs.
- [ ] When whitelisting an internal rule, use `wl:<internal_id>`.
- [ ] Document why an internal rule is whitelisted.

## 3.3 Valid Use of Internal Rule IDs in Whitelists

Internal rule ID used as whitelist target:

```nginx
BasicRule wl:15 "mz:$URL:/api/legacy-json|BODY";
```

This means:

- Whitelist internal rule `15`.
- Apply only for URL `/api/legacy-json` and body match zone.
- Do not disable rule `15` globally.

Global whitelist example, use only with strong justification:

```nginx
MainRule wl:15 "mz:$URL:/api/legacy-json|BODY";
```

Risky broad whitelist:

```nginx
MainRule wl:15;
```

Reason it is risky:

```text
It can suppress malformed JSON protection across the entire application.
```

---

# 4. Internal Rule 1 - Weird Request

## 4.1 Rule Identity

```text
Number: 1
Name: Weird Request
Action: BLOCK
Status: Deprecated
```

## 4.2 Meaning

Internal rule `1` refers to a request that contains a weird request which failed to be parsed by Naxsi.

This is a parser-level abnormal request condition.

## 4.3 Rule-Generation Use

Use this internal rule knowledge when:

- logs show internal rule ID `1`
- request parsing failed
- the request is not a normal HTTP request
- the user asks why Naxsi blocked a malformed request
- the generation target is false-positive tuning, not custom attack signature creation

## 4.4 Recommended Response for Rule 1 Hits

Preferred action:

```text
Investigate malformed request format and client behavior before whitelisting.
```

Possible tuning only if safe:

```nginx
BasicRule wl:1 "mz:$URL:/specific-endpoint";
```

Use with caution because parser-level failures can indicate malicious traffic, broken clients, scanners, or protocol smuggling attempts.

## 4.5 Do Not Generate Custom Rule ID 1

Incorrect:

```nginx
BasicRule id:1 "s:$EVADE:8" "rx:bad" "mz:URL" "msg:invalid";
```

Correct:

```nginx
BasicRule id:500001 "s:$EVADE:8" "rx:bad" "mz:URL" "msg:custom evasion rule";
```

---

# 5. Internal Rule 2 - Big Request

## 5.1 Rule Identity

```text
Number: 2
Name: Big Request
Action: BLOCK
```

## 5.2 Meaning

Internal rule `2` refers to a request that is too big to be parsed.

This happens when:

- NGINX has to create a temporary file on the filesystem
- content size mismatches the actual body size
- request body handling exceeds Naxsi parsing expectations

## 5.3 Security Interpretation

A big request can be:

- legitimate large upload
- accidental client error
- oversized JSON or form request
- body-size mismatch
- body parsing evasion attempt
- denial-of-service probing

## 5.4 Rule-Generation Use

When internal rule `2` appears:

- do not generate a generic attack-blocking rule first
- inspect application body size requirements
- check upload endpoints
- check NGINX body buffering and maximum body size settings
- consider endpoint-specific whitelist only after validation

## 5.5 Narrow Whitelist Example

For a known upload endpoint:

```nginx
BasicRule wl:2 "mz:$URL:/api/upload|BODY";
```

Better operational approach:

```text
Tune NGINX upload/body limits and Naxsi body parsing settings before whitelisting.
```

## 5.6 False Positive Checklist for Rule 2

- [ ] Is the endpoint expected to accept large file uploads?
- [ ] Is `client_max_body_size` appropriate?
- [ ] Are temporary files expected for this request?
- [ ] Is the `Content-Length` correct?
- [ ] Is the body truncated or malformed?
- [ ] Can the whitelist be scoped to a single URL and body zone?

---

# 6. Internal Rule 10 - Hex Encoded Null-Bytes

## 6.1 Rule Identity

```text
Number: 10
Name: Null-Byte Hex Encoding
Action: BLOCK
```

## 6.2 Meaning

Internal rule `10` refers to a request that contains one or many hex encoded null bytes.

Examples:

```text
0x00
\x00
%00
```

## 6.3 Security Interpretation

Null bytes are commonly associated with:

- parser confusion
- string termination tricks
- path traversal bypasses
- upload bypasses
- binary payloads sent into text fields
- protocol evasion

## 6.4 Rule-Generation Use

If observed payloads contain `%00`, `0x00`, or `\x00`, retrieve this section for:

- Naxsi null-byte internal blocking explanation
- evasion scoring guidance
- why broad whitelisting is dangerous
- why internal rule `10` is high-confidence

## 6.5 Custom Evasion Rule Example

If a custom user-defined Naxsi rule is needed in addition to the internal rule:

```nginx
BasicRule id:500010 "s:$EVADE:8" "rx:%00|\\x00|0x00" "mz:ARGS|BODY|URL" "msg:null byte evasion indicator";
```

CheckRule:

```nginx
CheckRule "$EVADE >= 8" BLOCK;
```

## 6.6 Whitelist Caution

Avoid broad whitelist:

```nginx
MainRule wl:10;
```

Prefer no whitelist unless there is a validated binary or legacy endpoint.

Narrow example only when absolutely justified:

```nginx
BasicRule wl:10 "mz:$URL:/api/binary-ingest|BODY";
```

---

# 7. Internal Rule 11 - Uncommon Content Type

## 7.1 Rule Identity

```text
Number: 11
Name: Uncommon Content Type
Action: BLOCK
```

## 7.2 Meaning

Internal rule `11` refers to a request that contains an uncommon content type.

This happens when:

- the `Content-Type` header is missing, or
- during a POST request, `Content-Type` is not one of the supported types.

Supported content types listed in the source:

```text
application/x-www-form-urlencoded
multipart/form-data
application/json
application/vnd.api+json
application/csp-report
```

## 7.3 Common Causes

Internal rule `11` may trigger when:

- API clients send POST requests without `Content-Type`
- clients use `text/plain`
- clients use vendor-specific JSON content types not in the accepted list
- webhook providers send unusual content types
- legacy clients send malformed or missing headers
- attackers intentionally omit or modify `Content-Type`

## 7.4 Rule-Generation Use

When this rule is retrieved, generated output should:

- explain that the problem is content-type validation
- recommend fixing the client header when possible
- recommend a narrow whitelist only for specific endpoints and content types
- avoid disabling all content-type checks globally

## 7.5 Narrow Whitelist Example

For a specific endpoint that legitimately accepts unusual content type:

```nginx
BasicRule wl:11 "mz:$URL:/api/webhook|$HEADERS_VAR:Content-Type";
```

## 7.6 Safer Configuration Guidance

Before whitelisting, prefer client fix:

```http
Content-Type: application/json
```

or:

```http
Content-Type: application/x-www-form-urlencoded
```

## 7.7 False Positive Checklist

- [ ] Is this a `POST`, `PUT`, or `PATCH` request?
- [ ] Is `Content-Type` missing?
- [ ] Is the client using a custom vendor media type?
- [ ] Can the client be fixed?
- [ ] Can the exception be scoped to one URL?
- [ ] Does whitelisting still allow Naxsi to inspect body payloads?

---

# 8. Internal Rule 12 - Invalid Formatted URL

## 8.1 Rule Identity

```text
Number: 12
Name: Invalid formatted URL
Action: BLOCK
```

## 8.2 Meaning

Internal rule `12` refers to a request that contains a badly formatted URL.

The source notes that NGINX may catch this earlier and return:

```text
400
```

## 8.3 Security Interpretation

Invalid URL format can indicate:

- broken clients
- scanners
- malformed fuzzing inputs
- invalid encoding
- request smuggling attempts
- bypass attempts against URL parsers

## 8.4 Rule-Generation Use

When logs show rule `12`, generated guidance should:

- explain that the URL is malformed before normal rule matching
- avoid writing a custom pattern rule as the first response
- recommend validating client URL construction
- recommend `nginx -t` only for configuration validation, not request-level URL validation
- whitelist only if a legacy client is confirmed and the scope is narrow

## 8.5 Whitelist Example

Use only after confirming a safe legacy pattern:

```nginx
BasicRule wl:12 "mz:$URL:/legacy-endpoint";
```

## 8.6 Tuning Caution

Do not globally whitelist invalid URL handling because it can weaken protection against parser confusion.

---

# 9. Internal Rule 13 - Malformed POST Format

## 9.1 Rule Identity

```text
Number: 13
Name: Malformed POST Format
Action: BLOCK
```

## 9.2 Meaning

Internal rule `13` refers to a malformed POST body.

Examples from the source include:

- missing `content-disposition`
- malformed boundary line
- missing name
- missing `Content-Type`
- other malformed POST structure

## 9.3 Security Interpretation

Malformed POST bodies can be associated with:

- broken multipart clients
- malformed form submissions
- upload parser bypass attempts
- body parsing confusion
- fuzzing and automated attacks

## 9.4 Rule-Generation Use

When this rule is retrieved, generated output should recommend:

- validating client multipart/form submission
- checking `Content-Type` and boundary format
- checking file upload clients
- avoiding broad whitelists
- scoping any whitelist to one URL and body zone

## 9.5 Whitelist Example

```nginx
BasicRule wl:13 "mz:$URL:/api/upload|BODY";
```

Use only when:

- the upload endpoint is known safe
- the malformed format is expected
- logs confirm exact false positive behavior
- malicious multipart payloads are still blocked by other rules

## 9.6 Related Rule

Internal rule `14` handles malformed POST boundary specifically.

---

# 10. Internal Rule 14 - Malformed POST Boundary

## 10.1 Rule Identity

```text
Number: 14
Name: Malformed POST Boundary
Action: BLOCK
```

## 10.2 Meaning

Internal rule `14` refers to a malformed POST boundary.

This primarily affects multipart form data.

## 10.3 Common Causes

- client generated invalid multipart boundary
- request body was truncated
- proxy or client corrupted multipart data
- attacker fuzzed multipart parsers
- file upload body does not match declared boundary

## 10.4 Rule-Generation Use

For rule `14` hits:

- explain that Naxsi could not parse multipart boundaries correctly
- recommend client/proxy fix first
- tune only a specific upload endpoint if required
- do not globally whitelist malformed multipart handling

## 10.5 Whitelist Example

```nginx
BasicRule wl:14 "mz:$URL:/upload|BODY";
```

## 10.6 Upload Security Warning

File upload endpoints are high risk. Whitelisting malformed boundary checks can weaken upload abuse protection.

Prefer:

- fixing the client
- validating file upload behavior
- using `LearningMode` and logs during tuning
- keeping `$UPLOAD` and `$EVADE` `CheckRule` active

---

# 11. Internal Rule 15 - Malformed JSON

## 11.1 Rule Identity

```text
Number: 15
Name: Malformed JSON
Action: BLOCK
```

## 11.2 Meaning

Internal rule `15` refers to a request that contains malformed JSON.

## 11.3 Common Causes

- invalid JSON syntax
- trailing commas where not supported
- missing quotes
- incorrect escaping
- truncated request body
- invalid character encoding
- `Content-Type: application/json` with non-JSON body
- attackers sending JSON parser confusion payloads

## 11.4 Rule-Generation Use

When observed issue is malformed JSON:

- do not generate a SQLi/XSS rule from this alone
- explain that the request failed JSON parsing
- recommend fixing client JSON generation
- use `LearningMode` and logs if tuning is needed
- whitelist only narrow legacy endpoints

## 11.5 Narrow Whitelist Example

```nginx
BasicRule wl:15 "mz:$URL:/api/legacy-json|BODY";
```

## 11.6 Safer Client Fix Example

Correct JSON:

```json
{
  "id": 123,
  "name": "example"
}
```

Malformed JSON example:

```json
{
  "id": 123,
  "name": "example",
}
```

## 11.7 False Positive Checklist

- [ ] Does the endpoint declare `Content-Type: application/json`?
- [ ] Is the body valid JSON?
- [ ] Is the body truncated?
- [ ] Does the client send JSON Lines or another non-standard format?
- [ ] Can the endpoint be changed to use an accepted content type?
- [ ] Can the exception be limited to one URL?

---

# 12. Internal Rule 16 - Empty POST Body

## 12.1 Rule Identity

```text
Number: 16
Name: Empty POST Body
Action: BLOCK
```

## 12.2 Meaning

Internal rule `16` refers to a request that contains an empty POST body.

## 12.3 Common Causes

- client sends `POST` without body
- health check uses POST incorrectly
- API endpoint expects empty body but uses POST
- request body was stripped by a proxy
- Content-Length mismatch
- automated scanner probes endpoints with empty POST

## 12.4 Rule-Generation Use

When rule `16` appears:

- explain that the issue is empty POST semantics
- recommend changing client method to `GET` when appropriate
- recommend ensuring a valid body for `POST`
- whitelist only known endpoints that intentionally accept empty POST

## 12.5 Narrow Whitelist Example

```nginx
BasicRule wl:16 "mz:$URL:/api/ping";
```

## 12.6 Safer Alternative

If endpoint is health check, prefer:

```http
GET /api/ping
```

instead of:

```http
POST /api/ping
```

with empty body.

---

# 13. Internal Rule 17 - libinjection SQLi

## 13.1 Rule Identity

```text
Number: 17
Name: libinjection SQLi
Score: $LIBINJECTION_SQL
```

## 13.2 Important Behavior

> **Warning:** Internal rule `17` does not directly block a request. It increases the score `$LIBINJECTION_SQL` by `1`.

Blocking requires a `CheckRule` for `$LIBINJECTION_SQL`.

## 13.3 Required Configuration

Enable libinjection SQLi detection:

```nginx
LibInjectionSql;
```

Define enforcement:

```nginx
CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
```

## 13.4 Why `$SQL` Is Not Enough

Core SQLi score and libinjection SQLi score are separate:

```nginx
CheckRule "$SQL >= 8" BLOCK;
```

does not enforce:

```text
$LIBINJECTION_SQL
```

You also need:

```nginx
CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
```

## 13.5 Rule-Generation Use

Use this section for:

- SQL injection attack type
- payloads such as `union select`, `or 1=1`, `sleep(`, `benchmark(`
- Naxsi libinjection SQLi configuration
- explaining why libinjection hit did not block
- generating correct `CheckRule` for `$LIBINJECTION_SQL`

## 13.6 SQLi Configuration Example

```nginx
location / {
    SecRulesEnabled;
    LibInjectionSql;
    DeniedUrl "/RequestDenied";

    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
}
```

## 13.7 Optional Custom SQLi Rule

```nginx
BasicRule id:500217 "s:$SQL:8" "rx:union\s+select|or\s+1\s*=\s*1|sleep\s*\(" "mz:ARGS|BODY" "msg:custom SQLi indicators";
```

## 13.8 Tuning Guidance

If `$LIBINJECTION_SQL` false positives occur:

- identify URL and parameter from logs
- prefer narrow whitelist by match zone
- use `LearningMode` while tuning
- do not disable libinjection globally unless absolutely necessary

Example whitelist:

```nginx
BasicRule wl:17 "mz:$URL:/sql-lab|$ARGS_VAR:query";
```

---

# 14. Internal Rule 18 - libinjection XSS

## 14.1 Rule Identity

```text
Number: 18
Name: libinjection Xss
Score: $LIBINJECTION_XSS
```

## 14.2 Important Behavior

> **Warning:** Internal rule `18` does not directly block a request. It increases the score `$LIBINJECTION_XSS` by `1`.

Blocking requires a `CheckRule` for `$LIBINJECTION_XSS`.

## 14.3 Required Configuration

Enable libinjection XSS detection:

```nginx
LibInjectionXss;
```

Define enforcement:

```nginx
CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
```

## 14.4 Why `$XSS` Is Not Enough

Core XSS score and libinjection XSS score are separate:

```nginx
CheckRule "$XSS >= 8" BLOCK;
```

does not enforce:

```text
$LIBINJECTION_XSS
```

You also need:

```nginx
CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
```

## 14.5 Rule-Generation Use

Use this section for:

- XSS attack type
- payloads containing `<script>`, `onerror=`, `onload=`, `javascript:`, SVG, IMG, iframe, HTML event handlers
- Naxsi libinjection XSS configuration
- explaining why libinjection XSS hit did not block
- generating correct `CheckRule` for `$LIBINJECTION_XSS`

## 14.6 XSS Configuration Example

```nginx
location / {
    SecRulesEnabled;
    LibInjectionXss;
    DeniedUrl "/RequestDenied";

    CheckRule "$XSS >= 8" BLOCK;
    CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
}
```

## 14.7 Optional Custom XSS Rule

```nginx
BasicRule id:500218 "s:$XSS:8" "rx:<\s*script|onerror\s*=|onload\s*=|javascript:" "mz:ARGS|BODY|HEADERS" "msg:custom XSS indicators";
```

## 14.8 Tuning Guidance

If `$LIBINJECTION_XSS` false positives occur:

- check if the endpoint legitimately accepts HTML
- prefer narrow whitelist by parameter
- avoid globally disabling XSS checks
- use `LearningMode` and JSON logs while tuning

Example whitelist:

```nginx
BasicRule wl:18 "mz:$URL:/admin/editor|$ARGS_VAR:html";
```

---

# 15. Internal Rule 19 - No Rules Loaded

## 15.1 Rule Identity

```text
Number: 19
Name: No Rules
Action: DROP
```

## 15.2 Meaning

Internal rule `19` is triggered only when the WAF is enabled but no global and no location-specific rules have been loaded at the current location.

This is a configuration error condition, not an attack signature.

## 15.3 Common Causes

- `SecRulesEnabled` is present but no `include /etc/nginx/naxsi/naxsi_core.rules;`
- no `MainRule` exists in `http` scope
- no `BasicRule` exists in the protected `location`
- rule include path is wrong
- included rule file is empty
- Naxsi is enabled before rule files are loaded
- repository rules are not installed

## 15.4 Rule-Generation Use

If the user asks why all requests are dropped or logs show rule `19`, generate configuration fix, not a custom detection rule.

## 15.5 Corrective Configuration

Include core rules:

```nginx
include /etc/nginx/naxsi/naxsi_core.rules;
```

Enable Naxsi and define CheckRules:

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$XSS >= 8" BLOCK;
}
```

Define denied location:

```nginx
location /RequestDenied {
    internal;
    return 403;
}
```

## 15.6 Minimal Custom BasicRule to Avoid No-Rules-Loaded

If using a location-specific custom rule only:

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:500019 "s:$UWA:8" "str:scanner-test" "mz:ARGS|URL" "msg:example location rule";

    CheckRule "$UWA >= 8" BLOCK;
}
```

## 15.7 Troubleshooting Checklist

- [ ] Is Naxsi module loaded?
- [ ] Is `SecRulesEnabled` present?
- [ ] Is at least one `MainRule` or `BasicRule` loaded?
- [ ] Is `naxsi_core.rules` included?
- [ ] Does the include path exist?
- [ ] Are rule files readable by NGINX?
- [ ] Does `nginx -t` pass?
- [ ] Are required `CheckRule` directives present?

---

# 16. Internal Rule 20 - Malformed UTF-8

## 16.1 Rule Identity

```text
Number: 20
Name: Malformed UTF-8
Action: DROP
```

## 16.2 Meaning

Internal rule `20` refers to a request that contains malformed UTF-8.

## 16.3 Security Interpretation

Malformed UTF-8 can indicate:

- parser confusion attack
- encoding evasion
- corrupted client input
- binary data sent to text endpoints
- malicious obfuscation
- invalid request body or query encoding

## 16.4 Rule-Generation Use

When malformed UTF-8 is observed:

- explain that Naxsi drops the request at internal rule level
- recommend fixing client encoding
- whitelist only if endpoint intentionally accepts non-UTF8/binary data
- avoid generating a normal XSS/SQLi rule unless payload contains clear attack tokens

## 16.5 Narrow Whitelist Example

```nginx
BasicRule wl:20 "mz:$URL:/api/binary-ingest|BODY";
```

## 16.6 Tuning Warning

Malformed UTF-8 is high-risk for parser bypasses. Do not globally whitelist:

```nginx
MainRule wl:20;
```

---

# 17. Internal Rule 21 - Illegal Host in Header

## 17.1 Rule Identity

```text
Number: 21
Name: Illegal Host in Header
Action: DROP
```

## 17.2 Meaning

Internal rule `21` refers to a request that contains a `Host` header with an illegal IP.

Illegal host ranges listed in the source:

```text
0.0.0.0/8
255.255.255.255/32
0000:0000:0000:0000:0000:0000:0000:0000/128
ff00:0000:0000:0000:0000:0000:0000:0000/8
```

## 17.3 Security Interpretation

Illegal Host header values may indicate:

- malformed client traffic
- scanner activity
- Host header abuse
- proxy misconfiguration
- SSRF probing
- virtual-host routing confusion attempts

## 17.4 Rule-Generation Use

When internal rule `21` appears:

- explain that Naxsi dropped due to illegal Host header IP
- recommend fixing upstream proxy/client Host header
- do not whitelist broadly
- consider explicit NGINX host validation if needed
- keep the internal drop behavior unless there is a very specific trusted reason

## 17.5 Example Additional Host Hardening

This is NGINX-level hardening, not a Naxsi internal rule replacement:

```nginx
server {
    listen 80 default_server;
    server_name _;
    return 444;
}
```

Application server block should use expected hostnames:

```nginx
server {
    listen 80;
    server_name example.com www.example.com;

    location / {
        SecRulesEnabled;
        DeniedUrl "/RequestDenied";
        CheckRule "$SQL >= 8" BLOCK;
        CheckRule "$XSS >= 8" BLOCK;
    }

    location /RequestDenied {
        internal;
        return 403;
    }
}
```

## 17.6 Whitelist Caution

Avoid whitelisting rule `21` because illegal Host headers are usually not needed for legitimate application traffic.

If a trusted internal proxy produces unusual Host headers, fix the proxy configuration instead of whitelisting the internal rule.

---

# 18. Internal Rules and Libinjection Score Enforcement

## 18.1 Libinjection Internal Rules Do Not Directly Block

Internal rules `17` and `18` are different from most internal blocking rules.

| Rule ID | Name | Score increment | Direct block? |
|---:|---|---|---|
| `17` | libinjection SQLi | `$LIBINJECTION_SQL += 1` | No |
| `18` | libinjection XSS | `$LIBINJECTION_XSS += 1` | No |

To block, the score must meet a `CheckRule` condition.

## 18.2 Required Libinjection Configuration

```nginx
location / {
    SecRulesEnabled;

    LibInjectionSql;
    LibInjectionXss;

    DeniedUrl "/RequestDenied";

    CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
    CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
}
```

## 18.3 Threshold Consideration

The source basic configuration uses:

```nginx
CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
```

But internal rules `17` and `18` increment their score by `1`.

Rule-generation implications:

- A threshold of `8` requires accumulated hits or scoring behavior across rules/locations.
- If the user expects a single libinjection hit to block, they may need a lower threshold such as `1`.
- Lowering threshold increases false-positive risk and should be tested in `LearningMode`.

Example strict libinjection blocking:

```nginx
CheckRule "$LIBINJECTION_SQL >= 1" BLOCK;
CheckRule "$LIBINJECTION_XSS >= 1" BLOCK;
```

Safer baseline from example config:

```nginx
CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
```

## 18.4 Generation Guidance

When generating Naxsi libinjection configuration, include a note:

```text
Use threshold 8 to follow the example baseline. Use threshold 1 only if a single libinjection detection should block and false positives have been tested.
```

---

# 19. Whitelisting Internal Rules Safely

## 19.1 Whitelist Syntax

Global whitelist:

```nginx
MainRule wl:<RULE_ID> "mz:<MATCH_ZONE>";
```

Location-specific whitelist:

```nginx
BasicRule wl:<RULE_ID> "mz:<MATCH_ZONE>";
```

Example:

```nginx
BasicRule wl:15 "mz:$URL:/api/legacy-json|BODY";
```

## 19.2 Internal Rule Whitelist Matrix

| Internal rule | Can be whitelisted? | Preferred approach |
|---:|---|---|
| `1` Weird Request | Yes, but rarely | Fix malformed client/request parser issue first. |
| `2` Big Request | Yes | Tune body/upload limits; whitelist only upload endpoint if safe. |
| `10` Null byte | Yes, high risk | Avoid unless binary endpoint is validated. |
| `11` Content-Type | Yes | Fix client header; whitelist endpoint-specific content type if required. |
| `12` Invalid URL | Yes, high risk | Fix URL generation; avoid broad whitelist. |
| `13` Malformed POST | Yes | Fix multipart/client formatting; narrow whitelist only. |
| `14` Malformed boundary | Yes | Fix multipart boundary; narrow upload whitelist only. |
| `15` Malformed JSON | Yes | Fix JSON; narrow legacy endpoint whitelist only. |
| `16` Empty POST Body | Yes | Prefer GET or proper body; whitelist only known endpoint. |
| `17` libinjection SQLi | Yes | Prefer parameter/URL-specific whitelist if false positive. |
| `18` libinjection XSS | Yes | Prefer parameter/URL-specific whitelist if false positive. |
| `19` No Rules Loaded | Do not whitelist as normal solution | Fix missing rules configuration. |
| `20` Malformed UTF-8 | Yes, high risk | Whitelist only binary/non-UTF8 endpoint if safe. |
| `21` Illegal Host | Avoid | Fix client/proxy Host header; keep blocked. |

## 19.3 Recommended Whitelist Workflow

1. Enable JSON logs:

```nginx
set $naxsi_json_log 1;
```

2. Identify internal rule ID from logs.
3. Identify match zone and request component.
4. Confirm the traffic is legitimate.
5. Create a narrow `BasicRule` whitelist if the exception is location-specific.
6. Re-test malicious payloads.
7. Keep `CheckRule` thresholds active.
8. Validate NGINX config:

```bash
nginx -t
```

## 19.4 Whitelist Examples by Internal Rule

### Content-Type false positive on webhook

```nginx
BasicRule wl:11 "mz:$URL:/api/webhook|$HEADERS_VAR:Content-Type";
```

### Malformed JSON on legacy endpoint

```nginx
BasicRule wl:15 "mz:$URL:/api/legacy-json|BODY";
```

### Empty POST body on ping endpoint

```nginx
BasicRule wl:16 "mz:$URL:/api/ping";
```

### Libinjection SQLi false positive in SQL training lab

```nginx
BasicRule wl:17 "mz:$URL:/training/sql|$ARGS_VAR:query";
```

### Libinjection XSS false positive in HTML editor

```nginx
BasicRule wl:18 "mz:$URL:/admin/editor|$ARGS_VAR:html";
```

---

# 20. Internal Rule Hits to Operational Fixes

## 20.1 Decision Matrix

| Observed internal rule hit | Likely root cause | Recommended generated response |
|---:|---|---|
| `1` | Unparseable request | Investigate request format; avoid broad whitelist. |
| `2` | Oversized body or content mismatch | Tune body/upload settings; narrow whitelist only for upload endpoint. |
| `10` | Null byte evasion | Treat as high-risk; block or score as `$EVADE`; avoid whitelist. |
| `11` | Missing/unsupported Content-Type | Fix client Content-Type; narrow whitelist for known endpoint. |
| `12` | Invalid URL | Fix client URL; keep blocked unless legacy behavior confirmed. |
| `13` | Malformed POST | Fix POST/multipart format; narrow upload whitelist if needed. |
| `14` | Malformed boundary | Fix multipart boundary; avoid broad whitelist. |
| `15` | Malformed JSON | Fix JSON body; whitelist legacy endpoint only if necessary. |
| `16` | Empty POST body | Use GET or send valid body; whitelist health/ping endpoint if required. |
| `17` | libinjection SQLi score | Add/verify `LibInjectionSql` and `CheckRule "$LIBINJECTION_SQL ..."`; tune false positives. |
| `18` | libinjection XSS score | Add/verify `LibInjectionXss` and `CheckRule "$LIBINJECTION_XSS ..."`; tune false positives. |
| `19` | WAF enabled but no rules loaded | Fix configuration by including core rules or adding `MainRule`/`BasicRule`. |
| `20` | Malformed UTF-8 | Fix encoding; narrow whitelist only for binary/non-UTF8 endpoint. |
| `21` | Illegal Host header IP | Fix client/proxy/Host validation; avoid whitelist. |

## 20.2 Do Not Generate Custom Rules for Pure Configuration Errors

For internal rule `19`, the correct solution is configuration repair, not a detection rule.

Bad response:

```nginx
BasicRule id:500019 "s:$UWA:8" "str:no rules" "mz:URL" "msg:fix no rules";
```

Good response:

```nginx
include /etc/nginx/naxsi/naxsi_core.rules;

location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$XSS >= 8" BLOCK;
}
```

## 20.3 Do Not Lower Security by Broad Whitelisting

Bad:

```nginx
MainRule wl:10,11,12,13,14,15,16,20,21;
```

Better:

```nginx
BasicRule wl:15 "mz:$URL:/api/legacy-json|BODY";
```

---

# 21. Complete Configuration Template Including Internal-Rule Awareness

## 21.1 Baseline Production Naxsi Configuration

```nginx
load_module /etc/nginx/modules/ngx_http_naxsi_module.so;

http {
    include /etc/nginx/naxsi/naxsi_core.rules;

    server {
        listen 80;
        server_name example.com;

        set $naxsi_json_log 1;

        location / {
            proxy_pass http://internal-ip-address:80;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            SecRulesEnabled;

            LibInjectionSql;
            LibInjectionXss;

            DeniedUrl "/RequestDenied";

            include /etc/nginx/naxsi/blocking/*.rules;

            CheckRule "$SQL >= 8" BLOCK;
            CheckRule "$XSS >= 8" BLOCK;
            CheckRule "$RFI >= 8" BLOCK;
            CheckRule "$UWA >= 8" BLOCK;
            CheckRule "$EVADE >= 8" BLOCK;
            CheckRule "$UPLOAD >= 5" BLOCK;
            CheckRule "$TRAVERSAL >= 5" BLOCK;
            CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
            CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
        }

        location /RequestDenied {
            internal;
            return 403;
        }
    }
}
```

## 21.2 Tuning Configuration with LearningMode

```nginx
load_module /etc/nginx/modules/ngx_http_naxsi_module.so;

http {
    include /etc/nginx/naxsi/naxsi_core.rules;

    server {
        listen 80;
        server_name example.com;

        set $naxsi_json_log 1;

        location / {
            proxy_pass http://internal-ip-address:80;

            SecRulesEnabled;
            LearningMode;

            LibInjectionSql;
            LibInjectionXss;

            DeniedUrl "/RequestDenied";

            include /etc/nginx/naxsi/blocking/*.rules;

            CheckRule "$SQL >= 8" BLOCK;
            CheckRule "$XSS >= 8" BLOCK;
            CheckRule "$RFI >= 8" BLOCK;
            CheckRule "$UWA >= 8" BLOCK;
            CheckRule "$EVADE >= 8" BLOCK;
            CheckRule "$UPLOAD >= 5" BLOCK;
            CheckRule "$TRAVERSAL >= 5" BLOCK;
            CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
            CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
        }

        location /RequestDenied {
            internal;
            return 403;
        }
    }
}
```

## 21.3 Validation

Always validate:

```bash
nginx -t
```

Reload only if validation succeeds.

---

# 22. Attack-Type Mapping for Internal Rules

## 22.1 XSS

Relevant internal rule:

```text
18 - libinjection XSS
```

Related configuration:

```nginx
LibInjectionXss;
CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
CheckRule "$XSS >= 8" BLOCK;
```

Optional custom XSS score rule:

```nginx
BasicRule id:500180 "s:$XSS:8" "rx:<\s*script|onerror\s*=|onload\s*=|javascript:" "mz:ARGS|BODY|HEADERS" "msg:custom XSS indicators";
```

## 22.2 SQL Injection

Relevant internal rule:

```text
17 - libinjection SQLi
```

Related configuration:

```nginx
LibInjectionSql;
CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
CheckRule "$SQL >= 8" BLOCK;
```

Optional custom SQLi score rule:

```nginx
BasicRule id:500170 "s:$SQL:8" "rx:union\s+select|or\s+1\s*=\s*1|sleep\s*\(" "mz:ARGS|BODY" "msg:custom SQLi indicators";
```

## 22.3 Evasion / Encoding Abuse

Relevant internal rules:

```text
10 - Null-Byte Hex Encoding
20 - Malformed UTF-8
12 - Invalid formatted URL
```

Optional custom evasion score rule:

```nginx
BasicRule id:500100 "s:$EVADE:8" "rx:%00|\\x00|%u[0-9a-fA-F]{4}|/\*.*\*/" "mz:ARGS|BODY|URL" "msg:custom evasion indicators";
```

Related CheckRule:

```nginx
CheckRule "$EVADE >= 8" BLOCK;
```

## 22.4 Upload Abuse

Relevant internal rules:

```text
2 - Big Request
13 - Malformed POST Format
14 - Malformed POST Boundary
16 - Empty POST Body
```

Related CheckRule:

```nginx
CheckRule "$UPLOAD >= 5" BLOCK;
```

Tuning guidance:

```text
Use endpoint-specific whitelists for known upload endpoints only after validating logs.
```

## 22.5 Host Header / SSRF-Like Probing

Relevant internal rule:

```text
21 - Illegal Host in Header
```

Recommended action:

```text
Fix client/proxy Host header handling and keep internal DROP behavior.
```

Optional NGINX hardening:

```nginx
server {
    listen 80 default_server;
    server_name _;
    return 444;
}
```

---

# 23. RAG Context Assembly Guidance

## 23.1 What This Document Should Help Generate

When retrieved, this document should help an LLM produce:

- explanation of a Naxsi internal rule hit
- safe Naxsi whitelist for a specific internal rule
- warning about reserved IDs below `1000`
- correct `LibInjectionSql` and `LibInjectionXss` configuration
- correct `CheckRule` for `$LIBINJECTION_SQL` and `$LIBINJECTION_XSS`
- fix for internal rule `19` (`No Rules Loaded`)
- tuning guidance for malformed JSON, POST, UTF-8, Content-Type, and Host header issues
- operational steps to test and validate with `nginx -t`

## 23.2 Output Template for Internal Rule Analysis

```markdown
## Internal Rule Hit

- Rule ID:
- Rule name:
- Action or score:
- Meaning:

## Likely Root Cause

Explain parser/body/content-type/libinjection/host issue.

## Recommended Fix

Provide:
- client fix, or
- Naxsi configuration fix, or
- narrow whitelist if justified

## Proposed Naxsi Configuration

```nginx
...
```

## Safety Notes

Explain:
- false-positive risk
- why broad whitelist is dangerous
- whether LearningMode affects this rule
- how to validate with `nginx -t`
```

## 23.3 Output Template for Libinjection Rule Generation

```markdown
## Rule Objective

- Attack type: SQLi or XSS
- Detection source: Naxsi libinjection
- Internal rule: 17 or 18
- Enforcement goal:

## Proposed Configuration

```nginx
location / {
    SecRulesEnabled;
    LibInjectionSql;
    LibInjectionXss;
    DeniedUrl "/RequestDenied";

    CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
    CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
}
```

## Why This Works

Explain:
- internal rule 17 increments `$LIBINJECTION_SQL`
- internal rule 18 increments `$LIBINJECTION_XSS`
- `CheckRule` is required for blocking
- threshold selection and LearningMode implications

## Tuning Notes

Explain whitelisting by URL/parameter if false positives occur.
```

---

# 24. Common Mistakes and Corrections

## 24.1 Mistake: Custom Rule ID Below 1000

Incorrect:

```nginx
BasicRule id:18 "s:$XSS:8" "rx:<script" "mz:ARGS" "msg:XSS";
```

Correct:

```nginx
BasicRule id:500018 "s:$XSS:8" "rx:<script" "mz:ARGS" "msg:XSS";
```

## 24.2 Mistake: Enabling LibInjection Without CheckRule

Incorrect:

```nginx
location / {
    SecRulesEnabled;
    LibInjectionSql;
    LibInjectionXss;
    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$XSS >= 8" BLOCK;
}
```

Correct:

```nginx
location / {
    SecRulesEnabled;
    LibInjectionSql;
    LibInjectionXss;
    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$XSS >= 8" BLOCK;
    CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
    CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
}
```

## 24.3 Mistake: Trying to Fix Rule 19 with a Whitelist

Incorrect:

```nginx
BasicRule wl:19 "mz:URL";
```

Correct:

```nginx
include /etc/nginx/naxsi/naxsi_core.rules;

location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";
    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$XSS >= 8" BLOCK;
}
```

## 24.4 Mistake: Broadly Whitelisting Malformed JSON

Risky:

```nginx
MainRule wl:15;
```

Safer:

```nginx
BasicRule wl:15 "mz:$URL:/api/legacy-json|BODY";
```

## 24.5 Mistake: Assuming LearningMode Prevents All Blocking

Incorrect assumption:

```text
LearningMode means all Naxsi blocks become logs.
```

Correct:

```text
LearningMode turns normal BLOCK CheckRules into LOG, but internal rules below 1000 may still block or drop abnormal requests.
```

## 24.6 Mistake: Treating Illegal Host as a Normal False Positive

Risky:

```nginx
BasicRule wl:21 "mz:HEADERS";
```

Better:

```text
Fix upstream proxy or client Host header generation. Keep illegal Host header drops enabled unless there is a proven and narrow trusted case.
```

---

# 25. Retrieval Keywords

## 25.1 Naxsi Internal Rule Keywords

```text
Naxsi internal rules
ids lower than 1000
reserved rule ids
No rules shall be defined with ids lower than 1000
internal blocking rules can be whitelisted
Weird Request
Big Request
Null-Byte Hex Encoding
Uncommon Content Type
Invalid formatted URL
Malformed POST Format
Malformed POST Boundary
Malformed JSON
Empty POST Body
libinjection SQLi
libinjection Xss
No Rules Loaded
Malformed UTF-8
Illegal Host in Header
```

## 25.2 Naxsi Configuration Keywords

```text
SecRulesEnabled
LearningMode
DeniedUrl
CheckRule
BLOCK
DROP
LOG
ALLOW
LibInjectionSql
LibInjectionXss
$LIBINJECTION_SQL
$LIBINJECTION_XSS
$SQL
$XSS
$EVADE
$UPLOAD
$TRAVERSAL
naxsi_core.rules
nginx -t
```

## 25.3 Whitelist Keywords

```text
MainRule wl
BasicRule wl
internal rule whitelist
whitelist internal rule 15
whitelist malformed JSON
whitelist content type
whitelist libinjection SQLi
whitelist libinjection XSS
mz:
$URL
$ARGS_VAR
$HEADERS_VAR
BODY
```

## 25.4 Attack and Parser Keywords

```text
XSS
SQL injection
SQLi
null byte
%00
malformed JSON
malformed UTF-8
invalid URL
multipart boundary
empty POST body
uncommon content type
illegal Host header
parser evasion
request smuggling
upload abuse
libinjection
```

---

# 26. Final Checklist for Naxsi Internal Rule-Aware Generation

- [ ] Never generate custom rule IDs below `1000`.
- [ ] Explain that internal rules are hardcoded in Naxsi.
- [ ] Use internal rule IDs only in `wl:` whitelist directives.
- [ ] Whitelist internal blocking rules only with narrow match zones.
- [ ] Do not whitelist internal rule `19` as the normal fix.
- [ ] Fix `No Rules Loaded` by including rules or adding `MainRule`/`BasicRule`.
- [ ] If using `LibInjectionSql`, include `$LIBINJECTION_SQL` `CheckRule`.
- [ ] If using `LibInjectionXss`, include `$LIBINJECTION_XSS` `CheckRule`.
- [ ] Explain that internal rules `17` and `18` increment scores by `1` and do not directly block.
- [ ] Explain threshold implications for `$LIBINJECTION_SQL` and `$LIBINJECTION_XSS`.
- [ ] Treat null bytes, malformed UTF-8, invalid URLs, and illegal Host headers as high-risk by default.
- [ ] Prefer fixing clients/proxies before whitelisting parser-level internal rules.
- [ ] Use `LearningMode` during tuning but do not claim it prevents all internal blocks/drops.
- [ ] Enable JSON logs for tuning.
- [ ] Validate with `nginx -t`.
- [ ] Keep whitelists documented and scoped by URL, parameter, header, or body zone.
