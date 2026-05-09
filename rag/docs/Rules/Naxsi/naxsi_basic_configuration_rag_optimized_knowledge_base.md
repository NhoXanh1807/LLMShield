# Naxsi Basic Configuration Knowledge Base for RAG and WAF Rule Generation
# 1. Naxsi Configuration Model
## 1.1 Definition

Naxsi is an NGINX WAF module. Naxsi protection is configured by loading the Naxsi module, including rule files, enabling Naxsi inside protected `location` blocks, and defining score-based `CheckRule` actions.

Minimum conceptual flow:

```text
Load Naxsi module
→ Include global rules such as naxsi_core.rules
→ Enable Naxsi inside a location
→ Define DeniedUrl for blocked requests
→ Define CheckRule thresholds and actions
→ Optionally enable libinjection SQLi/XSS
→ Optionally include extra blocking rules
→ Optionally create whitelists
→ Test NGINX config with nginx -t
```

## 1.2 Naxsi Configuration Layers

| NGINX scope | Naxsi configuration role | Common directives |
|---|---|---|
| Global / top-level | Load the dynamic Naxsi module. | `load_module` |
| `http` block | Include global Naxsi rules and declare global `MainRule` rules or whitelists. | `include`, `MainRule` |
| `server` block | Define virtual host and reverse proxy context. | `server_name`, `listen`, `location` |
| Protected `location` block | Enable Naxsi and define local enforcement policy. | `SecRulesEnabled`, `DeniedUrl`, `CheckRule`, `LearningMode`, `LibInjectionSql`, `LibInjectionXss`, `BasicRule` |
| Denied internal `location` | Return blocked response. | `internal`, `return 403` |

## 1.3 Rule-Generation Principle

When generating a Naxsi WAF configuration:

1. Always include `SecRulesEnabled` in the protected `location`.
2. Always define `DeniedUrl` and the corresponding internal redirect location.
3. Always define `CheckRule` for every score family that the rules can increment.
4. If `LibInjectionSql` is enabled, define `CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;`.
5. If `LibInjectionXss` is enabled, define `CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;`.
6. Include `naxsi_core.rules` before relying on core score names such as `$SQL`, `$XSS`, `$RFI`, `$TRAVERSAL`, `$UPLOAD`, `$UWA`, and `$EVADE`.
7. Use `LearningMode` while tuning false positives, but remember internal rules with IDs below `1000` can still drop suspicious requests.
8. Use `nginx -t` to validate syntax before reload.

---

# 2. Loading the Naxsi Module

## 2.1 Dynamic Module Requirement

After Naxsi is compiled as a dynamic module, NGINX must load the shared library before any Naxsi directives can be used.

Module load directive:

```nginx
load_module /usr/lib/nginx/modules/ngx_http_naxsi_module.so;
```

Alternative path example:

```nginx
load_module /etc/nginx/modules/ngx_http_naxsi_module.so;
```

The correct path depends on how Naxsi was installed.

## 2.2 Failure Mode

> **Warning:** NGINX fails to load the configuration if `ngx_http_naxsi_module.so` is not loaded and the configuration contains Naxsi directives.

This affects directives such as:

```nginx
SecRulesEnabled;
DeniedUrl "/RequestDenied";
CheckRule "$SQL >= 8" BLOCK;
LibInjectionSql;
LibInjectionXss;
LearningMode;
MainRule ...
BasicRule ...
```

## 2.3 Validation Command

Before reloading NGINX, validate the configuration:

```bash
nginx -t
```

Use this command after:

- adding `load_module`
- including `naxsi_core.rules`
- adding `SecRulesEnabled`
- adding `CheckRule`
- adding custom `MainRule` or `BasicRule`
- adding whitelists
- adding additional blocking rule includes

---

# 3. Including Core Rules

## 3.1 Core Rule Include

After loading the module, include the Naxsi core rules. The source document identifies `naxsi_core.rules` as the basic ruleset.

Example:

```nginx
include /etc/nginx/naxsi/naxsi_core.rules;
```

This can be included directly in:

```nginx
/etc/nginx/nginx.conf
```

## 3.2 Purpose of `naxsi_core.rules`

The core rules provide basic pattern-based detection and score increments for categories such as:

| Score | Meaning | Rule-generation use |
|---|---|---|
| `$SQL` | SQL injection score | SQLi detection using core rules. |
| `$XSS` | Cross-site scripting score | XSS detection using core rules. |
| `$RFI` | Remote File Inclusion score | RFI detection. |
| `$TRAVERSAL` | Path traversal score | Directory traversal and file access attempts. |
| `$UPLOAD` | Malicious upload score | File upload abuse detection. |
| `$UWA` | Unwanted Access score | Scanner, admin probing, unwanted access. |
| `$EVADE` | Evasion score | Evasion attempts and tools trying to avoid detection. |

## 3.3 Required CheckRules for Core Rules

When using Naxsi repository rules and `naxsi_core.rules`, define corresponding `CheckRule` directives.

Recommended baseline:

```nginx
CheckRule "$SQL >= 8" BLOCK;
CheckRule "$XSS >= 8" BLOCK;
CheckRule "$RFI >= 8" BLOCK;
CheckRule "$UWA >= 8" BLOCK;
CheckRule "$EVADE >= 8" BLOCK;
CheckRule "$UPLOAD >= 5" BLOCK;
CheckRule "$TRAVERSAL >= 5" BLOCK;
```

Rule-generation guidance:

- Use threshold `8` for `$SQL`, `$XSS`, `$RFI`, `$UWA`, and `$EVADE` as the default baseline from the source example.
- Use threshold `5` for `$UPLOAD` and `$TRAVERSAL` as the source example does.
- Tune thresholds only when logs show false positives or false negatives.
- Do not generate a score-producing rule without a matching `CheckRule`.

---

# 4. Enabling Naxsi in a Protected Location

## 4.1 Minimum Protected Location

A protected `location` must define:

```nginx
SecRulesEnabled;
DeniedUrl "/RequestDenied";
CheckRule "$FOO >= 8" BLOCK;
```

Minimum example:

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";
    CheckRule "$FOO >= 8" BLOCK;
}

location /RequestDenied {
    internal;
    return 403;
}
```

## 4.2 `SecRulesEnabled`

`SecRulesEnabled` enables Naxsi in the current `location`.

```nginx
location / {
    SecRulesEnabled;
}
```

> **Important:** `SecRulesEnabled` is mandatory to enable Naxsi in a `location`.

If `SecRulesEnabled` is missing, Naxsi rules will not be enforced for that location.

## 4.3 `DeniedUrl`

`DeniedUrl` defines where Naxsi internally redirects blocked, dropped, or logged requests.

Example:

```nginx
DeniedUrl "/RequestDenied";
```

The destination must be a separate NGINX `location`.

Recommended denied location:

```nginx
location /RequestDenied {
    internal;
    return 403;
}
```

## 4.4 `DeniedUrl` Security Rule

> **Warning:** Mark the denied destination as `internal` so external clients cannot directly request it and use it to fingerprint or pre-detect the WAF.

Recommended:

```nginx
location /RequestDenied {
    internal;
    return 403;
}
```

Risky:

```nginx
location /RequestDenied {
    return 403;
}
```

## 4.5 Denied Request Headers

Naxsi adds useful internal headers when blocking, dropping, or logging requests:

```text
x-orig_url
x-orig_args
x-naxsi_sig
```

Rule-generation implication:

- Use the denied location for consistent block responses.
- Do not expose detailed WAF internals in public responses.
- Use logs for diagnostics, not user-facing response content.

---

# 5. `CheckRule`: Score-Based Enforcement

## 5.1 Definition

`CheckRule` instructs Naxsi to take an action when a score condition is met.

Syntax pattern:

```nginx
CheckRule "$SCORE_NAME >= THRESHOLD" ACTION;
```

Example:

```nginx
CheckRule "$SQL >= 8" BLOCK;
```

Meaning:

- If `$SQL` is greater than or equal to `8`, apply `BLOCK`.

## 5.2 Supported CheckRule Actions

`CheckRule` can use these actions:

| Action | Meaning | Rule-generation use |
|---|---|---|
| `LOG` | Log matching requests. | Monitoring and false-positive analysis. |
| `BLOCK` | Block according to Naxsi behavior when not in learning mode. | Default enforcement for most categories. |
| `DROP` | Drop request. | Strong enforcement for severe or always-malicious traffic. |
| `ALLOW` | Allow traffic when condition is met. | Rare; use carefully for allow logic. |

## 5.3 Score Name Requirement

Score variable names must start with a dollar sign:

```text
$
```

Score variable names may contain underscores:

```text
$LIBINJECTION_XSS
$LIBINJECTION_SQL
```

Correct:

```nginx
CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
```

Incorrect:

```nginx
CheckRule "LIBINJECTION_XSS >= 8" BLOCK;
```

## 5.4 `BLOCK` and `LearningMode`

If `LearningMode` is enabled, `BLOCK` CheckRules behave as `LOG` for normal rules. This lets operators collect false-positive evidence without blocking production traffic.

Example learning deployment:

```nginx
location / {
    SecRulesEnabled;
    LearningMode;
    DeniedUrl "/RequestDenied";
    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$XSS >= 8" BLOCK;
}
```

Important exception:

> **Important:** Internal Naxsi rules with IDs below `1000` can still drop requests even in learning mode because they indicate abnormal processing or protocol-level issues.

## 5.5 CheckRule Threshold Matrix

| Attack type or category | Score | Baseline CheckRule |
|---|---|---|
| SQL injection | `$SQL` | `CheckRule "$SQL >= 8" BLOCK;` |
| XSS | `$XSS` | `CheckRule "$XSS >= 8" BLOCK;` |
| Remote File Inclusion | `$RFI` | `CheckRule "$RFI >= 8" BLOCK;` |
| Unwanted Access | `$UWA` | `CheckRule "$UWA >= 8" BLOCK;` |
| Evasion | `$EVADE` | `CheckRule "$EVADE >= 8" BLOCK;` |
| Malicious upload | `$UPLOAD` | `CheckRule "$UPLOAD >= 5" BLOCK;` |
| Traversal | `$TRAVERSAL` | `CheckRule "$TRAVERSAL >= 5" BLOCK;` |
| Libinjection XSS | `$LIBINJECTION_XSS` | `CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;` |
| Libinjection SQLi | `$LIBINJECTION_SQL` | `CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;` |

## 5.6 Rule-Generation Checklist for CheckRule

- [ ] Include a `CheckRule` for every score variable used by included rules.
- [ ] Use `$` before score name.
- [ ] Use `BLOCK` for enforcement.
- [ ] Use `LOG` or `LearningMode` for tuning.
- [ ] Use `DROP` only when the condition should block even during learning workflows.
- [ ] Confirm `DeniedUrl` exists when using blocking actions.
- [ ] Validate with `nginx -t`.

---

# 6. Learning Mode

## 6.1 Definition

`LearningMode` tells Naxsi not to honor `CheckRule` actions defined as `BLOCK`. Instead, `BLOCK` actions are interpreted as `LOG`.

Example:

```nginx
location / {
    SecRulesEnabled;
    LearningMode;
    DeniedUrl "/RequestDenied";
    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$XSS >= 8" BLOCK;
}
```

## 6.2 When to Use LearningMode

Use `LearningMode` when:

- deploying Naxsi for a new application
- collecting false positives
- validating a new custom rule
- tuning whitelists
- measuring real application behavior before enforcement
- adding additional blocking rules from `/etc/nginx/naxsi/blocking/*.rules`

## 6.3 LearningMode Limitation

Internal rules with IDs below `1000` can drop requests even in `LearningMode`.

Rule-generation implication:

- Do not promise that `LearningMode` prevents all blocking.
- If internal rules false positive, use explicit whitelists only after validating the cause.
- Treat internal rule false positives as high-signal events that need careful review.

---

# 7. Libinjection XSS and SQLi Detection

## 7.1 `LibInjectionXss`

`LibInjectionXss` enables libinjection XSS detection on all requests in the location.

Example:

```nginx
location / {
    SecRulesEnabled;
    LibInjectionXss;
    CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
}
```

## 7.2 `LibInjectionSql`

`LibInjectionSql` enables libinjection SQL injection detection on all requests in the location.

Example:

```nginx
location / {
    SecRulesEnabled;
    LibInjectionSql;
    CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
}
```

## 7.3 Libinjection Rule-Generation Requirement

When generating a Naxsi configuration with libinjection:

- If `LibInjectionXss;` is present, include:

```nginx
CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
```

- If `LibInjectionSql;` is present, include:

```nginx
CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
```

## 7.4 Libinjection and Core Score Difference

Core rules and libinjection rules use different score families.

| Detection source | Score |
|---|---|
| Core SQLi rules | `$SQL` |
| Core XSS rules | `$XSS` |
| libinjection SQLi | `$LIBINJECTION_SQL` |
| libinjection XSS | `$LIBINJECTION_XSS` |

Do not assume that:

```nginx
CheckRule "$SQL >= 8" BLOCK;
```

will enforce libinjection SQLi detections.

Also define:

```nginx
CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
```

Do not assume that:

```nginx
CheckRule "$XSS >= 8" BLOCK;
```

will enforce libinjection XSS detections.

Also define:

```nginx
CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
```

---

# 8. Including Additional Blocking Rules

## 8.1 Additional Rule Include

The source example includes additional blocking rules:

```nginx
include /etc/nginx/naxsi/blocking/*.rules;
```

Use this when additional Naxsi repository blocking rule files or custom blocking rule files are installed under:

```text
/etc/nginx/naxsi/blocking/
```

## 8.2 Required CheckRules When Using Repository Blocking Rules

When using rules found in the Naxsi repository, include the corresponding `CheckRule` directives.

Baseline:

```nginx
CheckRule "$SQL >= 8" BLOCK;
CheckRule "$XSS >= 8" BLOCK;
CheckRule "$RFI >= 8" BLOCK;
CheckRule "$UWA >= 8" BLOCK;
CheckRule "$EVADE >= 8" BLOCK;
CheckRule "$UPLOAD >= 5" BLOCK;
CheckRule "$TRAVERSAL >= 5" BLOCK;
CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
```

## 8.3 Rule-Generation Guidance

If a generated configuration includes:

```nginx
include /etc/nginx/naxsi/blocking/*.rules;
```

then the generated output should also include:

- core `CheckRule` thresholds
- libinjection `CheckRule` thresholds if libinjection is enabled
- `LearningMode` recommendation for first deployment
- `nginx -t` validation instruction
- log review and whitelist tuning instructions

---

# 9. Whitelists with `MainRule` and `BasicRule`

## 9.1 Whitelist Purpose

Naxsi core rules are intentionally simple and may match legitimate application behavior. Whitelists are used to permit legitimate behavior without disabling protection globally.

Use whitelists when:

- a specific parameter legitimately contains characters that core rules flag
- a known endpoint requires special input
- a CMS or framework generates known false positives
- a rule should be disabled for one match zone, not everywhere

## 9.2 Global Whitelist with `MainRule`

`MainRule` is declared at `http` scope. It is used for global rules or global whitelists.

Source whitelist example:

```nginx
MainRule wl:1000,1009,1315 "mz:$BODY_VAR:_wp_http_referer";
```

Meaning:

- Whitelist rule IDs `1000`, `1009`, and `1315`.
- Apply the whitelist to the match zone `$BODY_VAR:_wp_http_referer`.

## 9.3 Location-Specific Whitelist with `BasicRule`

`BasicRule` is declared at `location` scope. It is used for location-specific rules or whitelists.

Source whitelist example:

```nginx
BasicRule wl:1000,1009,1315 "mz:$BODY_VAR:_wp_http_referer";
```

Meaning:

- Whitelist rule IDs `1000`, `1009`, and `1315`.
- Apply the whitelist only in the current `location`.
- Target match zone `$BODY_VAR:_wp_http_referer`.

## 9.4 MainRule vs BasicRule

| Directive | NGINX scope | Use |
|---|---|---|
| `MainRule` | `http` | Global custom rule or global whitelist. |
| `BasicRule` | `location` | Location-specific custom rule or whitelist. |

## 9.5 Whitelist Design Rule

A whitelist should be as narrow as possible.

Prefer:

```nginx
BasicRule wl:1000 "mz:$URL:/search|$ARGS_VAR:q";
```

Avoid broad whitelists that disable a rule everywhere:

```nginx
MainRule wl:1000;
```

## 9.6 Whitelist Checklist

- [ ] Identify the exact rule ID causing the false positive.
- [ ] Identify the exact match zone causing the false positive.
- [ ] Prefer `BasicRule` for location-specific whitelists.
- [ ] Use `MainRule` only when the exception is truly global.
- [ ] Validate that the whitelist does not create a bypass for real attacks.
- [ ] Re-test malicious payloads after whitelisting.
- [ ] Keep whitelists version-controlled and documented.

---

# 10. Naxsi Rule Syntax for Custom Rules

## 10.1 MainRule and BasicRule Rule Shape

Naxsi rules search for patterns in parts of a request and increment named scores or apply actions.

General pattern:

```nginx
MainRule id:<ID> "s:$SCORE:<POINTS>" "<MATCH_PATTERN>" "mz:<MATCH_ZONE>" "msg:<MESSAGE>";
```

Location-specific pattern:

```nginx
BasicRule id:<ID> "s:$SCORE:<POINTS>" "<MATCH_PATTERN>" "mz:<MATCH_ZONE>" "msg:<MESSAGE>";
```

## 10.2 Rule ID

Naxsi rule IDs are numeric and unique.

Example:

```nginx
id:45678
```

Important rule ID guidance:

- IDs below `1000` are reserved for Naxsi internal rules.
- Use IDs above `1000` for custom rules.
- Rule IDs are used in logs and whitelists.

## 10.3 Match Pattern Types

Common match patterns:

| Pattern | Meaning | Example |
|---|---|---|
| `rx:` | Regular expression match. | `"rx:<script|onerror"` |
| `str:` | Literal string match. | `"str:union select"` |
| `d:libinj_xss` | libinjection XSS match. | `"d:libinj_xss"` |
| `d:libinj_sql` | libinjection SQLi match. | `"d:libinj_sql"` |

## 10.4 Score Action

The score action increments a named score.

Example:

```nginx
"s:$SQL:8"
```

Meaning:

- Increment `$SQL` score by `8`.

Example:

```nginx
"s:$XSS:8"
```

Meaning:

- Increment `$XSS` score by `8`.

## 10.5 Match Zone

The match zone tells Naxsi where to inspect.

Examples:

```nginx
"mz:ARGS|BODY"
```

```nginx
"mz:$URL:/vuln_page.php|$ARGS_VAR:id"
```

```nginx
"mz:$HEADERS_VAR:User-Agent"
```

```nginx
"mz:$BODY_VAR:_wp_http_referer"
```

## 10.6 Example Custom Blacklist Rule

Drop requests to `/vuln_page.php` where argument `id` contains anything other than digits:

```nginx
BasicRule id:4242 "mz:$URL:/vuln_page.php|$ARGS_VAR:id" "rx:[^\d]+" "s:DROP" "msg:blacklist for SQLI in /vuln_page.php";
```

Rule-generation meaning:

- Scope to URL `/vuln_page.php`.
- Inspect argument `id`.
- Match non-digit characters.
- Apply `DROP`.
- This can virtually patch an unquoted SQLi in numeric ID parameter.

## 10.7 Custom Rule Checklist

- [ ] Use `MainRule` for global rules.
- [ ] Use `BasicRule` for location-specific rules.
- [ ] Use a custom ID above `1000`.
- [ ] Use `rx:` for regex patterns.
- [ ] Use `str:` for stable literal patterns.
- [ ] Use `s:$SCORE:POINTS` when generating score-based detection.
- [ ] Use `s:DROP` only for strong, highly scoped virtual patches.
- [ ] Use `mz:` to restrict the inspected location.
- [ ] Include `msg:` for operator diagnostics.
- [ ] Define matching `CheckRule` if using a custom score.

---

# 11. JSON Logging

## 11.1 Enable JSON Logs

The source document enables JSON logs with:

```nginx
set $naxsi_json_log 1;
```

Use this inside the `server` block or appropriate NGINX context for logging.

## 11.2 Rule-Generation Use

Enable JSON logs when:

- tuning false positives
- building whitelists
- monitoring rule hits
- debugging match zones
- correlating blocked payloads with request components
- feeding logs into analysis pipelines

Example:

```nginx
server {
    listen 80;
    server_name example.com;

    set $naxsi_json_log 1;

    location / {
        SecRulesEnabled;
        DeniedUrl "/RequestDenied";
        CheckRule "$SQL >= 8" BLOCK;
        CheckRule "$XSS >= 8" BLOCK;
    }
}
```

---

# 12. Complete Reverse Proxy Example Configuration

## 12.1 Source Configuration Objective

The source configuration defines an NGINX reverse proxy to a backend web service hosted on:

```text
internal-ip-address:80
```

It enables Naxsi, core rules, additional rules, JSON logs, libinjection SQLi/XSS detection, and blocking thresholds.

## 12.2 Full RAG-Optimized Configuration

```nginx
# Load Naxsi dynamic module.
load_module /etc/nginx/modules/ngx_http_naxsi_module.so;

server {
    listen 80;
    server_name example.com;

    # Enable Naxsi JSON logs for easier false-positive tuning and rule debugging.
    set $naxsi_json_log 1;

    # Include core Naxsi rules.
    include /etc/nginx/naxsi/naxsi_core.rules;

    location / {
        # Reverse proxy target.
        proxy_pass http://internal-ip-address:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Enable Naxsi for this location.
        SecRulesEnabled;

        # Optional tuning mode. When enabled, BLOCK CheckRules are considered LOG.
        # LearningMode;

        # Enable libinjection support for SQL injection and XSS detection.
        LibInjectionSql;
        LibInjectionXss;

        # Internal denied request destination.
        DeniedUrl "/RequestDenied";

        # Include additional Naxsi blocking rules.
        include /etc/nginx/naxsi/blocking/*.rules;

        # Mandatory CheckRules for Naxsi repository rules and core score families.
        CheckRule "$SQL >= 8" BLOCK;
        CheckRule "$XSS >= 8" BLOCK;
        CheckRule "$RFI >= 8" BLOCK;
        CheckRule "$UWA >= 8" BLOCK;
        CheckRule "$EVADE >= 8" BLOCK;
        CheckRule "$UPLOAD >= 5" BLOCK;
        CheckRule "$TRAVERSAL >= 5" BLOCK;

        # Mandatory CheckRules when LibInjectionXss and LibInjectionSql are enabled.
        CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
        CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
    }

    # The location where blocked requests are internally redirected.
    location /RequestDenied {
        internal;
        return 403;
    }
}
```

## 12.3 Configuration Explanation

| Directive | Purpose |
|---|---|
| `load_module` | Loads Naxsi module into NGINX. |
| `set $naxsi_json_log 1` | Enables JSON logging. |
| `include /etc/nginx/naxsi/naxsi_core.rules` | Includes basic Naxsi core rules. |
| `proxy_pass` | Forwards accepted requests to backend service. |
| `proxy_set_header` | Preserves host, real IP, forwarded IP, and scheme information. |
| `SecRulesEnabled` | Enables Naxsi in the `location`. |
| `LearningMode` | Optional tuning mode; turns `BLOCK` into `LOG` for normal rules. |
| `LibInjectionSql` | Enables libinjection SQLi detection. |
| `LibInjectionXss` | Enables libinjection XSS detection. |
| `DeniedUrl` | Internal redirect target for blocked requests. |
| `include /etc/nginx/naxsi/blocking/*.rules` | Includes additional blocking rules. |
| `CheckRule` | Applies actions based on score thresholds. |
| `location /RequestDenied` | Returns HTTP `403` for blocked requests. |
| `internal` | Prevents direct external access to denied location. |

---

# 13. Attack-Specific Naxsi Rule Generation

## 13.1 XSS Configuration Pattern

Use when the attack type is:

```text
XSS
cross-site scripting
script tag
onerror
onload
javascript:
HTML injection
```

Recommended configuration:

```nginx
location / {
    SecRulesEnabled;
    LibInjectionXss;
    DeniedUrl "/RequestDenied";

    CheckRule "$XSS >= 8" BLOCK;
    CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
}
```

Custom XSS virtual patch example:

```nginx
BasicRule id:500100 "s:$XSS:8" "rx:<\s*script|onerror\s*=|onload\s*=|javascript:" "mz:ARGS|BODY|HEADERS" "msg:custom XSS payload indicators";
```

Tuning guidance:

- Use `LearningMode` first if false positives are unknown.
- Use `BasicRule wl:<id> "mz:<zone>"` to whitelist legitimate fields.
- Avoid global whitelists for fields that only false positive on one endpoint.

## 13.2 SQL Injection Configuration Pattern

Use when the attack type is:

```text
SQL injection
SQLi
union select
or 1=1
sleep(
benchmark(
information_schema
```

Recommended configuration:

```nginx
location / {
    SecRulesEnabled;
    LibInjectionSql;
    DeniedUrl "/RequestDenied";

    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
}
```

Custom SQLi virtual patch for numeric `id` parameter:

```nginx
BasicRule id:500200 "mz:$URL:/vuln_page.php|$ARGS_VAR:id" "rx:[^\d]+" "s:DROP" "msg:virtual patch for SQLi in numeric id parameter";
```

Custom SQLi signature example:

```nginx
BasicRule id:500201 "s:$SQL:8" "rx:union\s+select|or\s+1\s*=\s*1|sleep\s*\(" "mz:ARGS|BODY" "msg:custom SQL injection indicators";
```

Tuning guidance:

- Prefer endpoint and parameter scoping for SQLi virtual patches.
- Use `LearningMode` before enforcing broad `$SQL` rules.
- Use `$LIBINJECTION_SQL` CheckRule if `LibInjectionSql` is enabled.

## 13.3 Path Traversal / LFI Configuration Pattern

Use when the attack type is:

```text
path traversal
directory traversal
LFI
../
..%2f
/etc/passwd
```

Recommended CheckRule:

```nginx
CheckRule "$TRAVERSAL >= 5" BLOCK;
```

Custom traversal rule example:

```nginx
BasicRule id:500300 "s:$TRAVERSAL:5" "rx:\.\./|\.\.\\|%2e%2e%2f|/etc/passwd" "mz:URL|ARGS|BODY" "msg:custom path traversal indicators";
```

Tuning guidance:

- Scope to vulnerable file/path parameters when known.
- Avoid broad blocking on all URI components unless logs confirm attacks.
- Keep `$TRAVERSAL` threshold aligned with included core rules.

## 13.4 Remote File Inclusion Configuration Pattern

Use when the attack type is:

```text
RFI
remote file inclusion
http://
https://
php://
data://
```

Recommended CheckRule:

```nginx
CheckRule "$RFI >= 8" BLOCK;
```

Custom RFI rule example:

```nginx
BasicRule id:500400 "s:$RFI:8" "rx:https?://|php://|data://" "mz:ARGS|BODY" "msg:custom RFI indicators";
```

Tuning guidance:

- Scope to URL-like parameters if the application legitimately accepts remote URLs.
- Use whitelists for known callback or webhook parameters if needed.
- Prefer log/learning mode during rollout.

## 13.5 Upload Abuse Configuration Pattern

Use when the attack type is:

```text
malicious upload
web shell
file upload abuse
.php upload
.jsp upload
```

Recommended CheckRule:

```nginx
CheckRule "$UPLOAD >= 5" BLOCK;
```

Custom upload rule example:

```nginx
BasicRule id:500500 "s:$UPLOAD:5" "rx:\.(php|phtml|jsp|jspx|asp|aspx)$" "mz:FILE_EXT" "msg:dangerous uploaded file extension";
```

Tuning guidance:

- Confirm the exact Naxsi match zone available for upload metadata in your deployment.
- If file upload fields are application-specific, scope rules tightly.
- Use `LearningMode` to avoid blocking legitimate file workflows.

## 13.6 Evade / Evasion Configuration Pattern

Use when the attack type is:

```text
evasion
scanner evasion
encoded payload
obfuscation
```

Recommended CheckRule:

```nginx
CheckRule "$EVADE >= 8" BLOCK;
```

Custom evasion rule example:

```nginx
BasicRule id:500600 "s:$EVADE:8" "rx:%00|%u[0-9a-fA-F]{4}|/\*.*\*/" "mz:ARGS|BODY|URL" "msg:custom evasion indicators";
```

Tuning guidance:

- Evasion signals can be noisy.
- Combine with path or parameter match zones when possible.
- Use logs before blocking if the application legitimately transports encoded content.

## 13.7 Unwanted Access Configuration Pattern

Use when the attack type is:

```text
scanner
admin probing
unwanted access
nmap
nikto
sqlmap
suspicious user-agent
```

Recommended CheckRule:

```nginx
CheckRule "$UWA >= 8" BLOCK;
```

Custom scanner User-Agent rule:

```nginx
BasicRule id:500700 "s:$UWA:8" "rx:sqlmap|nikto|acunetix|nmap|nuclei" "mz:$HEADERS_VAR:User-Agent" "msg:known scanner user-agent";
```

Tuning guidance:

- User-Agent can be spoofed.
- Use as one signal among others, not as sole authentication.
- Use `DROP` only for high-confidence hostile scanners.

---

# 14. Whitelisting and False-Positive Tuning Examples

## 14.1 Whitelist a WordPress Referer Body Variable

Source pattern:

```nginx
MainRule wl:1000,1009,1315 "mz:$BODY_VAR:_wp_http_referer";
BasicRule wl:1000,1009,1315 "mz:$BODY_VAR:_wp_http_referer";
```

Use:

- `MainRule` if the whitelist applies globally.
- `BasicRule` if it applies only inside one `location`.

## 14.2 Whitelist Query Parameter on One URL

Example:

```nginx
BasicRule wl:1000 "mz:$URL:/search|$ARGS_VAR:q";
```

Use this when:

- rule ID `1000` false positives only on `/search`
- parameter `q` legitimately contains characters that trigger the rule
- protection should remain active elsewhere

## 14.3 Whitelist Trusted IP

The official directive set supports IP-based allowlisting through `IgnoreIP` and `IgnoreCIDR`.

Single IP:

```nginx
location / {
    IgnoreIP "1.2.3.4";
}
```

CIDR range:

```nginx
location / {
    IgnoreCIDR "192.168.0.0/24";
}
```

Use carefully:

- Trusted scanners or internal monitoring may need allowlisting.
- Avoid broad public CIDR allowlists.
- Prefer short-lived exceptions when possible.

## 14.4 False-Positive Tuning Workflow

1. Enable `LearningMode`.
2. Enable JSON logs:

```nginx
set $naxsi_json_log 1;
```

3. Generate traffic representative of normal users.
4. Review Naxsi logs and identify:
   - rule ID
   - score
   - match zone
   - parameter/header/body field
   - URL path
5. Create a narrow whitelist with `BasicRule`.
6. Re-test malicious payloads.
7. Remove `LearningMode` only after expected traffic passes safely.

---

# 15. Naxsi Context Assembly for LLM Generation

## 15.1 What a Generated Naxsi Answer Should Include

A complete generated Naxsi answer should contain:

- protected `location` block
- `SecRulesEnabled`
- `DeniedUrl`
- internal denied location
- required `CheckRule` directives
- optional `LearningMode`
- optional `LibInjectionSql` / `LibInjectionXss`
- optional core rule include
- optional blocking rule include
- optional custom `BasicRule` or `MainRule`
- optional whitelists
- testing command `nginx -t`
- false-positive tuning notes

## 15.2 Minimal Safe Output Template

```markdown
## Rule Objective

- WAF: Naxsi
- Attack type:
- Payload location:
- Desired action:
- Deployment mode: LearningMode or blocking

## Proposed NGINX/Naxsi Configuration

```nginx
load_module /etc/nginx/modules/ngx_http_naxsi_module.so;

server {
    listen 80;
    server_name example.com;

    set $naxsi_json_log 1;
    include /etc/nginx/naxsi/naxsi_core.rules;

    location / {
        SecRulesEnabled;
        # LearningMode;
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

## Why This Configuration Matches the Bypass

Explain:
- selected score family
- selected CheckRule
- selected match zone
- selected libinjection directive if used
- selected custom BasicRule or MainRule if used

## Deployment Steps

1. Save config.
2. Run `nginx -t`.
3. Reload only after syntax validation.
4. Monitor logs.
5. Tune whitelists.
6. Disable `LearningMode` after validation.

## False Positives and Whitelisting

Explain:
- likely false-positive source
- exact whitelist recommendation
- why not to whitelist globally unless required
```

---

# 16. Common Mistakes and Corrections

## 16.1 Mistake: Missing `SecRulesEnabled`

Incorrect:

```nginx
location / {
    DeniedUrl "/RequestDenied";
    CheckRule "$SQL >= 8" BLOCK;
}
```

Correct:

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";
    CheckRule "$SQL >= 8" BLOCK;
}
```

## 16.2 Mistake: Missing Denied Location

Incorrect:

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";
    CheckRule "$XSS >= 8" BLOCK;
}
```

Correct:

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";
    CheckRule "$XSS >= 8" BLOCK;
}

location /RequestDenied {
    internal;
    return 403;
}
```

## 16.3 Mistake: Denied Location Not Internal

Risky:

```nginx
location /RequestDenied {
    return 403;
}
```

Better:

```nginx
location /RequestDenied {
    internal;
    return 403;
}
```

## 16.4 Mistake: Enabling LibInjection Without CheckRule

Incorrect:

```nginx
location / {
    SecRulesEnabled;
    LibInjectionXss;
    LibInjectionSql;
    CheckRule "$XSS >= 8" BLOCK;
    CheckRule "$SQL >= 8" BLOCK;
}
```

Correct:

```nginx
location / {
    SecRulesEnabled;
    LibInjectionXss;
    LibInjectionSql;
    CheckRule "$XSS >= 8" BLOCK;
    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
    CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
}
```

## 16.5 Mistake: Using Score Variable Without `$`

Incorrect:

```nginx
CheckRule "SQL >= 8" BLOCK;
```

Correct:

```nginx
CheckRule "$SQL >= 8" BLOCK;
```

## 16.6 Mistake: Loading Naxsi Directives Without Module

Incorrect:

```nginx
server {
    location / {
        SecRulesEnabled;
    }
}
```

Correct:

```nginx
load_module /etc/nginx/modules/ngx_http_naxsi_module.so;

server {
    location / {
        SecRulesEnabled;
    }
}
```

## 16.7 Mistake: Overbroad Whitelist

Risky:

```nginx
MainRule wl:1000;
```

Better:

```nginx
BasicRule wl:1000 "mz:$URL:/search|$ARGS_VAR:q";
```

## 16.8 Mistake: Blocking Before Tuning

Risky first deployment:

```nginx
CheckRule "$XSS >= 8" BLOCK;
CheckRule "$SQL >= 8" BLOCK;
```

Safer first deployment:

```nginx
LearningMode;
CheckRule "$XSS >= 8" BLOCK;
CheckRule "$SQL >= 8" BLOCK;
```

Then review logs, create whitelists, and disable `LearningMode` when ready.

---

# 17. Complete Production-Oriented Template

## 17.1 Production Template with LearningMode Disabled

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
            CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
            CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
        }

        location /RequestDenied {
            internal;
            return 403;
        }
    }
}
```

## 17.2 Tuning Template with LearningMode Enabled

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
            CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
            CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
        }

        location /RequestDenied {
            internal;
            return 403;
        }
    }
}
```

## 17.3 Validation

Always run:

```bash
nginx -t
```

Then reload NGINX only if syntax validation succeeds.

---

# 18. Retrieval Keywords

## 18.1 Naxsi Configuration Keywords

```text
Naxsi
Nginx Anti XSS SQL Injection
ngx_http_naxsi_module.so
load_module
include naxsi_core.rules
SecRulesEnabled
DeniedUrl
CheckRule
LearningMode
LibInjectionSql
LibInjectionXss
RequestDenied
internal
return 403
set $naxsi_json_log 1
nginx -t
```

## 18.2 Naxsi Score Keywords

```text
$SQL
$XSS
$RFI
$UWA
$EVADE
$UPLOAD
$TRAVERSAL
$LIBINJECTION_XSS
$LIBINJECTION_SQL
BLOCK
LOG
DROP
ALLOW
```

## 18.3 Naxsi Rule Syntax Keywords

```text
MainRule
BasicRule
wl
id:
s:
rx:
str:
d:libinj_xss
d:libinj_sql
mz:
msg:
ARGS
BODY
URL
HEADERS
$ARGS_VAR
$BODY_VAR
$HEADERS_VAR
```

## 18.4 Attack Keywords

```text
XSS
cross-site scripting
script tag
onerror
onload
javascript
SQL injection
SQLi
union select
or 1=1
sleep
benchmark
RFI
remote file inclusion
path traversal
directory traversal
malicious upload
web shell
evasion
scanner user-agent
```

---

# 19. Final Checklist for Naxsi Rule Generation

- [ ] Load the Naxsi module with `load_module`.
- [ ] Include `naxsi_core.rules` when relying on core score families.
- [ ] Enable Naxsi in each protected `location` with `SecRulesEnabled`.
- [ ] Define `DeniedUrl`.
- [ ] Define an internal denied location that returns `403`.
- [ ] Define `CheckRule` for `$SQL` if SQLi rules are used.
- [ ] Define `CheckRule` for `$XSS` if XSS rules are used.
- [ ] Define `CheckRule` for `$RFI` if RFI rules are used.
- [ ] Define `CheckRule` for `$TRAVERSAL` if traversal rules are used.
- [ ] Define `CheckRule` for `$UPLOAD` if upload rules are used.
- [ ] Define `CheckRule` for `$UWA` if unwanted-access rules are used.
- [ ] Define `CheckRule` for `$EVADE` if evasion rules are used.
- [ ] If `LibInjectionXss` is enabled, define `$LIBINJECTION_XSS`.
- [ ] If `LibInjectionSql` is enabled, define `$LIBINJECTION_SQL`.
- [ ] Use `LearningMode` during initial tuning.
- [ ] Remember internal rule IDs below `1000` may still drop in learning mode.
- [ ] Use `MainRule` at `http` scope.
- [ ] Use `BasicRule` at `location` scope.
- [ ] Use custom rule IDs above `1000`.
- [ ] Use precise `mz:` match zones for virtual patches.
- [ ] Use whitelists narrowly.
- [ ] Enable JSON logs for tuning.
- [ ] Test with `nginx -t`.
- [ ] Reload only after validation succeeds.
