# Naxsi Directives Knowledge Base for RAG and WAF Rule Generation
# 1. Naxsi Directive Model
## 1.1 Definition

Naxsi directives are NGINX configuration directives available when the Naxsi module is enabled.

The module file is:

```text
ngx_http_naxsi_module.so
```

Typical module loading pattern:

```nginx
load_module /etc/nginx/modules/ngx_http_naxsi_module.so;
```

or:

```nginx
load_module /usr/lib/nginx/modules/ngx_http_naxsi_module.so;
```

The exact path depends on installation.

## 1.2 Directive Scope Matters

Naxsi directives are valid only in specific NGINX blocks.

| Directive | NGINX block | Purpose |
|---|---|---|
| `SecRulesEnabled` | `location` | Enables Naxsi inspection in a location. |
| `CheckRule` | `location` | Defines score condition and action. |
| `LibInjectionXss` | `location` | Enables libinjection XSS detection for all requests in the location. |
| `LibInjectionSql` | `location` | Enables libinjection SQLi detection for all requests in the location. |
| `LearningMode` | `location` | Converts normal `BLOCK` actions to `LOG` for tuning. |
| `DeniedUrl` | `location` | Defines internal redirect target for block/drop/log handling. |
| `MainRule` | `http` | Declares global rule or global whitelist. |
| `BasicRule` | `location` | Declares location-specific rule or location-specific whitelist. |
| `IgnoreIP` | `location` | Whitelists a specific source IP address. |
| `IgnoreCIDR` | `location` | Whitelists a source IP range. |

## 1.3 Generation Principle

A generated Naxsi answer should not output a directive in the wrong NGINX block.

Correct:

```nginx
http {
    MainRule id:45678 "s:$UWA:8" "str:nmap" "mz:$HEADERS_VAR:User-Agent" "msg:nmap in user-agent";

    server {
        location / {
            SecRulesEnabled;
            BasicRule id:45679 "s:$XSS:8" "rx:<script" "mz:ARGS" "msg:script tag in args";
            CheckRule "$XSS >= 8" BLOCK;
        }
    }
}
```

Incorrect:

```nginx
location / {
    MainRule id:45678 "s:$UWA:8" "str:nmap" "mz:$HEADERS_VAR:User-Agent" "msg:nmap in user-agent";
}
```

Reason:

```text
MainRule belongs in the http block, not the location block.
```

---

# 2. `SecRulesEnabled`

## 2.1 Directive Identity

| Field | Value |
|---|---|
| Directive | `SecRulesEnabled` |
| NGINX block | `location` |
| Required? | Yes, required to enable Naxsi in a protected location |
| Main use | Turn on Naxsi inspection for the current `location` |

## 2.2 Definition

`SecRulesEnabled` is mandatory to enable Naxsi in an NGINX `location`.

Example:

```nginx
location / {
    SecRulesEnabled;
}
```

## 2.3 Rule-Generation Meaning

If a generated Naxsi configuration is intended to protect a path, API, or virtual host, the protected `location` must include:

```nginx
SecRulesEnabled;
```

Without `SecRulesEnabled`, Naxsi rules and `CheckRule` directives in that `location` will not protect the request path.

## 2.4 Correct Protected Location Pattern

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$XSS >= 8" BLOCK;
}
```

## 2.5 Common Mistake

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

## 2.6 Checklist for `SecRulesEnabled`

- [ ] Add `SecRulesEnabled` to every location that should be protected by Naxsi.
- [ ] Do not place `SecRulesEnabled` in `http` scope.
- [ ] Do not place `SecRulesEnabled` in `server` scope unless your NGINX/Naxsi version explicitly supports it; the source directive scope is `location`.
- [ ] Pair it with `DeniedUrl`.
- [ ] Pair it with appropriate `CheckRule` directives.
- [ ] Ensure at least one global or location-specific rule is loaded to avoid Naxsi internal rule `19` (`No Rules Loaded`).

---

# 3. `CheckRule`

## 3.1 Directive Identity

| Field | Value |
|---|---|
| Directive | `CheckRule` |
| NGINX block | `location` |
| Required? | Required to instruct Naxsi what action to take when rule scores meet thresholds |
| Main use | Map a score condition to `LOG`, `BLOCK`, `DROP`, or `ALLOW` |

## 3.2 Definition

`CheckRule` tells Naxsi which action to take when a score condition is met.

Syntax:

```nginx
CheckRule "$SCORE_NAME >= THRESHOLD" ACTION;
```

Example:

```nginx
CheckRule "$SQL >= 8" BLOCK;
```

Meaning:

- Inspect score variable `$SQL`.
- If `$SQL` is greater than or equal to `8`, perform the `BLOCK` action.

## 3.3 Supported Actions

`CheckRule` supports the following actions:

| Action | Meaning | Generation use |
|---|---|---|
| `LOG` | Log matching requests. | Monitoring and false-positive tuning. |
| `BLOCK` | Block when `LearningMode` is not enabled. | Normal enforcement action. |
| `DROP` | Drop the request. | Strong enforcement; use carefully. |
| `ALLOW` | Allow the request. | Rare; only for carefully scoped allow logic. |

## 3.4 Score Variable Name Constraint

Score variable names:

- must start with a dollar sign `$`
- may contain underscores `_`

Correct:

```nginx
CheckRule "$FOO_UU >= 8" LOG;
CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
```

Incorrect:

```nginx
CheckRule "FOO_UU >= 8" LOG;
CheckRule "LIBINJECTION_SQL >= 8" BLOCK;
```

Reason:

```text
Score variables must start with `$`.
```

## 3.5 Comparison Operators

The source examples use:

```nginx
CheckRule "$FOO_UU >= 8" LOG;
CheckRule "$BARRRR < 99" DROP;
CheckRule "$SOMETHING <= 33" BLOCK;
```

Supported score-condition patterns include:

```text
$SCORE >= value
$SCORE <= value
$SCORE < value
```

For WAF rule generation, the most common pattern is:

```nginx
CheckRule "$SCORE >= THRESHOLD" BLOCK;
```

## 3.6 `BLOCK` and `LearningMode`

> **Important:** `BLOCK` behaves as enforcement only when `LearningMode` is not enabled. In `LearningMode`, normal `BLOCK` actions are interpreted as `LOG`.

Example tuning mode:

```nginx
location / {
    SecRulesEnabled;
    LearningMode;
    DeniedUrl "/RequestDenied";

    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$XSS >= 8" BLOCK;
}
```

In this mode, normal `$SQL` and `$XSS` blocking events are logged rather than blocked.

## 3.7 Baseline Score Thresholds for Naxsi Core Rules

When using the basic Naxsi global rule set, include these `CheckRule` directives:

```nginx
CheckRule "$SQL >= 8" BLOCK;
CheckRule "$RFI >= 8" BLOCK;
CheckRule "$TRAVERSAL >= 5" BLOCK;
CheckRule "$UPLOAD >= 5" BLOCK;
CheckRule "$XSS >= 8" BLOCK;
CheckRule "$UWA >= 8" BLOCK;
CheckRule "$EVADE >= 8" BLOCK;
```

## 3.8 Libinjection CheckRules

If `LibInjectionXss` is enabled, include:

```nginx
CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
```

If `LibInjectionSql` is enabled, include:

```nginx
CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
```

## 3.9 CheckRule Selection Matrix

| Attack or score category | Score | Baseline `CheckRule` |
|---|---|---|
| SQL injection | `$SQL` | `CheckRule "$SQL >= 8" BLOCK;` |
| XSS | `$XSS` | `CheckRule "$XSS >= 8" BLOCK;` |
| Remote File Inclusion | `$RFI` | `CheckRule "$RFI >= 8" BLOCK;` |
| Traversal / LFI | `$TRAVERSAL` | `CheckRule "$TRAVERSAL >= 5" BLOCK;` |
| Upload abuse | `$UPLOAD` | `CheckRule "$UPLOAD >= 5" BLOCK;` |
| Unwanted access / scanner | `$UWA` | `CheckRule "$UWA >= 8" BLOCK;` |
| Evasion | `$EVADE` | `CheckRule "$EVADE >= 8" BLOCK;` |
| libinjection SQLi | `$LIBINJECTION_SQL` | `CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;` |
| libinjection XSS | `$LIBINJECTION_XSS` | `CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;` |

## 3.10 CheckRule Checklist

- [ ] Define a `CheckRule` for every score family used by rules.
- [ ] Start score variables with `$`.
- [ ] Use `BLOCK` for normal enforcement.
- [ ] Use `LOG` or `LearningMode` for tuning.
- [ ] Use `DROP` only for high-confidence severe conditions.
- [ ] If using `$LIBINJECTION_SQL`, enable `LibInjectionSql`.
- [ ] If using `$LIBINJECTION_XSS`, enable `LibInjectionXss`.
- [ ] Include `DeniedUrl` for blocking or logging redirect handling.
- [ ] Test configuration with `nginx -t`.

---

# 4. `LibInjectionXss`

## 4.1 Directive Identity

| Field | Value |
|---|---|
| Directive | `LibInjectionXss` |
| NGINX block | `location` |
| Main use | Enable libinjection XSS detection on all requests in the location |
| Score increment | `$LIBINJECTION_XSS += 1` for each match |
| Required companion directive | `CheckRule "$LIBINJECTION_XSS >= <threshold>" BLOCK;` |

## 4.2 Definition

When `LibInjectionXss` is defined, Naxsi enables libinjection XSS detection on all requests for that location.

Example:

```nginx
location / {
    # enable libinjection xss
    LibInjectionXss;

    # define LIBINJECTION_XSS for libinjection
    CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
}
```

## 4.3 Important Score Behavior

Detected XSS increases:

```text
$LIBINJECTION_XSS
```

by:

```text
1
```

for each match.

This means `LibInjectionXss` alone does not define an enforcement decision. Naxsi still needs a matching `CheckRule`.

## 4.4 Correct XSS Libinjection Configuration

```nginx
location / {
    SecRulesEnabled;
    LibInjectionXss;
    DeniedUrl "/RequestDenied";

    CheckRule "$XSS >= 8" BLOCK;
    CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
}
```

## 4.5 Strict XSS Libinjection Configuration

Use only after false-positive testing:

```nginx
location / {
    SecRulesEnabled;
    LibInjectionXss;
    DeniedUrl "/RequestDenied";

    CheckRule "$LIBINJECTION_XSS >= 1" BLOCK;
}
```

Reason:

- The source states each libinjection XSS match increments `$LIBINJECTION_XSS` by `1`.
- A threshold of `1` blocks a single libinjection XSS hit.
- A threshold of `8` follows the example baseline but may require accumulated score behavior.

## 4.6 Rule-Generation Use

Use `LibInjectionXss` when the attack type is:

```text
XSS
cross-site scripting
script tag
onerror
onload
javascript:
HTML injection
```

Recommended generated answer should include:

```nginx
LibInjectionXss;
CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
```

and, if core rules are also included:

```nginx
CheckRule "$XSS >= 8" BLOCK;
```

## 4.7 Common Mistake

Incorrect:

```nginx
location / {
    SecRulesEnabled;
    LibInjectionXss;
    CheckRule "$XSS >= 8" BLOCK;
}
```

Correct:

```nginx
location / {
    SecRulesEnabled;
    LibInjectionXss;
    CheckRule "$XSS >= 8" BLOCK;
    CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
}
```

Reason:

```text
$XSS and $LIBINJECTION_XSS are separate score variables.
```

---

# 5. `LibInjectionSql`

## 5.1 Directive Identity

| Field | Value |
|---|---|
| Directive | `LibInjectionSql` |
| NGINX block | `location` |
| Main use | Enable libinjection SQLi detection on all requests in the location |
| Score increment | `$LIBINJECTION_SQL += 1` for each match |
| Required companion directive | `CheckRule "$LIBINJECTION_SQL >= <threshold>" BLOCK;` |

## 5.2 Definition

When `LibInjectionSql` is defined, Naxsi enables libinjection SQL injection detection on all requests for that location.

Example:

```nginx
location / {
    # enable libinjection sqli
    LibInjectionSql;

    # define LIBINJECTION_SQL for libinjection
    CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
}
```

## 5.3 Important Score Behavior

Detected SQLi increases:

```text
$LIBINJECTION_SQL
```

by:

```text
1
```

for each match.

This means `LibInjectionSql` alone does not define an enforcement decision. Naxsi still needs a matching `CheckRule`.

## 5.4 Correct SQLi Libinjection Configuration

```nginx
location / {
    SecRulesEnabled;
    LibInjectionSql;
    DeniedUrl "/RequestDenied";

    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
}
```

## 5.5 Strict SQLi Libinjection Configuration

Use only after false-positive testing:

```nginx
location / {
    SecRulesEnabled;
    LibInjectionSql;
    DeniedUrl "/RequestDenied";

    CheckRule "$LIBINJECTION_SQL >= 1" BLOCK;
}
```

Reason:

- The source states each libinjection SQLi match increments `$LIBINJECTION_SQL` by `1`.
- A threshold of `1` blocks a single libinjection SQLi hit.
- A threshold of `8` follows the example baseline but may require accumulated score behavior.

## 5.6 Rule-Generation Use

Use `LibInjectionSql` when the attack type is:

```text
SQL injection
SQLi
union select
or 1=1
sleep(
benchmark(
information_schema
```

Recommended generated answer should include:

```nginx
LibInjectionSql;
CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
```

and, if core rules are also included:

```nginx
CheckRule "$SQL >= 8" BLOCK;
```

## 5.7 Common Mistake

Incorrect:

```nginx
location / {
    SecRulesEnabled;
    LibInjectionSql;
    CheckRule "$SQL >= 8" BLOCK;
}
```

Correct:

```nginx
location / {
    SecRulesEnabled;
    LibInjectionSql;
    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
}
```

Reason:

```text
$SQL and $LIBINJECTION_SQL are separate score variables.
```

---

# 6. `LearningMode`

## 6.1 Directive Identity

| Field | Value |
|---|---|
| Directive | `LearningMode` |
| NGINX block | `location` |
| Main use | Tune false positives by logging normal `BLOCK` actions instead of blocking |
| Applies to | `CheckRule` actions defined as `BLOCK` |
| Important exception | Internal rules with IDs below `1000` may still drop requests |

## 6.2 Definition

`LearningMode` instructs Naxsi not to honor `CheckRule` actions that define `BLOCK` in the current `location`.

All normal `BLOCK` actions are interpreted as:

```text
LOG
```

Example:

```nginx
location / {
    # enable Naxsi learning mode
    LearningMode;
}
```

## 6.3 Full LearningMode Example

```nginx
location / {
    SecRulesEnabled;
    LearningMode;
    DeniedUrl "/RequestDenied";

    LibInjectionSql;
    LibInjectionXss;

    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$XSS >= 8" BLOCK;
    CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
    CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
}
```

## 6.4 When to Use LearningMode

Use `LearningMode` when:

- deploying Naxsi to a new web application
- enabling new global rules
- enabling new location-specific rules
- enabling libinjection SQLi or XSS for the first time
- identifying false positives
- designing `MainRule` or `BasicRule` whitelists
- reviewing whether `$SQL`, `$XSS`, `$RFI`, `$TRAVERSAL`, `$UPLOAD`, `$UWA`, or `$EVADE` thresholds are too strict

## 6.5 Internal Rule Exception

> **Important:** Internal rules with IDs lower than `1000` may still drop the request even in `LearningMode`, because these internal rules indicate that Naxsi cannot correctly process the request or something abnormal is happening.

Examples of internal rules that can matter in learning mode:

```text
11 - Uncommon Content Type
15 - Malformed JSON
19 - No Rules Loaded
20 - Malformed UTF-8
21 - Illegal Host in Header
```

Whitelists can be applied if those are confirmed false positives.

## 6.6 LearningMode Generation Warning

Do not claim:

```text
LearningMode disables all blocking.
```

Correct statement:

```text
LearningMode converts normal CheckRule BLOCK actions to LOG, but Naxsi internal rules below ID 1000 may still drop/block abnormal requests.
```

## 6.7 Tuning Workflow

1. Enable `LearningMode`.
2. Enable JSON logs if available:

```nginx
set $naxsi_json_log 1;
```

3. Generate representative normal traffic.
4. Review Naxsi logs for rule ID, score, URL, parameter, body, and header match zones.
5. Create narrow whitelists.
6. Re-test malicious payloads.
7. Disable `LearningMode` only after expected traffic is clean.

---

# 7. `DeniedUrl`

## 7.1 Directive Identity

| Field | Value |
|---|---|
| Directive | `DeniedUrl` |
| NGINX block | `location` |
| Main use | Define where Naxsi internally redirects when blocking, dropping, or logging requests |
| Security recommendation | The denied location should be marked `internal` |

## 7.2 Definition

`DeniedUrl` defines the NGINX internal redirect destination used when Naxsi blocks, drops, or logs requests.

Example:

```nginx
location / {
    DeniedUrl "/RequestDenied";
}
```

The target should be implemented as a separate NGINX location:

```nginx
location /RequestDenied {
    internal;
    return 403;
}
```

## 7.3 Headers Added by Naxsi

When blocking, dropping, or logging requests, Naxsi adds the following headers:

```text
x-orig_url
x-orig_args
x-naxsi_sig
```

These headers are useful for internal handling and diagnostics.

## 7.4 Internal Location Requirement

> **Tip:** Mark the `DeniedUrl` location as `internal` to prevent possible pre-detection of the WAF.

Correct:

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

Reason:

```text
If the denied location is externally reachable, attackers may fingerprint or pre-detect WAF behavior.
```

## 7.5 Complete DeniedUrl Pattern

```nginx
server {
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

## 7.6 DeniedUrl Checklist

- [ ] Define `DeniedUrl` inside the protected `location`.
- [ ] Define the corresponding NGINX location.
- [ ] Mark the denied location as `internal`.
- [ ] Return a generic response such as `403`.
- [ ] Do not expose Naxsi signature data to end users.
- [ ] Use logs for diagnostics instead of verbose user-facing error content.

---

# 8. `MainRule`

## 8.1 Directive Identity

| Field | Value |
|---|---|
| Directive | `MainRule` |
| NGINX block | `http` |
| Main use | Declare a global rule or global whitelist |
| Common deployment | Put global rules in a separate config file and include it in `http` |

## 8.2 Definition

`MainRule` declares a global Naxsi rule or whitelist.

It belongs in the NGINX `http` block.

Example:

```nginx
http {
    # global whitelist
    MainRule wl:12345 "mz:$URL:/robots.txt|URL";

    # global rule
    MainRule id:45678 "s:$UWA:8" "str:nmap" "mz:$HEADERS_VAR:User-Agent" "msg:nmap in user-agent";
}
```

## 8.3 Global Whitelist

A global whitelist uses:

```nginx
MainRule wl:<RULE_ID> "mz:<MATCH_ZONE>";
```

Example:

```nginx
MainRule wl:12345 "mz:$URL:/robots.txt|URL";
```

Meaning:

- Whitelist rule ID `12345`.
- Apply globally.
- Scope to `/robots.txt` and `URL` match zone.

## 8.4 Global Rule

A global rule uses:

```nginx
MainRule id:<ID> "s:$SCORE:<POINTS>" "<MATCH_PATTERN>" "mz:<MATCH_ZONE>" "msg:<MESSAGE>";
```

Example scanner rule:

```nginx
MainRule id:45678 "s:$UWA:8" "str:nmap" "mz:$HEADERS_VAR:User-Agent" "msg:nmap in user-agent";
```

Meaning:

- Rule ID: `45678`.
- Increment `$UWA` by `8`.
- Match literal string `nmap`.
- Inspect `User-Agent` header.
- Log message: `nmap in user-agent`.

Required `CheckRule`:

```nginx
CheckRule "$UWA >= 8" BLOCK;
```

inside the protected `location`.

## 8.5 Include Pattern for Global Rules

The source recommends defining global rules in a config file and using `include`.

Example:

```nginx
http {
    include /etc/nginx/naxsi/naxsi_core.rules;
    include /etc/nginx/naxsi/global_custom_rules.conf;

    server {
        location / {
            SecRulesEnabled;
            DeniedUrl "/RequestDenied";
            CheckRule "$UWA >= 8" BLOCK;
        }
    }
}
```

## 8.6 Required CheckRules for Naxsi Source Global Rules

The Naxsi source code includes a list of global rules providing a basic ruleset. Those rules require these `CheckRule` directives:

```nginx
CheckRule "$SQL >= 8" BLOCK;
CheckRule "$RFI >= 8" BLOCK;
CheckRule "$TRAVERSAL >= 5" BLOCK;
CheckRule "$UPLOAD >= 5" BLOCK;
CheckRule "$XSS >= 8" BLOCK;
CheckRule "$UWA >= 8" BLOCK;
CheckRule "$EVADE >= 8" BLOCK;
```

## 8.7 MainRule Generation Checklist

- [ ] Use `MainRule` only in `http`.
- [ ] Use `MainRule` for global rules or global whitelists.
- [ ] Prefer `BasicRule` for endpoint-specific whitelists.
- [ ] Use custom IDs greater than or equal to `1000`.
- [ ] Define matching `CheckRule` in protected locations for the score used by the `MainRule`.
- [ ] Use `include` for maintainability.
- [ ] Avoid broad global whitelists unless justified.

---

# 9. `BasicRule`

## 9.1 Directive Identity

| Field | Value |
|---|---|
| Directive | `BasicRule` |
| NGINX block | `location` |
| Main use | Declare a location-specific rule or whitelist |
| Common deployment | Put location-specific rules or whitelists in a file and include it in a protected `location` |

## 9.2 Definition

`BasicRule` declares a location-specific Naxsi rule or whitelist.

It belongs in a `location` block.

Example:

```nginx
location / {
    # location-specific whitelist
    BasicRule wl:12345 "mz:$URL:/robots.txt|URL";

    # location-specific rule
    BasicRule id:45678 "s:$UWA:8" "str:nmap" "mz:$HEADERS_VAR:User-Agent" "msg:nmap in user-agent";
}
```

## 9.3 Location-Specific Whitelist

A `BasicRule` whitelist uses:

```nginx
BasicRule wl:<RULE_ID> "mz:<MATCH_ZONE>";
```

Example:

```nginx
BasicRule wl:12345 "mz:$URL:/robots.txt|URL";
```

Use this when the whitelist should apply only to one `location`.

## 9.4 Location-Specific Rule

A `BasicRule` detection rule uses:

```nginx
BasicRule id:<ID> "s:$SCORE:<POINTS>" "<MATCH_PATTERN>" "mz:<MATCH_ZONE>" "msg:<MESSAGE>";
```

Example scanner detection rule:

```nginx
BasicRule id:45678 "s:$UWA:8" "str:nmap" "mz:$HEADERS_VAR:User-Agent" "msg:nmap in user-agent";
```

Required `CheckRule`:

```nginx
CheckRule "$UWA >= 8" BLOCK;
```

## 9.5 Include Pattern for Location-Specific Rules

The source recommends defining these rules in a config file and using `include`.

Example:

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    include /etc/nginx/naxsi/location_custom_rules.conf;

    CheckRule "$UWA >= 8" BLOCK;
}
```

## 9.6 Known Application Whitelist Use Case

The Naxsi source code contains location-specific whitelists for known web applications such as:

```text
WordPress
Etherpad
Drupal
```

Use this concept when tuning known false positives for common applications.

## 9.7 BasicRule vs MainRule

| Need | Use |
|---|---|
| Global rule across all protected locations | `MainRule` |
| Global whitelist across all protected locations | `MainRule` |
| Location-specific rule | `BasicRule` |
| Location-specific whitelist | `BasicRule` |
| Narrow false-positive exception for one endpoint | `BasicRule` |
| Known application-specific whitelist in one location | `BasicRule` |

## 9.8 BasicRule Generation Checklist

- [ ] Use `BasicRule` in `location`, not `http`.
- [ ] Use custom IDs greater than or equal to `1000`.
- [ ] Use `wl:<id>` for whitelists.
- [ ] Use `id:<id>` for detection rules.
- [ ] Define matching `CheckRule` for the score used.
- [ ] Scope match zones narrowly.
- [ ] Prefer `BasicRule` over `MainRule` for false-positive tuning.

---

# 10. `IgnoreIP`

## 10.1 Directive Identity

| Field | Value |
|---|---|
| Directive | `IgnoreIP` |
| NGINX block | `location` |
| Main use | Whitelist requests from a specific IP address |
| Supports | IPv4 and IPv6 single addresses |

## 10.2 Definition

`IgnoreIP` whitelists requests from specified source IP addresses.

Example:

```nginx
location / {
    IgnoreIP "1.2.3.4";
    IgnoreIP "2001:4860:4860::8844";
}
```

## 10.3 Rule-Generation Use

Use `IgnoreIP` for:

- trusted internal scanner IPs
- internal monitoring systems
- known backend health checks
- temporary emergency bypass for one source IP
- trusted administrative source addresses

## 10.4 Security Warning

`IgnoreIP` bypasses Naxsi checks for requests from that IP.

Use only when:

- the IP is trusted
- the IP is stable
- the business reason is documented
- the exception is reviewed
- it is not a broad public address
- it is not a user-controlled header value

## 10.5 IgnoreIP Example with Protected Location

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    IgnoreIP "1.2.3.4";

    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$XSS >= 8" BLOCK;
}
```

## 10.6 IgnoreIP Checklist

- [ ] Use only inside `location`.
- [ ] Use a literal trusted IPv4 or IPv6 address.
- [ ] Do not use for broad ranges; use `IgnoreCIDR` instead.
- [ ] Do not trust `X-Forwarded-For` unless NGINX real IP handling is correctly configured.
- [ ] Document why the IP is trusted.
- [ ] Review periodically.

---

# 11. `IgnoreCIDR`

## 11.1 Directive Identity

| Field | Value |
|---|---|
| Directive | `IgnoreCIDR` |
| NGINX block | `location` |
| Main use | Whitelist requests from an IP range |
| Supports | IPv4 and IPv6 CIDR ranges |

## 11.2 Definition

`IgnoreCIDR` whitelists requests from specified IP ranges.

Example:

```nginx
location / {
    IgnoreCIDR "192.168.0.0/24";
    IgnoreCIDR "2001:4860:4860::/112";
}
```

## 11.3 Rule-Generation Use

Use `IgnoreCIDR` for:

- office networks
- internal private networks
- trusted scanner subnets
- controlled VPN address ranges
- internal service ranges

## 11.4 Security Warning

`IgnoreCIDR` is broader than `IgnoreIP`.

Use only when:

- the range is controlled
- all hosts in the range are trusted
- source IP resolution is accurate
- the exception is not exposed to arbitrary clients
- the range is reviewed periodically

## 11.5 IgnoreCIDR Example with Protected Location

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    IgnoreCIDR "192.168.0.0/24";

    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$XSS >= 8" BLOCK;
}
```

## 11.6 IgnoreCIDR Checklist

- [ ] Use only inside `location`.
- [ ] Use the narrowest possible CIDR.
- [ ] Avoid broad public ranges.
- [ ] Do not use for application users unless the trust boundary is clear.
- [ ] Confirm real client IP handling if behind a proxy or load balancer.
- [ ] Prefer `IgnoreIP` if only one IP needs allowlisting.

---

# 12. Complete Directive Reference Table

| Directive | Scope | Required for protection? | Typical pairings | Main generation risk |
|---|---|---:|---|---|
| `SecRulesEnabled` | `location` | Yes | `DeniedUrl`, `CheckRule`, rules | Missing it means Naxsi is not enabled. |
| `CheckRule` | `location` | Yes for score enforcement | score-producing rules, libinjection, `DeniedUrl` | Missing score variables or missing `$`. |
| `LibInjectionXss` | `location` | Optional | `$LIBINJECTION_XSS` `CheckRule` | Enabling without CheckRule means detections may not block. |
| `LibInjectionSql` | `location` | Optional | `$LIBINJECTION_SQL` `CheckRule` | Enabling without CheckRule means detections may not block. |
| `LearningMode` | `location` | Optional | JSON logs, whitelists | Mistakenly assuming all internal drops stop. |
| `DeniedUrl` | `location` | Strongly recommended | internal denied location | Exposing denied location externally. |
| `MainRule` | `http` | If using global rules | `include`, matching `CheckRule` | Placing in wrong scope or using broad whitelist. |
| `BasicRule` | `location` | If using local rules | `CheckRule`, `SecRulesEnabled` | Missing CheckRule or broad whitelist. |
| `IgnoreIP` | `location` | Optional | trusted single source | Overtrusting one IP or incorrect real IP setup. |
| `IgnoreCIDR` | `location` | Optional | trusted network ranges | Overbroad bypass of WAF checks. |

---

# 13. Complete Baseline Naxsi Configuration Using Directives

## 13.1 Baseline Production Configuration

```nginx
load_module /etc/nginx/modules/ngx_http_naxsi_module.so;

http {
    include /etc/nginx/naxsi/naxsi_core.rules;

    server {
        listen 80;
        server_name example.com;

        set $naxsi_json_log 1;

        location / {
            SecRulesEnabled;

            DeniedUrl "/RequestDenied";

            LibInjectionSql;
            LibInjectionXss;

            CheckRule "$SQL >= 8" BLOCK;
            CheckRule "$RFI >= 8" BLOCK;
            CheckRule "$TRAVERSAL >= 5" BLOCK;
            CheckRule "$UPLOAD >= 5" BLOCK;
            CheckRule "$XSS >= 8" BLOCK;
            CheckRule "$UWA >= 8" BLOCK;
            CheckRule "$EVADE >= 8" BLOCK;
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

## 13.2 Tuning Configuration with LearningMode

```nginx
load_module /etc/nginx/modules/ngx_http_naxsi_module.so;

http {
    include /etc/nginx/naxsi/naxsi_core.rules;

    server {
        listen 80;
        server_name example.com;

        set $naxsi_json_log 1;

        location / {
            SecRulesEnabled;
            LearningMode;

            DeniedUrl "/RequestDenied";

            LibInjectionSql;
            LibInjectionXss;

            CheckRule "$SQL >= 8" BLOCK;
            CheckRule "$RFI >= 8" BLOCK;
            CheckRule "$TRAVERSAL >= 5" BLOCK;
            CheckRule "$UPLOAD >= 5" BLOCK;
            CheckRule "$XSS >= 8" BLOCK;
            CheckRule "$UWA >= 8" BLOCK;
            CheckRule "$EVADE >= 8" BLOCK;
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

## 13.3 Validation Command

Always validate configuration before reload:

```bash
nginx -t
```

Reload only if syntax validation succeeds.

---

# 14. Attack-Specific Generation Patterns

## 14.1 XSS Configuration Pattern

Use when attack type is:

```text
XSS
cross-site scripting
script tag
onerror
onload
javascript:
HTML injection
```

Recommended directives:

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    LibInjectionXss;

    BasicRule id:500100 "s:$XSS:8" "rx:<\s*script|onerror\s*=|onload\s*=|javascript:" "mz:ARGS|BODY|HEADERS" "msg:custom XSS indicators";

    CheckRule "$XSS >= 8" BLOCK;
    CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
}
```

Why:

- `SecRulesEnabled` turns on Naxsi.
- `LibInjectionXss` adds libinjection XSS detection.
- `BasicRule` adds explicit custom XSS score.
- `$XSS` enforces custom/core XSS rules.
- `$LIBINJECTION_XSS` enforces libinjection XSS score.
- `DeniedUrl` handles blocked request routing.

## 14.2 SQL Injection Configuration Pattern

Use when attack type is:

```text
SQL injection
SQLi
union select
or 1=1
sleep(
benchmark(
information_schema
```

Recommended directives:

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    LibInjectionSql;

    BasicRule id:500200 "s:$SQL:8" "rx:union\s+select|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(" "mz:ARGS|BODY" "msg:custom SQLi indicators";

    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
}
```

Why:

- `LibInjectionSql` enables libinjection SQLi detection.
- `$LIBINJECTION_SQL` CheckRule is required.
- Custom `BasicRule` increases `$SQL`.
- `$SQL` CheckRule enforces core/custom SQLi scores.

## 14.3 Scanner User-Agent Pattern

Use when attack type is scanner, bot, or unwanted access:

```nginx
http {
    MainRule id:500300 "s:$UWA:8" "str:nmap" "mz:$HEADERS_VAR:User-Agent" "msg:nmap in user-agent";

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

Alternative with regex and location-specific `BasicRule`:

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule id:500301 "s:$UWA:8" "rx:sqlmap|nikto|acunetix|nmap|nuclei" "mz:$HEADERS_VAR:User-Agent" "msg:known scanner user-agent";

    CheckRule "$UWA >= 8" BLOCK;
}
```

## 14.4 Trusted Scanner IP Allowlist Pattern

Use `IgnoreIP` for a specific trusted scanner:

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    IgnoreIP "1.2.3.4";

    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$XSS >= 8" BLOCK;
}
```

Use `IgnoreCIDR` for a trusted scanner subnet:

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    IgnoreCIDR "192.168.0.0/24";

    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$XSS >= 8" BLOCK;
}
```

Security note:

```text
IgnoreIP and IgnoreCIDR bypass Naxsi checks for matching source addresses. Use only for trusted and controlled sources.
```

---

# 15. Whitelist Generation Patterns

## 15.1 Global Whitelist with MainRule

Use when the false positive occurs globally and safely across the application.

```nginx
http {
    MainRule wl:12345 "mz:$URL:/robots.txt|URL";
}
```

Use sparingly.

## 15.2 Location-Specific Whitelist with BasicRule

Use when the false positive occurs only in one location.

```nginx
location / {
    BasicRule wl:12345 "mz:$URL:/robots.txt|URL";
}
```

Prefer `BasicRule` for most false-positive tuning.

## 15.3 Parameter-Specific Whitelist

Example:

```nginx
location /search {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    BasicRule wl:1000 "mz:$URL:/search|$ARGS_VAR:q";

    CheckRule "$XSS >= 8" BLOCK;
}
```

Use when:

- one parameter legitimately triggers a Naxsi rule
- the exception should not apply globally
- the endpoint is known and tested

## 15.4 Internal Rule Whitelist Reminder

Internal rule IDs below `1000` can be whitelisted if false positives are confirmed.

Example malformed JSON exception:

```nginx
BasicRule wl:15 "mz:$URL:/api/legacy-json|BODY";
```

Do not create a custom rule with ID `15`.

---

# 16. Common Mistakes and Corrections

## 16.1 Missing `SecRulesEnabled`

Incorrect:

```nginx
location / {
    CheckRule "$SQL >= 8" BLOCK;
}
```

Correct:

```nginx
location / {
    SecRulesEnabled;
    CheckRule "$SQL >= 8" BLOCK;
}
```

## 16.2 Missing `$` in Score Variable

Incorrect:

```nginx
CheckRule "SQL >= 8" BLOCK;
```

Correct:

```nginx
CheckRule "$SQL >= 8" BLOCK;
```

## 16.3 Enabling LibInjection Without Matching CheckRule

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

## 16.4 Placing `MainRule` in `location`

Incorrect:

```nginx
location / {
    MainRule id:45678 "s:$UWA:8" "str:nmap" "mz:$HEADERS_VAR:User-Agent" "msg:nmap in user-agent";
}
```

Correct:

```nginx
http {
    MainRule id:45678 "s:$UWA:8" "str:nmap" "mz:$HEADERS_VAR:User-Agent" "msg:nmap in user-agent";
}
```

## 16.5 Placing `BasicRule` in `http`

Incorrect:

```nginx
http {
    BasicRule id:45678 "s:$UWA:8" "str:nmap" "mz:$HEADERS_VAR:User-Agent" "msg:nmap in user-agent";
}
```

Correct:

```nginx
location / {
    BasicRule id:45678 "s:$UWA:8" "str:nmap" "mz:$HEADERS_VAR:User-Agent" "msg:nmap in user-agent";
}
```

## 16.6 Exposing DeniedUrl

Risky:

```nginx
location /RequestDenied {
    return 403;
}
```

Correct:

```nginx
location /RequestDenied {
    internal;
    return 403;
}
```

## 16.7 Assuming LearningMode Stops Internal Drops

Incorrect assumption:

```text
LearningMode prevents all blocking and dropping.
```

Correct:

```text
LearningMode converts normal CheckRule BLOCK actions to LOG, but internal rules with IDs below 1000 may still drop abnormal requests.
```

## 16.8 Overbroad IP Allowlist

Risky:

```nginx
IgnoreCIDR "0.0.0.0/0";
```

Better:

```nginx
IgnoreIP "1.2.3.4";
```

or a narrow controlled CIDR:

```nginx
IgnoreCIDR "192.168.0.0/24";
```

---

# 17. Output Templates for LLM Rule Generation

## 17.1 Naxsi Rule Generation Template

```markdown
## Rule Objective

- WAF: Naxsi
- Attack type:
- Payload location:
- Desired action:
- Deployment mode: blocking or learning

## Proposed Naxsi Configuration

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    # directives and rules here

    CheckRule "$SCORE >= THRESHOLD" BLOCK;
}

location /RequestDenied {
    internal;
    return 403;
}
```

## Why This Configuration Works

Explain:
- why `SecRulesEnabled` is required
- which directive detects the attack
- which score is incremented
- which `CheckRule` enforces the score
- how `DeniedUrl` handles block/drop/log flow

## False Positives and Tuning

Explain:
- whether `LearningMode` should be used first
- which `BasicRule wl:<id>` whitelist could be used
- why broad whitelists or broad IP ignores are risky
```

## 17.2 Libinjection Output Template

```markdown
## Rule Objective

- Attack type: XSS or SQLi
- Detection source: libinjection
- Score variable:
- Enforcement threshold:

## Proposed Configuration

```nginx
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";

    LibInjectionSql;
    LibInjectionXss;

    CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;
    CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
}

location /RequestDenied {
    internal;
    return 403;
}
```

## Why This Works

- `LibInjectionSql` increments `$LIBINJECTION_SQL` by `1` for each SQLi match.
- `LibInjectionXss` increments `$LIBINJECTION_XSS` by `1` for each XSS match.
- `CheckRule` is required to convert scores into actions.
- `LearningMode` should be used first if false positives are unknown.
```

## 17.3 Whitelist Output Template

```markdown
## False Positive Context

- Rule ID:
- Match zone:
- URL:
- Parameter/header/body field:
- Why this is legitimate:

## Proposed Narrow Whitelist

```nginx
location / {
    BasicRule wl:<RULE_ID> "mz:<MATCH_ZONE>";
}
```

## Safety Notes

- Prefer `BasicRule` over `MainRule` for endpoint-specific tuning.
- Do not whitelist globally unless the exception is truly global.
- Re-test malicious payloads after adding the whitelist.
```

---

# 18. Retrieval Keywords

## 18.1 Directive Keywords

```text
Naxsi directives
SecRulesEnabled
CheckRule
LibInjectionXss
LibInjectionSql
LearningMode
DeniedUrl
MainRule
BasicRule
IgnoreIP
IgnoreCIDR
ngx_http_naxsi_module.so
location block
http block
```

## 18.2 Score and Action Keywords

```text
$SQL
$RFI
$TRAVERSAL
$UPLOAD
$XSS
$UWA
$EVADE
$LIBINJECTION_SQL
$LIBINJECTION_XSS
LOG
BLOCK
DROP
ALLOW
score variable
dollar sign
underscore
```

## 18.3 Rule Syntax Keywords

```text
MainRule id
MainRule wl
BasicRule id
BasicRule wl
s:$UWA:8
str:nmap
rx:
mz:$HEADERS_VAR:User-Agent
mz:$URL:/robots.txt|URL
msg:
global rule
global whitelist
location-specific rule
location-specific whitelist
```

## 18.4 Attack Keywords

```text
XSS
cross-site scripting
SQL injection
SQLi
libinjection xss
libinjection sqli
scanner
nmap
user-agent
trusted IP
trusted CIDR
false positive
whitelist
learning mode
```

---

# 19. Final Checklist for Naxsi Directive-Aware Generation

- [ ] Put `SecRulesEnabled` in `location`.
- [ ] Put `CheckRule` in `location`.
- [ ] Put `LibInjectionXss` in `location`.
- [ ] Put `LibInjectionSql` in `location`.
- [ ] Put `LearningMode` in `location`.
- [ ] Put `DeniedUrl` in `location`.
- [ ] Put `MainRule` in `http`.
- [ ] Put `BasicRule` in `location`.
- [ ] Put `IgnoreIP` in `location`.
- [ ] Put `IgnoreCIDR` in `location`.
- [ ] Use `$` at the start of score variable names.
- [ ] Include `$LIBINJECTION_XSS` CheckRule when `LibInjectionXss` is enabled.
- [ ] Include `$LIBINJECTION_SQL` CheckRule when `LibInjectionSql` is enabled.
- [ ] Include `DeniedUrl` and an internal denied location for blocking flows.
- [ ] Use `LearningMode` during first deployment or false-positive tuning.
- [ ] Mention that internal rules below `1000` may still drop in learning mode.
- [ ] Use `MainRule` for global rules/whitelists only.
- [ ] Use `BasicRule` for location-specific rules/whitelists.
- [ ] Prefer narrow whitelists over global whitelists.
- [ ] Use `IgnoreIP` or `IgnoreCIDR` only for trusted source addresses.
- [ ] Validate with `nginx -t` before reload.
