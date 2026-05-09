# Cloudflare Ruleset Engine Actions Knowledge Base for WAF Rule Generation
# 1. Cloudflare Ruleset Engine Core Model

## 1.1 Rule Definition

A Cloudflare Ruleset Engine rule contains two essential parts:

| Rule part | Purpose |
|---|---|
| `expression` | Defines which incoming requests match. Expressions are written in the Cloudflare Rules language. |
| `action` | Defines what Cloudflare does when the request matches the expression. |

A rule can also include:

- `description`
- `enabled`
- `action_parameters`
- `logging`
- phase-specific options
- product-specific configuration

## 1.2 Rule Expression

A rule expression defines the request-matching condition.

Simple expression syntax:

```text
<field> <comparison_operator> <value>
```

Example:

```text
http.request.uri.path contains "/admin"
```

Compound expression syntax:

```text
<expression> <logical_operator> <expression>
```

Example:

```text
http.host eq "example.com" and http.request.uri.path contains "/admin"
```

Common logical operators:

| Operator | Meaning |
|---|---|
| `not` | Negation |
| `and` | Both expressions must be true |
| `xor` | Exactly one expression must be true |
| `or` | At least one expression must be true |

Rule expressions can use grouping symbols to enforce precedence.

Example:

```text
(http.request.uri.path contains "/login" or http.request.uri.path contains "/admin")
and not ip.src in {203.0.113.10 203.0.113.11}
```

## 1.3 Rule Action

The rule action determines how Cloudflare handles a request that matches the rule expression.

For WAF rule generation, the most important actions are:

| Action | API value | Primary rule-generation use |
|---|---|---|
| Block | `block` | Deny malicious requests. |
| Managed Challenge | `managed_challenge` | Challenge suspicious traffic with adaptive challenge selection. |
| Non-Interactive Challenge | `js_challenge` | Apply automatic browser challenge. |
| Interactive Challenge | `challenge` | Require a visible human challenge. |
| Skip | `skip` | Create controlled exceptions or bypass specific security evaluation. |
| Log | `log` | Validate rules before stronger enforcement. Enterprise only. |
| Execute | `execute` | Execute a managed or custom ruleset. |

Other actions exist, but most are not primary WAF attack-blocking actions.

---

# 2. Action Selection for WAF Rule Generation

## 2.1 Recommended Action Decision Matrix

| Goal | Recommended action | Reason |
|---|---|---|
| Block confirmed malicious XSS, SQLi, RCE, path traversal, or exploit traffic | `block` | Terminating security action that denies matched requests. |
| Validate a new rule without enforcement | `log` if available, otherwise use a low-impact deployment mode supported by the product | Records matches before committing to a stronger action. |
| Reduce bot/spam traffic with minimal friction | `managed_challenge` | Cloudflare dynamically selects challenge type. |
| Require automatic browser verification | `js_challenge` | Non-interactive challenge suitable for browser-like clients. |
| Require explicit human verification | `challenge` | Stronger friction for suspicious traffic. |
| Exempt trusted traffic from custom rules, managed rules, rate limiting, or other security products | `skip` | Creates a targeted exception. |
| Deploy a managed ruleset or custom ruleset | `execute` | Executes rules from another ruleset in the same phase. |
| Rewrite URI/header/request metadata | `rewrite` | Use only in Transform Rules or exposed-credential check contexts, not general attack blocking. |
| Redirect visitors | `redirect` | Use for routing/navigation policies, not primary WAF defense. |
| Change origin routing | `route` | Use in Origin Rules, not WAF custom rule generation. |
| Change product configuration | `set_config` | Use in Configuration Rules, not WAF custom rule generation. |
| Change caching or compression | `set_cache_settings`, `compress_response` | Not used for SQLi/XSS WAF rule generation. |

## 2.2 Terminating and Non-Terminating Actions

Some actions are terminating. A terminating action stops evaluation of remaining rules for that request in the relevant context.

| Action | API value | Terminating? | Rule-generation implication |
|---|---|---:|---|
| Block | `block` | Yes | Later rules do not evaluate after the request is blocked. |
| Managed Challenge | `managed_challenge` | Yes | If challenge succeeds, request proceeds; otherwise it is blocked. |
| Non-Interactive Challenge | `js_challenge` | Yes | Browser-compatible challenge flow; failed challenge blocks request. |
| Interactive Challenge | `challenge` | Yes | User must pass challenge; failed challenge blocks request. |
| Redirect | `redirect` | Yes | Request is redirected instead of continuing normally. |
| Serve Error | `serve_error` | Yes | Used for custom error rules, not primary WAF attack mitigation. |
| Log | `log` | No | Records a match and lets evaluation continue. |
| Execute | `execute` | No | Executes another ruleset; rules inside the executed ruleset can terminate. |
| Skip | `skip` | Not strictly terminating | Skips configured rules, phases, rulesets, or products. |
| Rewrite | `rewrite` | No | Modifies request or response according to rule configuration. |
| Route | `route` | No | Changes origin routing behavior. |
| Set Configuration | `set_config` | No | Changes supported product settings. |
| Compress Response | `compress_response` | No | Sets response compression behavior. |
| Set Cache Settings | `set_cache_settings` | No | Adjusts cache behavior. |

---

# 3. Cloudflare WAF Custom Rule Actions

## 3.1 Custom Rule Definition

Cloudflare WAF custom rules control incoming traffic by filtering requests to a zone. A custom rule has:

- an expression
- an action
- an optional description
- optional action parameters
- optional logging configuration

Custom rules run in the `http_request_firewall_custom` phase.

Custom rules are evaluated in order. If an earlier rule uses a terminating action such as `block`, later rules will not run for that request.

## 3.2 Custom Rule Generation Fields

When generating a Cloudflare WAF custom rule, include:

| Field | Required | Purpose |
|---|---:|---|
| `description` | Recommended | Human-readable rule objective. |
| `expression` | Yes | Matching condition. |
| `action` | Yes | Action to perform on match. |
| `action_parameters` | Conditional | Required for some actions such as custom block response, skip, execute, redirect, or rewrite. |
| `enabled` | Recommended | Whether the rule should execute. |
| `logging` | Optional | Can control logging for some actions such as skip. |

## 3.3 WAF Custom Rule API Pattern

```json
{
  "description": "Block XSS payloads in query string",
  "expression": "lower(http.request.uri.query) contains \"<script\" or lower(http.request.uri.query) contains \"onerror=\"",
  "action": "block",
  "enabled": true
}
```

## 3.4 WAF Custom Rule Phase

Custom rules must be deployed to the `http_request_firewall_custom` phase entry point ruleset.

When creating a zone-level custom rule via API:

1. Get the zone entry point ruleset for `http_request_firewall_custom`.
2. If it exists, add the rule to that ruleset.
3. If it does not exist, create the entry point ruleset.
4. Preserve rule order so allowlist or skip exceptions appear before broader block rules.

---

# 4. Block Action (`block`)

## 4.1 Definition

The `block` action denies matching requests. In most security products, the request is denied with an HTTP `403` response. For some products such as rate limiting, the response may be `429`.

The `block` action is terminating. If a rule blocks a request, later rules do not execute for that request in the relevant evaluation context.

## 4.2 When to Generate `block`

Generate `block` when:

- The payload is confirmed malicious.
- The expression is specific enough to avoid broad false positives.
- The request pattern is known to represent XSS, SQL injection, exploit probing, credential attack, automated abuse, or another security violation.
- The user explicitly asks for enforcement.
- The rule has already been validated using logs or testing.

## 4.3 When Not to Generate `block`

Avoid immediate `block` when:

- The rule expression is broad or experimental.
- The application may legitimately accept HTML, JavaScript, SQL-like strings, templates, code snippets, or unusual encoding.
- The action is being used for rule validation.
- A false positive could affect production users.
- A more appropriate response is challenge or skip.

## 4.4 Block Rule for XSS Indicators in Query String

```json
{
  "description": "Block reflected XSS indicators in query string",
  "expression": "lower(http.request.uri.query) contains \"<script\" or lower(http.request.uri.query) contains \"onerror=\" or lower(http.request.uri.query) contains \"javascript:\"",
  "action": "block",
  "enabled": true
}
```

## 4.5 Block Rule for URL-Encoded XSS Indicators

Cloudflare expressions inspect request fields available to the Ruleset Engine. When generating expressions for encoded payloads, include known encoded indicators if the documentation or observed traffic shows that encoded forms reach the expression unchanged.

```json
{
  "description": "Block URL-encoded XSS indicators in query string",
  "expression": "lower(http.request.uri.query) contains \"%3cscript\" or lower(http.request.uri.query) contains \"onerror%3d\" or lower(http.request.uri.query) contains \"javascript%3a\"",
  "action": "block",
  "enabled": true
}
```

## 4.6 Block Rule for SQL Injection Indicators

```json
{
  "description": "Block SQL injection indicators in query string",
  "expression": "lower(http.request.uri.query) contains \"union select\" or lower(http.request.uri.query) contains \"or 1=1\" or lower(http.request.uri.query) contains \"sleep(\" or lower(http.request.uri.query) contains \"benchmark(\"",
  "action": "block",
  "enabled": true
}
```

## 4.7 Block Action with Custom Response

For WAF custom rules on supported plans, the `block` action can include a custom response.

Custom response fields:

| Field | Purpose |
|---|---|
| `response.content_type` | Response content type. Supported values include `text/html`, `text/plain`, `application/json`, and `text/xml`. |
| `response.status_code` | HTTP response status code. Must be in the `400` to `499` range. Default is typically `403` for WAF block. |
| `response.content` | Response body. |

Example:

```json
{
  "description": "Block SQL injection indicators with JSON response",
  "expression": "lower(http.request.uri.query) contains \"union select\" or lower(http.request.uri.query) contains \"or 1=1\"",
  "action": "block",
  "action_parameters": {
    "response": {
      "status_code": 403,
      "content_type": "application/json",
      "content": "{\"error\":\"request blocked by WAF\"}"
    }
  },
  "enabled": true
}
```

## 4.8 Block Rule Generation Checklist

Before generating a `block` rule:

- [ ] The expression is specific enough for enforcement.
- [ ] The action is explicitly `block`.
- [ ] The expression uses relevant fields such as `http.request.uri.query`, `http.request.uri.path`, `http.request.body.raw`, `http.request.headers`, or `ip.src`.
- [ ] False-positive risk is stated.
- [ ] Rule ordering is considered.
- [ ] If custom response is used, status code is between `400` and `499`.
- [ ] If custom response is used, content type matches response body format.

---

# 5. Managed Challenge Action (`managed_challenge`)

## 5.1 Definition

The `managed_challenge` action challenges matching requests and lets Cloudflare dynamically choose the appropriate challenge type. It is recommended for reducing automated abuse while lowering unnecessary human CAPTCHA burden.

The action is terminating. If the client passes the challenge, Cloudflare accepts the request; otherwise, the request is blocked.

## 5.2 When to Generate `managed_challenge`

Use `managed_challenge` when:

- Traffic is suspicious but not confirmed malicious.
- Blocking may be too aggressive.
- Bot-like behavior is present.
- Requests target sensitive paths such as login, admin, checkout, or signup endpoints.
- The rule should reduce automated abuse while allowing legitimate browsers.

## 5.3 Managed Challenge Rule for Suspicious Login Traffic

```json
{
  "description": "Managed challenge suspicious login traffic",
  "expression": "http.request.uri.path contains \"/login\" and (cf.threat_score gt 20 or not cf.client.bot)",
  "action": "managed_challenge",
  "enabled": true
}
```

## 5.4 Managed Challenge Rule for Suspicious XSS Probing

```json
{
  "description": "Managed challenge suspicious XSS probing in query string",
  "expression": "lower(http.request.uri.query) contains \"<script\" or lower(http.request.uri.query) contains \"onerror=\" or lower(http.request.uri.query) contains \"javascript:\"",
  "action": "managed_challenge",
  "enabled": true
}
```

## 5.5 Managed Challenge Generation Checklist

- [ ] Use for suspicious or automated traffic, not confirmed critical attacks.
- [ ] Prefer `block` for confirmed malicious exploit payloads.
- [ ] Scope to sensitive endpoints if possible.
- [ ] Explain that the client must pass a challenge to proceed.
- [ ] Mention that failure results in blocking.

---

# 6. Non-Interactive Challenge Action (`js_challenge`)

## 6.1 Definition

The `js_challenge` action issues a non-interactive browser challenge. Browsers can satisfy the challenge automatically, while many bots and automated scripts cannot.

The action is terminating. If the challenge succeeds, the request proceeds. If it fails, the request is blocked.

## 6.2 When to Generate `js_challenge`

Use `js_challenge` when:

- The target traffic should normally come from real browsers.
- Automated clients are suspicious but not necessarily malicious.
- A lower-friction challenge is preferred over an interactive challenge.
- The application can tolerate browser challenge flow.

## 6.3 Non-Interactive Challenge Rule Example

```json
{
  "description": "Non-interactive challenge suspicious requests to search endpoint",
  "expression": "http.request.uri.path contains \"/search\" and lower(http.request.uri.query) contains \"<script\"",
  "action": "js_challenge",
  "enabled": true
}
```

## 6.4 Non-Interactive Challenge Generation Checklist

- [ ] Use when browser validation is appropriate.
- [ ] Avoid for API-only endpoints unless clients can handle the challenge.
- [ ] Prefer `block` for confirmed malicious payloads.
- [ ] Prefer `managed_challenge` when Cloudflare should choose the challenge type.

---

# 7. Interactive Challenge Action (`challenge`)

## 7.1 Definition

The `challenge` action requires the visitor to pass an interactive challenge. This action creates more friction than `managed_challenge` or `js_challenge`.

The action is terminating. If the user passes the challenge, the request proceeds. If not, the request is blocked.

## 7.2 When to Generate `challenge`

Use `challenge` when:

- Higher assurance of human interaction is required.
- Suspicious requests target high-risk resources.
- The user explicitly wants interactive verification.
- Automated abuse is likely but outright blocking is too aggressive.

## 7.3 Interactive Challenge Rule Example

```json
{
  "description": "Interactive challenge high-risk admin access",
  "expression": "http.request.uri.path contains \"/admin\" and not ip.src in {203.0.113.10 203.0.113.11}",
  "action": "challenge",
  "enabled": true
}
```

## 7.4 Interactive Challenge Generation Checklist

- [ ] Use only when user friction is acceptable.
- [ ] Avoid for APIs and machine clients.
- [ ] Prefer `managed_challenge` for adaptive challenge behavior.
- [ ] Scope narrowly to high-risk paths or suspicious traffic.

---

# 8. Log Action (`log`)

## 8.1 Definition

The `log` action records matching requests in Cloudflare Logs and does not terminate evaluation. It is available only on Enterprise plans.

The `log` action is recommended for validating a rule before using a more severe action such as `block`, `managed_challenge`, or `challenge`.

## 8.2 When to Generate `log`

Use `log` when:

- The rule is experimental.
- The false-positive risk is unknown.
- The expression is broad.
- The user wants detection without enforcement.
- The environment supports Enterprise-only Log action.

## 8.3 Log Rule Example for XSS Detection Validation

```json
{
  "description": "Log potential XSS indicators before enforcement",
  "expression": "lower(http.request.uri.query) contains \"<script\" or lower(http.request.uri.query) contains \"onerror=\" or lower(http.request.uri.query) contains \"javascript:\"",
  "action": "log",
  "enabled": true
}
```

## 8.4 Log Rule Example for SQL Injection Detection Validation

```json
{
  "description": "Log potential SQL injection indicators before enforcement",
  "expression": "lower(http.request.uri.query) contains \"union select\" or lower(http.request.uri.query) contains \"or 1=1\" or lower(http.request.uri.query) contains \"sleep(\"",
  "action": "log",
  "enabled": true
}
```

## 8.5 Log Action Generation Checklist

- [ ] Mention Enterprise plan requirement.
- [ ] Use for validation before blocking.
- [ ] Explain that evaluation continues after a log match.
- [ ] If Enterprise availability is unknown, suggest testing with a less disruptive supported action or reviewing Security Events.

---

# 9. Skip Action (`skip`)

## 9.1 Definition

The `skip` action allows matching requests to skip one or more Cloudflare security features, rules, rulesets, phases, or products depending on rule configuration.

A rule configured with `skip` is also called a skip rule or exception rule.

`skip` is not a normal allow action. It does not simply allow all traffic. It selectively bypasses configured evaluation.

## 9.2 When to Generate `skip`

Generate `skip` when:

- Legitimate traffic matches a security rule unintentionally.
- A trusted API client must bypass rate limiting.
- An internal monitoring service must bypass Managed Rules.
- A known benign path or source must bypass a specific noisy rule.
- A managed rule exception is needed.

## 9.3 When Not to Generate `skip`

Do not generate `skip` when:

- The user wants to block malicious traffic.
- The exception is broad and could let attacks bypass protection.
- The matching expression is not tightly scoped.
- The skip rule would be placed after the rule it is supposed to skip.
- The request source is not trusted.

## 9.4 Skip Action Parameters

The `skip` action uses `action_parameters` to define what should be skipped.

| Skip target | API parameter | Effect |
|---|---|---|
| Remaining rules in the current ruleset | `ruleset: "current"` | Skips remaining rules in the current ruleset. |
| One or more phases | `phases: [...]` | Skips specific phases such as rate limiting or managed rules. |
| Current phase | `phase: "current"` | Skips remaining rules in the current phase. Zone-level `http_request_firewall_custom` only. |
| Security products not based on Ruleset Engine | `products: [...]` | Skips specific legacy/security products. |
| Specific managed rulesets | `rulesets: [...]` | Skips selected managed rulesets. |
| Specific rules inside a managed ruleset | rule-specific action parameters | Creates a targeted managed-rule exception. |

## 9.5 Skip Remaining Rules in Current Ruleset

Use this only for tightly scoped trusted traffic.

```json
{
  "description": "Skip remaining custom rules for trusted monitoring endpoint",
  "expression": "http.request.uri.path contains \"/healthcheck\" and ip.src in {203.0.113.10}",
  "action": "skip",
  "action_parameters": {
    "ruleset": "current"
  },
  "enabled": true
}
```

## 9.6 Skip Rate Limiting Phase

```json
{
  "description": "Skip rate limiting for trusted API client",
  "expression": "http.request.uri.path starts_with \"/api/\" and ip.src in {203.0.113.10}",
  "action": "skip",
  "action_parameters": {
    "phases": [
      "http_ratelimit"
    ]
  },
  "enabled": true
}
```

## 9.7 Skip Managed Rules Phase

Use this only for narrow false-positive exceptions.

```json
{
  "description": "Skip managed rules for trusted internal scanner on healthcheck path",
  "expression": "http.request.uri.path eq \"/healthcheck\" and ip.src in {203.0.113.10}",
  "action": "skip",
  "action_parameters": {
    "phases": [
      "http_request_firewall_managed"
    ]
  },
  "enabled": true
}
```

## 9.8 Skip Specific Legacy Security Products

API values are case-sensitive.

```json
{
  "description": "Skip selected legacy security products for trusted source",
  "expression": "ip.src in {203.0.113.10}",
  "action": "skip",
  "action_parameters": {
    "products": [
      "zoneLockdown",
      "uaBlock",
      "bic"
    ]
  },
  "enabled": true
}
```

Available product API values include:

| Product | API value |
|---|---|
| Zone Lockdown | `zoneLockdown` |
| User Agent Blocking | `uaBlock` |
| Browser Integrity Check | `bic` |
| Hotlink Protection | `hot` |
| Security Level | `securityLevel` |
| Rate limiting rules, previous version | `rateLimit` |
| Managed rules, previous version | `waf` |

## 9.9 Skip Logging for Skip Rules

By default, matching skip rules can be logged. To disable logging for a skip rule:

```json
{
  "description": "Skip rate limiting and disable logging for trusted monitoring traffic",
  "expression": "http.request.uri.path eq \"/healthcheck\" and ip.src in {203.0.113.10}",
  "action": "skip",
  "action_parameters": {
    "phases": [
      "http_ratelimit"
    ]
  },
  "logging": {
    "enabled": false
  },
  "enabled": true
}
```

## 9.10 Skip Rule Ordering Constraint

Skip rules must be evaluated before the rules, phases, or rulesets they are intended to skip.

> **Warning:** If a skip rule is placed at the end of the rules list, it might skip nothing. Place skip exceptions before broad block rules, execute rules, or managed ruleset execution rules that they are intended to bypass.

## 9.11 Account-Level and Zone-Level Constraint

Cloudflare phases exist at account and zone levels.

Generation rules:

- Account-level skip rules affect account-level rules and phases.
- Zone-level skip rules affect zone-level rules and phases.
- To skip zone-level rules or phases, create the skip rule at the zone level.
- Account-level phases are generally Enterprise-only.

## 9.12 Skip Action Generation Checklist

- [ ] The expression is narrowly scoped.
- [ ] The trusted source, path, hostname, or client identity is explicit.
- [ ] The skip target is explicit in `action_parameters`.
- [ ] The rule is ordered before what it should skip.
- [ ] The skip action is not used as a broad allow-all bypass.
- [ ] Logging behavior is specified when relevant.
- [ ] False-positive risk and security risk are explained.

---

# 10. Execute Action (`execute`)

## 10.1 Definition

The `execute` action executes the rules in another ruleset. The executed ruleset can be a managed ruleset or a custom ruleset. The `execute` action itself is not terminating, but rules inside the executed ruleset can use terminating actions.

Rulesets belong to phases and can only execute in the same phase.

## 10.2 When to Generate `execute`

Use `execute` when:

- Deploying a managed ruleset.
- Deploying a custom ruleset.
- Applying a reusable set of rules across zones or accounts.
- The user asks to enable Cloudflare Managed Rules or a custom WAF ruleset.

## 10.3 Execute Custom Ruleset Pattern

```json
{
  "description": "Execute custom WAF ruleset",
  "expression": "true",
  "action": "execute",
  "action_parameters": {
    "id": "<CUSTOM_RULESET_ID>"
  },
  "enabled": true
}
```

## 10.4 Execute Managed Ruleset Pattern

```json
{
  "description": "Execute Cloudflare managed WAF ruleset",
  "expression": "true",
  "action": "execute",
  "action_parameters": {
    "id": "<MANAGED_RULESET_ID>"
  },
  "enabled": true
}
```

## 10.5 Execute Action Generation Checklist

- [ ] Use only when a ruleset ID is known or the generated output clearly marks it as a placeholder.
- [ ] Ensure the ruleset and execute rule belong to the same phase.
- [ ] Explain that the executed ruleset may contain terminating actions.
- [ ] For custom rulesets, include the creation/deployment distinction.
- [ ] For managed rulesets, mention overrides when false positives are possible.

---

# 11. Rewrite Action (`rewrite`)

## 11.1 Definition

The `rewrite` action rewrites the request or response by adjusting URI path, query string, HTTP request headers, or HTTP response headers according to the rule configuration.

This action is available only in specific products and phases, such as Transform Rules. In WAF custom rules, a rewrite-related action may appear in exposed credential checking contexts.

## 11.2 WAF Rule Generation Guidance

Do not use `rewrite` as a primary SQLi or XSS mitigation action.

Use `rewrite` only when:

- The user explicitly asks for request or response transformation.
- The target phase supports rewrite.
- The goal is header/URI/query rewriting, not attack blocking.
- The product context is Transform Rules or another supported feature.

## 11.3 Rewrite Action Checklist

- [ ] Verify supported phase.
- [ ] Do not use for general WAF block rules.
- [ ] Use `block`, `managed_challenge`, or `skip` for WAF security decisions.
- [ ] Include action parameters if generating a concrete rewrite rule.

---

# 12. Redirect Action (`redirect`)

## 12.1 Definition

The `redirect` action sends the visitor from a source URL to a target URL using an HTTP redirect. It is a terminating action.

It is available for redirect rules such as Single Redirects and Bulk Redirects.

## 12.2 WAF Rule Generation Guidance

Do not use `redirect` as a primary SQLi or XSS defense. Use it only when:

- The user asks for redirect behavior.
- The rule belongs to a redirect-capable product.
- The goal is routing users, not inspecting or blocking attack payloads.

For malicious input, prefer:

- `block` for confirmed attacks.
- `managed_challenge` for suspicious traffic.
- `skip` for safe exceptions.

---

# 13. Route Action (`route`)

## 13.1 Definition

The `route` action adjusts origin routing details such as the Host header, Server Name Indication, resolved hostname, or destination port. It is available in Origin Rules.

## 13.2 WAF Rule Generation Guidance

Do not use `route` for SQLi or XSS rule generation. Use it only when the user explicitly asks for origin routing behavior.

---

# 14. Set Configuration Action (`set_config`)

## 14.1 Definition

The `set_config` action changes configuration settings of supported Cloudflare products. It is available for Configuration Rules.

## 14.2 WAF Rule Generation Guidance

Do not use `set_config` for primary attack blocking. Use it only for configuration rules when the user explicitly asks to change product settings for matching traffic.

---

# 15. Compress Response Action (`compress_response`)

## 15.1 Definition

The `compress_response` action defines compression settings for delivering responses to visitors. It is available for Compression Rules.

## 15.2 WAF Rule Generation Guidance

Do not use `compress_response` for WAF attack mitigation, SQLi defense, XSS defense, or false-positive exceptions.

---

# 16. Set Cache Settings Action (`set_cache_settings`)

## 16.1 Definition

The `set_cache_settings` action customizes Cloudflare cache behavior. It is available in Cache Rules.

## 16.2 WAF Rule Generation Guidance

Do not use `set_cache_settings` for WAF attack mitigation. Use it only for cache behavior changes.

---

# 17. Serve Error Action (`serve_error`)

## 17.1 Definition

The `serve_error` action serves custom error content according to custom error rule configuration. It is available in Custom Error Rules and is terminating.

## 17.2 WAF Rule Generation Guidance

Do not use `serve_error` as a general WAF block substitute. Use `block` with custom response for WAF custom rules when the objective is to deny malicious requests and return a controlled response.

---

# 18. Log Custom Field Action (`log_custom_field`)

## 18.1 Definition

The `log_custom_field` action configures custom fields for Logpush jobs in a zone. It is available for custom log fields.

## 18.2 WAF Rule Generation Guidance

Do not use `log_custom_field` as a primary WAF mitigation action. Use it only when the user asks to enrich logging or Logpush data.

---

# 19. Deprecated Firewall Rules Actions: Allow and Bypass

Cloudflare Firewall Rules are deprecated and support a different action set, including `Allow` and `Bypass`.

For modern WAF custom rules:

- Do not generate deprecated Firewall Rules syntax.
- Use `skip` for controlled exceptions.
- Use `block`, `managed_challenge`, `js_challenge`, `challenge`, or `log` for current WAF custom rules.
- Mention migration risk if the user asks for `Allow` or `Bypass`.

---

# 20. Phase-Aware Rule Generation

## 20.1 Phase Definition

A phase is a stage in Cloudflare request or response processing where rulesets can execute. Phases are defined by Cloudflare and cannot be modified.

Phases exist at:

- account level
- zone level

For the same phase, account-level rules are evaluated before zone-level rules.

Each phase has at most one entry point ruleset at the account level and one at the zone level.

## 20.2 Important Phases for WAF Rule Generation

| Phase | Use in rule generation |
|---|---|
| `http_request_firewall_custom` | WAF custom rules. Use for `block`, challenge actions, `skip`, and custom ruleset execution. |
| `http_request_firewall_managed` | Managed WAF rules. Skip rules can target this phase for exceptions. |
| `http_ratelimit` | Rate limiting rules. Skip rules can target this phase for trusted traffic exceptions. |
| `http_request_sbfm` | Super Bot Fight Mode. Skip rules can target this phase when supported. |
| `http_request_transform` | Transform Rules. Use `rewrite`, not WAF block logic. |
| `http_request_late_transform` | Late Transform Rules. Use `rewrite`, not WAF block logic. |
| `http_response_headers_transform` | Response header Transform Rules. Use `rewrite`, not WAF block logic. |
| `http_request_origin` | Origin Rules. Use `route`, not WAF attack blocking. |
| `http_config_settings` | Configuration Rules. Use `set_config`, not WAF block logic. |

## 20.3 Phase-Aware Constraints

Generation rules:

- A ruleset can only execute in the same phase.
- Custom WAF rules run in `http_request_firewall_custom`.
- Skip rules targeting zone-level rules must be created at the zone level.
- Account-level custom rulesets generally require Enterprise plans.
- Some actions are only available in specific phases or products.
- Always state phase assumptions when generating API rules.

---

# 21. Ruleset and Custom Ruleset Generation

## 21.1 Ruleset Definition

A ruleset is an ordered set of rules applied to traffic on the Cloudflare global network. Rulesets belong to a phase and execute in that phase.

Ruleset types include:

| Ruleset type | Description |
|---|---|
| Entry point ruleset | The phase entry point containing ordered rules. |
| Managed ruleset | Preconfigured ruleset maintained by Cloudflare. |
| Custom ruleset | User-defined reusable ruleset. |

Rulesets are versioned. Each modification creates a new version.

## 21.2 Custom Ruleset Creation Pattern

```json
{
  "description": "Custom WAF ruleset for application-specific protections",
  "kind": "custom",
  "name": "Application custom WAF ruleset",
  "phase": "http_request_firewall_custom",
  "rules": [
    {
      "description": "Block XSS indicators in query string",
      "expression": "lower(http.request.uri.query) contains \"<script\" or lower(http.request.uri.query) contains \"onerror=\"",
      "action": "block",
      "enabled": true
    }
  ]
}
```

## 21.3 Custom Ruleset Deployment Pattern

To deploy a custom ruleset, create an `execute` rule in the entry point ruleset of the same phase.

```json
{
  "description": "Execute application custom WAF ruleset",
  "expression": "true",
  "action": "execute",
  "action_parameters": {
    "id": "<CUSTOM_RULESET_ID>"
  },
  "enabled": true
}
```

## 21.4 Custom Ruleset Generation Checklist

- [ ] `kind` is `custom`.
- [ ] `phase` is `http_request_firewall_custom` for WAF custom rules.
- [ ] Rules inside the custom ruleset contain clear descriptions.
- [ ] A separate `execute` rule deploys the custom ruleset.
- [ ] Ruleset ID placeholders are clearly marked if not known.
- [ ] Account-level custom rulesets are marked Enterprise-only when relevant.

---

# 22. Cloudflare Expression Fields Useful for WAF Rule Generation

## 22.1 Common Request Fields

Use fields that directly correspond to the attack surface.

| Field | Use |
|---|---|
| `http.request.uri.path` | Match path-based attacks or scope rules to specific paths. |
| `http.request.uri.query` | Match query string XSS, SQLi, redirects, and parameter-based payloads. |
| `http.host` | Scope rules to hostnames. |
| `http.request.method` | Scope rules to methods such as `GET`, `POST`, `PUT`. |
| `http.user_agent` | Detect suspicious user agents or scope exceptions. |
| `http.referer` | Match or scope requests by referrer. |
| `ip.src` | Scope allowlists, blocklists, trusted clients, or exceptions. |
| `cf.client.bot` | Identify known good bots. |
| `cf.threat_score` | Scope challenge rules to suspicious requests. |
| `http.request.body.raw` | Match request body content when supported and available. |
| `http.request.headers` | Match header-based indicators when supported. |

## 22.2 Field Selection Rules

When generating WAF rules:

- Use `http.request.uri.query` for query-string XSS and SQLi.
- Use `http.request.uri.path` to scope to vulnerable endpoints.
- Use `http.host` to scope to a target domain.
- Use `ip.src` for trusted source exceptions.
- Use `cf.threat_score` to increase challenge confidence.
- Use body fields only when the Cloudflare product and plan support body inspection for the rule type.

---

# 23. Cloudflare Expression Operators Useful for WAF Rule Generation

## 23.1 Common Comparison Operators

| Operator | Use |
|---|---|
| `eq` | Exact equality. |
| `ne` | Not equal. |
| `contains` | Substring match. |
| `matches` | Regular expression match. |
| `in` | Set membership or IP range membership. |
| `starts_with` | Prefix match. |
| `ends_with` | Suffix match. |
| `gt`, `ge`, `lt`, `le` | Numeric comparison. |

## 23.2 Operator Selection Rules

- Use `contains` for stable literal payload indicators.
- Use `matches` for flexible patterns such as event handler attributes, SQLi token spacing, or multiple alternatives.
- Use `in` for IP allowlists and CIDR ranges.
- Use `starts_with` for path scoping.
- Use `eq` for exact path, host, method, or header values.
- Use grouping to avoid ambiguous precedence in complex expressions.

## 23.3 XSS Regex Expression Example

```text
lower(http.request.uri.query) matches "(<script|onerror\s*=|onload\s*=|javascript:)"
```

## 23.4 SQLi Regex Expression Example

```text
lower(http.request.uri.query) matches "(union\s+select|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\()"
```

---

# 24. Action Generation for XSS Rules

## 24.1 XSS Block Rule

Use this when XSS payloads are confirmed malicious.

```json
{
  "description": "Block XSS payload indicators in query string",
  "expression": "lower(http.request.uri.query) matches \"(<script|onerror\\\\s*=|onload\\\\s*=|javascript:)\"",
  "action": "block",
  "enabled": true
}
```

## 24.2 XSS Managed Challenge Rule

Use this when XSS-like traffic is suspicious but blocking may be too aggressive.

```json
{
  "description": "Managed challenge XSS-like query traffic",
  "expression": "lower(http.request.uri.query) matches \"(<script|onerror\\\\s*=|onload\\\\s*=|javascript:)\"",
  "action": "managed_challenge",
  "enabled": true
}
```

## 24.3 XSS Log Rule

Use this on Enterprise plans for validation before blocking.

```json
{
  "description": "Log XSS-like query traffic before enforcement",
  "expression": "lower(http.request.uri.query) matches \"(<script|onerror\\\\s*=|onload\\\\s*=|javascript:)\"",
  "action": "log",
  "enabled": true
}
```

## 24.4 XSS False-Positive Exception with Skip

Use this only for trusted sources or known safe application paths.

```json
{
  "description": "Skip custom XSS rules for trusted CMS editor source",
  "expression": "http.request.uri.path starts_with \"/cms/editor\" and ip.src in {203.0.113.10}",
  "action": "skip",
  "action_parameters": {
    "ruleset": "current"
  },
  "enabled": true
}
```

---

# 25. Action Generation for SQL Injection Rules

## 25.1 SQLi Block Rule

```json
{
  "description": "Block SQL injection indicators in query string",
  "expression": "lower(http.request.uri.query) matches \"(union\\\\s+select|or\\\\s+1\\\\s*=\\\\s*1|sleep\\\\s*\\\\(|benchmark\\\\s*\\\\()\"",
  "action": "block",
  "enabled": true
}
```

## 25.2 SQLi Managed Challenge Rule

```json
{
  "description": "Managed challenge SQLi-like traffic",
  "expression": "lower(http.request.uri.query) matches \"(union\\\\s+select|or\\\\s+1\\\\s*=\\\\s*1|sleep\\\\s*\\\\(|benchmark\\\\s*\\\\()\"",
  "action": "managed_challenge",
  "enabled": true
}
```

## 25.3 SQLi Log Rule

```json
{
  "description": "Log SQLi-like query traffic before enforcement",
  "expression": "lower(http.request.uri.query) matches \"(union\\\\s+select|or\\\\s+1\\\\s*=\\\\s*1|sleep\\\\s*\\\\(|benchmark\\\\s*\\\\()\"",
  "action": "log",
  "enabled": true
}
```

## 25.4 SQLi False-Positive Exception with Skip

Use this for trusted paths that legitimately carry SQL-like text.

```json
{
  "description": "Skip managed WAF rules for trusted SQL training lab path",
  "expression": "http.request.uri.path starts_with \"/training/sql\" and ip.src in {203.0.113.10}",
  "action": "skip",
  "action_parameters": {
    "phases": [
      "http_request_firewall_managed"
    ]
  },
  "enabled": true
}
```

---

# 26. Action Generation for API and Browser Traffic

## 26.1 API Traffic

Avoid challenge actions for API clients unless the API clients can handle Cloudflare challenges.

For API endpoints:

| Scenario | Recommended action |
|---|---|
| Confirmed malicious API payload | `block` |
| Rule validation | `log` if available |
| Trusted API client exception | `skip` with strict IP, token, path, or hostname scope |
| Suspicious but not confirmed traffic | Prefer narrow `block` or logging; use challenge only if clients support it |

Example API block rule:

```json
{
  "description": "Block SQLi indicators on API search endpoint",
  "expression": "http.request.uri.path starts_with \"/api/search\" and lower(http.request.uri.query) matches \"(union\\\\s+select|or\\\\s+1\\\\s*=\\\\s*1)\"",
  "action": "block",
  "enabled": true
}
```

## 26.2 Browser Traffic

For browser-facing pages:

| Scenario | Recommended action |
|---|---|
| Confirmed malicious XSS/SQLi payload | `block` |
| Suspicious automated traffic | `managed_challenge` |
| Browser-like but suspicious clients | `js_challenge` |
| High-risk human verification | `challenge` |
| Validation | `log` if available |

Example browser challenge rule:

```json
{
  "description": "Managed challenge suspicious browser traffic to login path",
  "expression": "http.request.uri.path eq \"/login\" and cf.threat_score gt 20",
  "action": "managed_challenge",
  "enabled": true
}
```

---

# 27. False Positive Tuning with Actions

## 27.1 Safe Tuning Workflow

1. Start with `log` on Enterprise plans, or a carefully scoped non-terminating/low-impact strategy where available.
2. Review Security Events and logs.
3. Narrow the expression using path, host, method, IP, or known vulnerable parameters.
4. Use `managed_challenge` when blocking is too aggressive.
5. Use `skip` only for tightly scoped trusted exceptions.
6. Move to `block` after validation.

## 27.2 Common False-Positive Sources

| Application behavior | Risk |
|---|---|
| CMS rich text editors | May submit HTML or JavaScript-like strings. |
| Developer tools | May submit code snippets. |
| SQL training labs | May submit SQL keywords intentionally. |
| Search forms | May contain operators, quotes, and unusual syntax. |
| API clients | May fail if challenged. |
| Internal scanners | May trigger WAF managed rules or rate limiting. |

## 27.3 Exception Rule Pattern

Place exception rules before broad enforcement rules.

```json
{
  "description": "Skip current custom rules for trusted internal scanner",
  "expression": "ip.src in {203.0.113.10} and http.request.uri.path starts_with \"/internal/scan\"",
  "action": "skip",
  "action_parameters": {
    "ruleset": "current"
  },
  "enabled": true
}
```

---

# 28. Rule Ordering Patterns

## 28.1 Recommended Rule Order for WAF Custom Rules

1. Narrow trusted skip exceptions.
2. Logging or validation rules.
3. Specific block rules for confirmed exploit indicators.
4. Challenge rules for suspicious traffic.
5. Broad catch-all rules only if validated.

## 28.2 Ordering Example

```json
[
  {
    "description": "Skip trusted internal scanner",
    "expression": "ip.src in {203.0.113.10} and http.request.uri.path starts_with \"/internal/scan\"",
    "action": "skip",
    "action_parameters": {
      "ruleset": "current"
    },
    "enabled": true
  },
  {
    "description": "Block XSS indicators in query string",
    "expression": "lower(http.request.uri.query) matches \"(<script|onerror\\\\s*=|javascript:)\"",
    "action": "block",
    "enabled": true
  },
  {
    "description": "Managed challenge suspicious login requests",
    "expression": "http.request.uri.path eq \"/login\" and cf.threat_score gt 20",
    "action": "managed_challenge",
    "enabled": true
  }
]
```

---

# 29. Complete Example: Cloudflare WAF Custom Ruleset for XSS and SQLi

## 29.1 Scenario

The application receives reflected XSS and SQLi bypass attempts in query strings. It also has a trusted internal scanner that should not trigger the custom rules.

## 29.2 Custom Ruleset

```json
{
  "description": "Application custom WAF rules for XSS and SQLi",
  "kind": "custom",
  "name": "Application custom WAF ruleset",
  "phase": "http_request_firewall_custom",
  "rules": [
    {
      "description": "Skip trusted internal scanner from current custom ruleset",
      "expression": "ip.src in {203.0.113.10} and http.request.uri.path starts_with \"/internal/scan\"",
      "action": "skip",
      "action_parameters": {
        "ruleset": "current"
      },
      "enabled": true
    },
    {
      "description": "Block reflected XSS indicators in query string",
      "expression": "lower(http.request.uri.query) matches \"(<script|onerror\\\\s*=|onload\\\\s*=|javascript:)\"",
      "action": "block",
      "enabled": true
    },
    {
      "description": "Block SQL injection indicators in query string",
      "expression": "lower(http.request.uri.query) matches \"(union\\\\s+select|or\\\\s+1\\\\s*=\\\\s*1|sleep\\\\s*\\\\(|benchmark\\\\s*\\\\()\"",
      "action": "block",
      "enabled": true
    },
    {
      "description": "Managed challenge suspicious login traffic",
      "expression": "http.request.uri.path eq \"/login\" and cf.threat_score gt 20",
      "action": "managed_challenge",
      "enabled": true
    }
  ]
}
```

## 29.3 Why This Ruleset Works

- The skip exception is first, so trusted internal scanner traffic is exempt before broad blocks.
- XSS and SQLi block rules use terminating `block` actions for confirmed malicious indicators.
- The challenge rule applies lower-friction protection to suspicious login traffic.
- Expressions use `lower()` to reduce case-bypass issues.
- Regex patterns cover common token spacing and event-handler indicators.

---

# 30. Final Rule-Generation Template

Use this format when generating Cloudflare WAF rules.

```markdown
## Rule Objective

Describe the attack type, bypass behavior, target request field, and desired action.

## Proposed Cloudflare Rule

Provide JSON rule or ruleset configuration.

## Expression Explanation

Explain:
- selected fields
- operators
- functions
- literals or regex patterns
- path/host/IP scoping

## Action Explanation

Explain:
- selected action
- whether the action is terminating
- why the action is appropriate
- required `action_parameters`

## Rule Ordering

Explain whether this rule must appear before or after skip, execute, managed rules, or broad block rules.

## False Positive and Tuning Notes

List:
- likely false-positive cases
- whether to start with `log`, `managed_challenge`, or `block`
- recommended skip exceptions
- recommended expression narrowing

## Deployment Notes

Mention:
- phase
- zone/account level
- Enterprise-only limitations if relevant
- ruleset ID placeholders if relevant
```

---

# 31. Final Checklist for Cloudflare Action Selection

- [ ] The rule has a clear `expression`.
- [ ] The rule has a correct `action`.
- [ ] The action is available in the intended product and phase.
- [ ] The phase is identified, usually `http_request_firewall_custom` for WAF custom rules.
- [ ] `block` is used for confirmed malicious traffic.
- [ ] `managed_challenge` is used for suspicious browser traffic where blocking is too aggressive.
- [ ] `js_challenge` is used only when browser-compatible automatic challenge is appropriate.
- [ ] `challenge` is used only when interactive friction is acceptable.
- [ ] `log` is used for validation only when Enterprise plan availability is assumed.
- [ ] `skip` is used only for narrow, trusted exceptions.
- [ ] `skip` rules appear before the rules or phases they should skip.
- [ ] `execute` is used only to run managed or custom rulesets.
- [ ] Non-WAF actions such as `rewrite`, `redirect`, `route`, `set_config`, `compress_response`, and `set_cache_settings` are not used for SQLi/XSS blocking unless the user explicitly asks for that product behavior.
- [ ] Custom block responses use supported content types and HTTP status codes in the `400`-`499` range.
- [ ] Rule ordering and terminating behavior are explained.
