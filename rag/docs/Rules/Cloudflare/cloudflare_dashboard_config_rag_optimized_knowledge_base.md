# Cloudflare WAF Custom Rule Dashboard Configuration Knowledge Base for Rule Generation
# 1. Cloudflare WAF Custom Rules in the Dashboard
## 1.1 Definition

A Cloudflare WAF custom rule is a security rule that evaluates incoming HTTP requests against a filter expression and then applies an action when the expression matches.

In the Cloudflare dashboard, a custom rule is configured using three core pieces:

| Dashboard area | Purpose | Rule-generation meaning |
|---|---|---|
| Rule name | Human-readable rule identifier. | Should describe attack type, request component, and intended action. |
| When incoming requests match | Match condition built from Field, Operator, and Value or an expression. | Becomes the Cloudflare Rules language `expression`. |
| Then take action | Action applied to matching requests. | Becomes the Cloudflare rule `action`, such as `block`, `managed_challenge`, `js_challenge`, `log`, or `skip`, depending on plan/action support. |

## 1.2 Core Rule Model

Dashboard configuration maps to rule JSON like this:

```json
{
  "description": "Rule name shown in the dashboard",
  "expression": "<Cloudflare Rules language expression>",
  "action": "<rule_action>",
  "enabled": true
}
```

Example:

```json
{
  "description": "Block XSS indicators in query string",
  "expression": "lower(http.request.uri.query) contains \"<script\" or lower(http.request.uri.query) contains \"onerror=\" or lower(http.request.uri.query) contains \"javascript:\"",
  "action": "block",
  "enabled": true
}
```

## 1.3 Dashboard Configuration Principle for WAF Rule Generation

When generating a Cloudflare dashboard rule:

1. Create a descriptive rule name.
2. Select request fields that match the payload location.
3. Select the operator that best matches the payload pattern.
4. Enter a value that is specific enough to avoid broad false positives.
5. Choose the action based on enforcement goal.
6. Use custom response settings only when the action is `Block`.
7. Deploy only after validating the expression and false-positive risk.
8. Save as draft if the rule is not ready for production enforcement.

---

# 2. Create a New Custom Rule in the Cloudflare Dashboard

## 2.1 Dashboard Navigation

To create a new Cloudflare WAF custom rule in the dashboard:

1. In the Cloudflare dashboard, go to the **Security rules** page.
2. Select **Create rule**.
3. Select **Custom rules**.
4. Enter a descriptive name in **Rule name**.
5. Configure the match condition under **When incoming requests match**.
6. Configure the action under **Then take action**.
7. Select **Deploy** to activate the rule immediately.
8. Select **Save as Draft** if the rule is not ready for deployment.

## 2.2 Old Dashboard Navigation

In the older Cloudflare dashboard path:

1. Log in to the Cloudflare dashboard.
2. Select the account and domain.
3. Go to **Security**.
4. Go to **WAF**.
5. Go to **Custom rules**.
6. Select **Create rule**.
7. Configure the rule name, match condition, and action.
8. Select **Deploy** or **Save as Draft**.

## 2.3 Duplicate an Existing Rule

To duplicate an existing custom rule:

1. Find the existing rule in the dashboard.
2. Select the three-dot menu next to the rule.
3. Select **Duplicate**.
4. Edit the duplicated rule name, expression, action, or response settings.
5. Select **Deploy** or **Save as Draft**.

Use duplication when:

- creating a similar rule for another endpoint
- testing a modified expression
- splitting a broad rule into more focused rules
- creating a stricter version of an existing log/challenge rule

## 2.4 Rule Creation Checklist

- [ ] Rule has a descriptive name.
- [ ] Rule expression matches the observed payload location.
- [ ] Field, Operator, and Value are syntactically valid.
- [ ] Expression uses case normalization where needed.
- [ ] Expression is scoped by host, path, method, or parameter where possible.
- [ ] Rule action matches enforcement intent.
- [ ] Custom response is configured only when using `Block`.
- [ ] Draft mode is used if validation is incomplete.
- [ ] Production deployment is performed only after testing or review.

---

# 3. Rule Name

## 3.1 Definition

The **Rule name** is the descriptive name shown in the Cloudflare dashboard.

A good rule name helps operators understand:

- what attack family the rule targets
- which request component is inspected
- which endpoint or scope is affected
- which action is applied
- whether the rule is temporary, tuning-related, or production enforcement

## 3.2 Rule Name Patterns

Good rule name examples:

```text
Block XSS indicators in search query string
```

```text
Block SQLi indicators in id parameter on API product endpoint
```

```text
Managed challenge suspicious login traffic
```

```text
Skip trusted scanner IPs for custom WAF rules
```

```text
Block encoded XSS payloads in raw query string
```

Bad rule name examples:

```text
Rule 1
```

```text
Test
```

```text
Block bad stuff
```

```text
Security
```

## 3.3 Rule Name Generation Guidance

When generating a rule name:

- include the attack type: XSS, SQLi, LFI, RCE, SSRF, bot, scanner, upload abuse
- include the request component: query string, parameter, header, cookie, body, URI path
- include the scope: path, host, API route, login endpoint, upload endpoint
- include the action: block, challenge, skip, log
- avoid ambiguous names
- avoid overly long names

Template:

```text
<Action> <attack type or policy> in <request component> on <scope>
```

Example:

```text
Block SQLi in id parameter on /api/products
```

---

# 4. Match Conditions: Field, Operator, and Value

## 4.1 Dashboard Match Condition Model

Under **When incoming requests match**, the dashboard compares a selected HTTP property to a configured value using a selected operator.

Dashboard configuration:

| Dashboard input | Meaning | Expression equivalent |
|---|---|---|
| Field | HTTP property or Cloudflare field to inspect. | `http.request.uri.query`, `http.request.uri.path`, `http.host`, `ip.src`, etc. |
| Operator | Comparison operation. | `eq`, `contains`, `matches`, `in`, `gt`, `lt`, etc. |
| Value | Literal, set, list, string, regex, number, Boolean, or selected value. | `"<script"`, `"union select"`, `{203.0.113.10}`, `$trusted_security_scanners`. |

General expression shape:

```text
<field> <operator> <value>
```

Example:

```text
http.request.uri.path eq "/login"
```

Compound expression shape:

```text
<scope condition>
and
<attack condition>
```

Example:

```text
starts_with(http.request.uri.path, "/search")
and lower(http.request.uri.query) contains "<script"
```

## 4.2 Field Selection for Dashboard Rules

Select the field based on where the attack payload appears.

| Payload or policy location | Recommended Cloudflare field |
|---|---|
| Query string, unknown parameter | `http.request.uri.query` |
| Query string, known parameter | `http.request.uri.args["param"][*]` |
| Encoded query payload | `raw.http.request.uri.query` |
| URI path | `http.request.uri.path` |
| Hostname | `http.host` |
| HTTP method | `http.request.method` |
| Header value | `http.request.headers["header-name"][*]` |
| User-Agent | `http.user_agent` or `http.request.headers["user-agent"][*]` |
| Cookie string | `http.cookie` |
| Specific cookie | `http.request.cookies["cookie-name"][*]` when available |
| Request body | `http.request.body.*` when supported |
| Trusted IP exception | `ip.src` |
| Country scope | `ip.src.country` |
| ASN scope | `ip.src.asnum` |
| Bot/verified bot | `cf.client.bot` or Bot Management fields |
| Threat/WAF score | `cf.threat_score`, `cf.waf.score`, `cf.waf.score.xss`, `cf.waf.score.sqli` |

## 4.3 Operator Selection for Dashboard Rules

| Detection need | Recommended operator or function pattern |
|---|---|
| Exact path or host | `eq` |
| Multiple exact values | `in` |
| IP or CIDR list | `in` |
| Stable literal attack indicator | `contains` |
| Flexible XSS/SQLi pattern | `matches` if available |
| Path prefix | `starts_with()` |
| Path suffix | `ends_with()` |
| Score or size threshold | `gt`, `ge`, `lt`, `le` |
| Trusted exclusion | `not <field> in <list>` |
| Multiple alternatives | `or` with grouping |
| Scope plus attack evidence | `and` with grouping |

## 4.4 Value Selection for Dashboard Rules

Choose values that are specific enough for rule generation.

Good XSS values:

```text
"<script"
"onerror="
"onload="
"javascript:"
"%3cscript"
```

Good SQLi values:

```text
"union select"
"or 1=1"
"sleep("
"benchmark("
"information_schema"
"union%20select"
"%27"
```

Bad broad values:

```text
"select"
"on"
"<"
"script"
```

## 4.5 Dashboard Match Condition Checklist

- [ ] Field matches the observed request component.
- [ ] Operator matches the intended comparison type.
- [ ] Value is specific enough to reduce false positives.
- [ ] String comparisons use `lower()` when case variations matter.
- [ ] Arrays use `any()` when any value should match.
- [ ] CIDR ranges use `in`, not equality.
- [ ] Regex uses `matches` only when plan support exists.
- [ ] Complex logic uses Expression Editor or API if required.
- [ ] The final expression stays under Cloudflare expression limits.

---

# 5. Dashboard Expression Builder vs Expression Editor

## 5.1 Expression Builder

The Expression Builder lets users configure rules by selecting:

- Field
- Operator
- Value
- logical conditions

Use Expression Builder when:

- the rule is simple
- one or a few conditions are needed
- the user wants a dashboard-guided workflow
- grouping or advanced syntax is not required

Example simple dashboard condition:

```text
http.request.uri.path eq "/login"
```

## 5.2 Expression Editor

The Expression Editor allows manual Cloudflare Rules language expressions.

Use Expression Editor when:

- parentheses are required
- `and` and `or` are mixed
- `matches` regex is needed
- `any()` is needed for arrays
- `lower()` is needed around array values
- raw fields are used
- a named list is used
- advanced functions such as `url_decode()` are needed
- the generated expression is easier to paste than build manually

Example Expression Editor rule:

```text
(
  lower(http.request.uri.query) contains "<script"
  or lower(raw.http.request.uri.query) contains "%3cscript"
)
and not ip.src in $trusted_security_scanners
```

## 5.3 Generation Guidance

When generating a dashboard rule:

- generate both the dashboard concept and the expression
- recommend Expression Editor if the expression contains parentheses, `any()`, `matches`, raw strings, named lists, or complex logic
- avoid claiming that complex expressions can always be built visually in Expression Builder
- use the API or Terraform when repeatability and version control matter

---

# 6. Rule Actions in the Dashboard

## 6.1 Action Selection

Under **Then take action**, the dashboard provides a **Choose action** dropdown. The selected action determines what Cloudflare does when the expression matches.

Common custom rule actions include:

| Action | Meaning | Rule-generation use |
|---|---|---|
| `block` | Refuse matching requests. | Use for high-confidence attack payloads. |
| `managed_challenge` | Issue a managed challenge. | Use for suspicious but not fully certain traffic. |
| `js_challenge` | Issue JavaScript challenge where supported. | Use for bot-like traffic where appropriate. |
| `challenge` | Issue interactive challenge where supported. | Use for higher-friction verification. |
| `log` | Log matching requests without enforcement. | Use for validation; availability depends on plan. |
| `skip` | Skip selected Cloudflare security features or rules. | Use for trusted-source or false-positive exceptions. |
| `allow` | Allow traffic in contexts where action is supported. | Use carefully; avoid broad bypass of security controls. |

## 6.2 Block Action

Selecting **Block** tells Cloudflare to refuse requests that match the rule conditions.

Use `Block` when:

- payload evidence is high confidence
- false-positive risk is acceptable
- the rule is scoped enough
- the matching condition is specific
- trusted scanners or allowed sources are excluded where needed

Example:

```json
{
  "description": "Block SQLi indicators in query string",
  "expression": "lower(http.request.uri.query) contains \"union select\" or lower(http.request.uri.query) contains \"or 1=1\"",
  "action": "block",
  "enabled": true
}
```

## 6.3 Managed Challenge Action

Use `managed_challenge` when:

- traffic is suspicious but not high confidence
- bot or threat-score evidence is present
- false positives would be harmful if blocked immediately
- the endpoint is sensitive, such as login or admin

Example:

```json
{
  "description": "Managed challenge suspicious login traffic",
  "expression": "http.request.uri.path eq \"/login\" and cf.threat_score gt 20 and not cf.client.bot",
  "action": "managed_challenge",
  "enabled": true
}
```

## 6.4 Log Action

Use `log` when:

- validating a new rule
- measuring false positives
- testing a broad expression before enforcement
- collecting evidence before switching to block or challenge

Plan constraint:

> **Note:** Cloudflare custom rule action support varies by plan. Log action availability can be restricted compared with other custom rule actions.

## 6.5 Skip Action

Use `skip` when:

- trusted scanner traffic should bypass selected custom rules
- a known false-positive source must be excluded
- a specific path, host, or IP should skip selected security controls
- a narrowly defined exception should run before broader block rules

Example:

```json
{
  "description": "Skip current custom rules for trusted security scanners",
  "expression": "ip.src in $trusted_security_scanners",
  "action": "skip",
  "action_parameters": {
    "ruleset": "current"
  },
  "enabled": true
}
```

## 6.6 Action Selection Checklist

- [ ] Use `block` only for high-confidence rules.
- [ ] Use `managed_challenge` for suspicious traffic with false-positive risk.
- [ ] Use `log` for testing when available.
- [ ] Use `skip` for narrowly scoped trusted exceptions.
- [ ] Place skip rules before rules they are meant to bypass.
- [ ] Do not use broad allow/skip logic for user-controlled values.
- [ ] Include action rationale in generated output.

---

# 7. Deploy vs Save as Draft

## 7.1 Deploy

Selecting **Deploy** saves and activates the rule.

Use **Deploy** when:

- the rule expression has been reviewed
- the action is appropriate
- false positives are understood
- any needed custom response is valid
- rule order has been considered
- skip exceptions are placed before enforcement rules

## 7.2 Save as Draft

Selecting **Save as Draft** saves the rule without deploying it.

Use **Save as Draft** when:

- expression validation is incomplete
- the rule needs stakeholder review
- the expected false positives are unknown
- the rule is broad
- payload evidence is incomplete
- the action is `block` and production risk is high

## 7.3 Deployment Checklist

- [ ] Confirm expression syntax.
- [ ] Confirm field/operator/value selection.
- [ ] Confirm action.
- [ ] Confirm custom response if `block`.
- [ ] Confirm rule order.
- [ ] Confirm skip rules and exceptions.
- [ ] Confirm plan support for regex, log, body fields, or custom response.
- [ ] Use draft mode if enforcement risk remains.

---

# 8. Configure a Custom Response for Blocked Requests

## 8.1 Definition

When the selected rule action is **Block**, the dashboard can optionally define a custom HTTP response returned to the client.

Custom response is only relevant for blocked requests.

> **Note:** Custom responses for blocked requests are available on Pro plans and above.

## 8.2 Custom Response Settings

A custom response has three settings:

| Setting | Purpose | Constraint |
|---|---|---|
| With response type | Selects the HTTP response content type. | Must match one of the supported response types. |
| With response code | Selects the HTTP status code returned to the client. | Must be between `400` and `499`. Default is `403` for WAF custom rules. |
| Response body | Body returned to the client. | Must be valid for the selected response type. Maximum size is `2 KB` for WAF custom rules. |

## 8.3 Custom Response Type Mapping

| Dashboard value | API value |
|---|---|
| Custom HTML | `"text/html"` |
| Custom Text | `"text/plain"` |
| Custom JSON | `"application/json"` |
| Custom XML | `"text/xml"` |

## 8.4 Custom HTML Response

Use **Custom HTML** when the response body is an HTML page.

API content type:

```json
"text/html"
```

Example body:

```html
<!doctype html>
<html>
  <head>
    <title>Request blocked</title>
  </head>
  <body>
    <h1>Request blocked</h1>
    <p>Your request was blocked by security policy.</p>
  </body>
</html>
```

## 8.5 Custom Text Response

Use **Custom Text** for plain text errors.

API content type:

```json
"text/plain"
```

Example body:

```text
Request blocked by security policy.
```

## 8.6 Custom JSON Response

Use **Custom JSON** for API endpoints.

API content type:

```json
"application/json"
```

Example body:

```json
{
  "error": "request_blocked",
  "message": "Request blocked by security policy."
}
```

Use JSON response when:

- the protected endpoint is an API
- clients expect JSON errors
- rule scope is limited to API paths
- the response body can stay under 2 KB

## 8.7 Custom XML Response

Use **Custom XML** for XML-based APIs or legacy clients.

API content type:

```json
"text/xml"
```

Example body:

```xml
<error>
  <code>request_blocked</code>
  <message>Request blocked by security policy.</message>
</error>
```

## 8.8 Response Code

The **With response code** setting controls the HTTP status code returned to the client.

Constraints:

- allowed range: `400` to `499`
- default for WAF custom rule block response: `403`
- choose a code that reflects the policy

Common choices:

| Status code | Meaning | Use |
|---|---|---|
| `400` | Bad Request | Malformed or invalid request syntax. |
| `401` | Unauthorized | Authentication required; use carefully. |
| `403` | Forbidden | Default and most common block response. |
| `404` | Not Found | Conceal resource existence if appropriate. |
| `429` | Too Many Requests | Prefer for rate limiting, not ordinary WAF block unless intentional. |

## 8.9 Response Body

The **Response body** is the body returned with the custom block response.

Constraints:

- body must be valid for the selected response type
- maximum field size: `2 KB`
- do not include secrets
- avoid reflecting user-controlled payloads
- keep error body generic
- avoid detailed WAF rule logic in the response

Safe JSON body:

```json
{
  "error": "request_blocked",
  "message": "The request was blocked by security policy."
}
```

Avoid response body:

```json
{
  "error": "blocked",
  "debug": "Matched SQLi regex union select or 1=1 in id parameter"
}
```

Reason:

- reveals detection logic
- helps attackers tune bypasses
- may expose implementation details

## 8.10 Custom Response JSON Rule Pattern

Cloudflare API-style rule with custom response parameters:

```json
{
  "description": "Block SQLi indicators with JSON response",
  "expression": "lower(http.request.uri.query) contains \"union select\" or lower(http.request.uri.query) contains \"or 1=1\"",
  "action": "block",
  "action_parameters": {
    "response": {
      "status_code": 403,
      "content_type": "application/json",
      "content": "{\"error\":\"request_blocked\",\"message\":\"The request was blocked by security policy.\"}"
    }
  },
  "enabled": true
}
```

## 8.11 Custom Response Checklist

- [ ] Custom response is used only with `Block`.
- [ ] Plan supports custom response.
- [ ] Response type matches response body format.
- [ ] Response code is between `400` and `499`.
- [ ] Default WAF block response code is `403`.
- [ ] Response body is under `2 KB`.
- [ ] Response body does not reveal detection logic.
- [ ] JSON response is used for API endpoints.
- [ ] HTML or text response is used for browser-oriented endpoints.

---

# 9. Plan and Feature Constraints Relevant to Dashboard Rule Generation

## 9.1 Custom Rule Availability

Cloudflare WAF custom rules are available across Cloudflare plans, but rule counts and feature support vary by plan.

Important generation implications:

- Do not assume unlimited custom rules.
- Do not assume regex support on all plans.
- Do not assume `log` action availability on all plans.
- Do not assume custom response support below Pro.
- Do not assume body fields, WAF score fields, Bot Management fields, API Shield fields, or account-level custom rulesets are available unless explicitly stated.

## 9.2 Regex Support

The `matches` operator is useful for XSS and SQLi patterns, but regex support is plan-dependent.

Rule-generation guidance:

- If the rule uses `matches`, include a fallback using `contains`.
- Use `matches` for whitespace-flexible SQLi patterns and compact XSS event-handler variants.
- Use `contains` for stable literals when regex support is unavailable.
- Mention that regex support must be verified before deployment.

Regex example:

```text
lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()"
```

Fallback:

```text
lower(http.request.uri.query) contains "union select"
or lower(http.request.uri.query) contains "or 1=1"
or lower(http.request.uri.query) contains "sleep("
```

## 9.3 Custom Response Support

Custom response for blocked requests is available on Pro plans and above.

Rule-generation guidance:

- If the user asks for custom response, include the plan note.
- If plan is unknown, make custom response optional.
- If endpoint is API, prefer JSON response.
- If endpoint is browser-facing, HTML or text response may be appropriate.

## 9.4 Account-Level Custom Rulesets

Account-level custom rulesets require Enterprise plan.

Generation guidance:

- Do not recommend account-level custom rulesets unless Enterprise is available or the user asks.
- For normal dashboard custom rules, assume zone-level custom rule unless context says account-level.
- When generating reusable deployment guidance, distinguish custom rules from account-level custom rulesets.

---

# 10. Dashboard Configuration for XSS Rules

## 10.1 XSS Rule Objective

Create a Cloudflare WAF custom rule that matches cross-site scripting payloads in a request component and applies an action such as block, managed challenge, log, or skip.

Common XSS request components:

- `http.request.uri.query`
- `http.request.uri.args["param"][*]`
- `raw.http.request.uri.query`
- `http.request.headers["header-name"][*]`
- `http.cookie`
- `http.request.body.form.values[*]` when supported

## 10.2 XSS Dashboard Field/Operator/Value Mapping

| Dashboard concept | Recommended selection |
|---|---|
| Field | Query string, URI argument, header, cookie, or body field matching payload location |
| Operator | `contains` for stable literals; `matches` for flexible variants |
| Value | `<script`, `onerror=`, `onload=`, `javascript:`, `%3cscript`, regex for event handlers |
| Action | `block` for high confidence; `managed_challenge` or `log` for tuning |

## 10.3 Basic XSS Dashboard Expression

```text
lower(http.request.uri.query) contains "<script"
or lower(http.request.uri.query) contains "onerror="
or lower(http.request.uri.query) contains "javascript:"
```

## 10.4 Encoded XSS Dashboard Expression

```text
lower(raw.http.request.uri.query) contains "%3cscript"
or lower(raw.http.request.uri.query) contains "%3csvg"
or lower(raw.http.request.uri.query) contains "javascript%3a"
```

## 10.5 Path-Scoped XSS Dashboard Expression

```text
starts_with(http.request.uri.path, "/search")
and (
  lower(http.request.uri.query) contains "<script"
  or lower(http.request.uri.query) contains "onerror="
  or lower(http.request.uri.query) contains "javascript:"
)
```

## 10.6 XSS Rule JSON for Dashboard Deployment

```json
{
  "description": "Block XSS indicators in search query string",
  "expression": "starts_with(http.request.uri.path, \"/search\") and (lower(http.request.uri.query) contains \"<script\" or lower(http.request.uri.query) contains \"onerror=\" or lower(http.request.uri.query) contains \"javascript:\")",
  "action": "block",
  "enabled": true
}
```

## 10.7 XSS Rule with Custom JSON Response

```json
{
  "description": "Block XSS indicators in API query string",
  "expression": "starts_with(http.request.uri.path, \"/api/search\") and (lower(http.request.uri.query) contains \"<script\" or lower(http.request.uri.query) contains \"onerror=\" or lower(http.request.uri.query) contains \"javascript:\")",
  "action": "block",
  "action_parameters": {
    "response": {
      "status_code": 403,
      "content_type": "application/json",
      "content": "{\"error\":\"request_blocked\",\"message\":\"The request was blocked by security policy.\"}"
    }
  },
  "enabled": true
}
```

## 10.8 XSS Dashboard Checklist

- [ ] Rule name mentions XSS and request component.
- [ ] Field matches payload location.
- [ ] `lower()` handles case-randomized payloads.
- [ ] Raw query field handles encoded payloads if observed.
- [ ] Path or parameter scoping reduces false positives.
- [ ] Action is `block` only when confidence is high.
- [ ] Custom response is valid if used.
- [ ] Expression Editor or API is used for grouped expressions.

---

# 11. Dashboard Configuration for SQL Injection Rules

## 11.1 SQLi Rule Objective

Create a Cloudflare WAF custom rule that matches SQL injection payloads and applies an appropriate enforcement or validation action.

Common SQLi request components:

- `http.request.uri.query`
- `http.request.uri.args["id"][*]`
- `raw.http.request.uri.query`
- `http.request.headers["header-name"][*]`
- `http.cookie`
- `http.request.body.form.values[*]` when supported

## 11.2 SQLi Dashboard Field/Operator/Value Mapping

| Dashboard concept | Recommended selection |
|---|---|
| Field | Query string, URI argument, header, cookie, or body field matching payload location |
| Operator | `contains` for stable literals; `matches` for whitespace variants |
| Value | `union select`, `or 1=1`, `sleep(`, `benchmark(`, `information_schema`, `%27`, regex |
| Action | `block` for high confidence; `managed_challenge` or `log` for tuning |

## 11.3 Basic SQLi Dashboard Expression

```text
lower(http.request.uri.query) contains "union select"
or lower(http.request.uri.query) contains "or 1=1"
or lower(http.request.uri.query) contains "sleep("
or lower(http.request.uri.query) contains "benchmark("
```

## 11.4 SQLi Regex Dashboard Expression

```text
lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema)"
```

## 11.5 Encoded SQLi Dashboard Expression

```text
lower(raw.http.request.uri.query) contains "union%20select"
or lower(raw.http.request.uri.query) contains "%27"
or lower(raw.http.request.uri.query) contains "%22"
```

## 11.6 Path-Scoped SQLi Dashboard Expression

```text
starts_with(http.request.uri.path, "/api/search")
and (
  lower(http.request.uri.query) contains "union select"
  or lower(http.request.uri.query) contains "or 1=1"
  or lower(http.request.uri.query) contains "sleep("
)
```

## 11.7 SQLi Rule JSON for Dashboard Deployment

```json
{
  "description": "Block SQLi indicators in API search query string",
  "expression": "starts_with(http.request.uri.path, \"/api/search\") and (lower(http.request.uri.query) contains \"union select\" or lower(http.request.uri.query) contains \"or 1=1\" or lower(http.request.uri.query) contains \"sleep(\")",
  "action": "block",
  "enabled": true
}
```

## 11.8 SQLi Rule with Custom JSON Response

```json
{
  "description": "Block SQLi indicators in API query string",
  "expression": "starts_with(http.request.uri.path, \"/api/\") and (lower(http.request.uri.query) contains \"union select\" or lower(http.request.uri.query) contains \"or 1=1\" or lower(http.request.uri.query) contains \"sleep(\")",
  "action": "block",
  "action_parameters": {
    "response": {
      "status_code": 403,
      "content_type": "application/json",
      "content": "{\"error\":\"request_blocked\",\"message\":\"The request was blocked by security policy.\"}"
    }
  },
  "enabled": true
}
```

## 11.9 SQLi Dashboard Checklist

- [ ] Rule name mentions SQL injection or SQLi.
- [ ] Field matches payload location.
- [ ] SQL keywords are normalized with `lower()`.
- [ ] Regex is used only when plan supports it.
- [ ] `contains` fallback is provided if regex support is unknown.
- [ ] Raw encoded values are included when bypass uses URL encoding.
- [ ] Broad literals like `"select"` alone are avoided.
- [ ] API/search/admin false positives are documented and tuned.
- [ ] Expression Editor or API is used for grouped expressions.

---

# 12. Trusted Exceptions and Skip Rules in Dashboard Configuration

## 12.1 Trusted Exception Objective

Trusted exceptions prevent known-safe traffic from being blocked or challenged by broad WAF rules.

Common trusted exception sources:

- internal security scanners
- CI/CD security tests
- office IPs
- partner IPs
- verified bots
- mTLS-authenticated clients
- specific non-public admin paths

## 12.2 Recommended Exception Fields

| Exception type | Recommended expression |
|---|---|
| Trusted scanner IP list | `ip.src in $trusted_security_scanners` |
| Office network IP list | `ip.src in $office_network` |
| Exact internal path | `http.request.uri.path eq "/internal/healthcheck"` |
| Internal path prefix | `starts_with(http.request.uri.path, "/internal/")` |
| Verified bot exclusion | `cf.client.bot` |
| mTLS verified client | `cf.tls_client_auth.cert_verified` |

## 12.3 Skip Rule Pattern

```json
{
  "description": "Skip current custom rules for trusted security scanners",
  "expression": "ip.src in $trusted_security_scanners",
  "action": "skip",
  "action_parameters": {
    "ruleset": "current"
  },
  "enabled": true
}
```

## 12.4 Exclusion Inside Block Rule

```text
(
  lower(http.request.uri.query) contains "<script"
  or lower(http.request.uri.query) contains "union select"
)
and not ip.src in $trusted_security_scanners
```

## 12.5 Exception Rule Checklist

- [ ] Exception is narrower than enforcement rule.
- [ ] Trusted IPs use named lists or inline IP sets.
- [ ] Skip rule is placed before enforcement rules.
- [ ] Spoofable headers are not used as sole trust signals.
- [ ] Exception scope includes host/path/method where possible.
- [ ] Rule description clearly states why the exception exists.

---

# 13. Rule Order and Evaluation Considerations

## 13.1 Why Rule Order Matters

Dashboard custom rules are evaluated in order within their ruleset or phase. A skip rule must be placed before the rules it should skip.

Rule-generation implication:

- generate skip exceptions before block rules
- keep broad block rules after narrow allow/skip/tuning rules
- document where the rule should be placed

## 13.2 Recommended Ordering Pattern

1. Trusted scanner or internal source skip rules.
2. Narrow false-positive exceptions.
3. High-confidence block rules.
4. Challenge rules.
5. Log-only validation rules.

## 13.3 Example Ordering

### Rule 1: Skip trusted scanners

```json
{
  "description": "Skip trusted scanners",
  "expression": "ip.src in $trusted_security_scanners",
  "action": "skip",
  "action_parameters": {
    "ruleset": "current"
  },
  "enabled": true
}
```

### Rule 2: Block XSS in query string

```json
{
  "description": "Block XSS indicators in query string",
  "expression": "lower(http.request.uri.query) contains \"<script\" or lower(http.request.uri.query) contains \"onerror=\"",
  "action": "block",
  "enabled": true
}
```

## 13.4 Rule Order Checklist

- [ ] Skip rules precede block rules.
- [ ] Specific rules precede broad rules.
- [ ] Draft or log validation is used for broad rules.
- [ ] Action precedence is understood before deployment.
- [ ] Generated instructions tell the user where to place the rule.

---

# 14. Dashboard-to-API Translation Reference

## 14.1 Dashboard Fields to JSON Fields

| Dashboard item | API/ruleset JSON equivalent |
|---|---|
| Rule name | `description` |
| When incoming requests match | `expression` |
| Choose action | `action` |
| Custom response type | `action_parameters.response.content_type` |
| Custom response code | `action_parameters.response.status_code` |
| Response body | `action_parameters.response.content` |
| Deploy / enabled state | `enabled` |

## 14.2 Basic Rule JSON

```json
{
  "description": "Block XSS indicators in query string",
  "expression": "lower(http.request.uri.query) contains \"<script\"",
  "action": "block",
  "enabled": true
}
```

## 14.3 Rule JSON with Custom Response

```json
{
  "description": "Block request with JSON response",
  "expression": "lower(http.request.uri.query) contains \"<script\"",
  "action": "block",
  "action_parameters": {
    "response": {
      "status_code": 403,
      "content_type": "application/json",
      "content": "{\"error\":\"request_blocked\",\"message\":\"The request was blocked by security policy.\"}"
    }
  },
  "enabled": true
}
```

## 14.4 Rule JSON with Skip Action

```json
{
  "description": "Skip current custom rules for trusted scanner IPs",
  "expression": "ip.src in $trusted_security_scanners",
  "action": "skip",
  "action_parameters": {
    "ruleset": "current"
  },
  "enabled": true
}
```

## 14.5 Translation Checklist

- [ ] Dashboard rule name becomes JSON `description`.
- [ ] Dashboard Field/Operator/Value becomes JSON `expression`.
- [ ] Dashboard action becomes JSON `action`.
- [ ] Block custom response becomes JSON `action_parameters.response`.
- [ ] `enabled` is true for deployed rules.
- [ ] Draft state should not be treated as production enforcement.
- [ ] Escape JSON strings correctly.

---

# 15. Complete Dashboard Workflow for Rule Generation

## 15.1 Workflow: Generate and Configure a Cloudflare WAF Rule

1. Identify the attack type:
   - XSS
   - SQLi
   - LFI
   - RCE
   - SSRF
   - bot/scanner
   - policy violation
2. Identify payload location:
   - query string
   - query parameter
   - URI path
   - header
   - cookie
   - request body
   - source IP
3. Choose the Field:
   - `http.request.uri.query`
   - `http.request.uri.args["param"][*]`
   - `raw.http.request.uri.query`
   - `http.request.uri.path`
   - `http.request.headers["name"][*]`
   - `http.cookie`
   - `ip.src`
4. Choose the Operator:
   - `contains` for stable literal
   - `matches` for regex if supported
   - `eq` for exact values
   - `in` for lists
   - `gt` / `lt` for score or size
5. Choose the Value:
   - specific payload indicators
   - exact route/host/method
   - named list
   - regex raw string
6. Add scope:
   - host
   - path
   - method
   - parameter
   - IP
7. Choose the action:
   - `block`
   - `managed_challenge`
   - `log`
   - `skip`
8. Configure custom response if action is `block` and custom response is needed.
9. Save as draft if validation is incomplete.
10. Deploy when ready.

## 15.2 Generated Output Template

Use this template when generating Cloudflare dashboard rule instructions:

```markdown
## Rule Objective

Describe the attack type, payload location, and intended action.

## Dashboard Configuration

- Rule name:
- Field:
- Operator:
- Value:
- Action:
- Custom response:

## Expression Editor Version

Provide a Cloudflare Rules language expression.

## Rule JSON Version

Provide JSON with `description`, `expression`, `action`, optional `action_parameters`, and `enabled`.

## Deployment Steps

1. Go to Cloudflare dashboard > Security rules.
2. Select Create rule > Custom rules.
3. Enter the rule name.
4. Under When incoming requests match, use Field/Operator/Value or Expression Editor.
5. Under Then take action, select the action.
6. Configure custom response if action is Block.
7. Select Save as Draft or Deploy.

## Tuning Notes

Explain false positives, exceptions, rule order, and whether to log/challenge before blocking.
```

---

# 16. Common Dashboard Configuration Mistakes and Corrections

## 16.1 Mistake: Vague Rule Name

Bad:

```text
Block bad requests
```

Better:

```text
Block SQLi indicators in query string on /api/search
```

## 16.2 Mistake: Broad Query Match Without Scope

Risky:

```text
lower(http.request.uri.query) contains "select"
```

Better:

```text
starts_with(http.request.uri.path, "/api/search")
and lower(http.request.uri.query) matches r"(union\s+select|or\s+1\s*=\s*1|sleep\s*\()"
```

## 16.3 Mistake: Using Regex Without Plan Check

Incomplete:

```text
lower(http.request.uri.query) matches r"(<script|onerror\s*=)"
```

Better output includes fallback:

```text
lower(http.request.uri.query) contains "<script"
or lower(http.request.uri.query) contains "onerror="
```

## 16.4 Mistake: Custom Response Without Block Action

Incorrect concept:

```text
managed_challenge with custom response body
```

Correct:

```text
Custom response is configured only when the selected action is Block.
```

## 16.5 Mistake: Invalid Custom Response Code

Incorrect:

```json
"status_code": 200
```

Correct:

```json
"status_code": 403
```

Allowed range:

```text
400-499
```

## 16.6 Mistake: Response Body Too Large

Incorrect:

```text
Response body larger than 2 KB
```

Correct:

```text
Keep WAF custom rule block response body at or below 2 KB.
```

## 16.7 Mistake: Revealing Detection Logic in Response Body

Risky response:

```json
{
  "message": "Blocked because query matched union select regex"
}
```

Safer response:

```json
{
  "error": "request_blocked",
  "message": "The request was blocked by security policy."
}
```

## 16.8 Mistake: Skip Rule After Block Rule

Incorrect order:

1. Block SQLi.
2. Skip trusted scanners.

Correct order:

1. Skip trusted scanners.
2. Block SQLi.

## 16.9 Mistake: Deploying Broad Rule Immediately

Risky:

```text
Deploy broad block rule without validation.
```

Safer:

```text
Save as Draft or use log/challenge validation before block enforcement where available.
```

---

# 17. Final Checklist for Cloudflare Dashboard Custom Rule Configuration

- [ ] Rule name is descriptive and attack-specific.
- [ ] Field matches the observed payload location.
- [ ] Operator matches the comparison type.
- [ ] Value is specific enough for security use.
- [ ] Expression uses `lower()` for case-varying payloads.
- [ ] Expression uses raw fields or `url_decode()` for encoded payloads.
- [ ] Expression uses `any()` for arrays.
- [ ] Expression uses `in` for IP lists and CIDR ranges.
- [ ] Expression avoids broad literals such as `"select"` or `"on"` alone.
- [ ] Expression is scoped by path, host, method, parameter, or IP when possible.
- [ ] Regex support is verified or a `contains` fallback is provided.
- [ ] Action is selected based on confidence and false-positive risk.
- [ ] Custom response is configured only for `Block`.
- [ ] Custom response type is valid.
- [ ] Custom response code is between `400` and `499`.
- [ ] Custom response body is under `2 KB`.
- [ ] Custom response body does not reveal WAF detection internals.
- [ ] Skip rules are placed before block rules.
- [ ] Rule is saved as draft if validation is incomplete.
- [ ] Rule is deployed only after review and testing.
