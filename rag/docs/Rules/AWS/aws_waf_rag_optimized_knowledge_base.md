# Part 3 - Optimized AWS WAF Knowledge Base for SQL Injection and XSS Rule Generation

## 10. Retrieval Index Card: AWS WAF SQL Injection and XSS Protection Overview

**Retrieval keywords:** AWS WAF, SQL injection, SQLI, cross-site scripting, XSS, rule statement, custom rule, managed rule group, request component, text transformation, Count, Block.

AWS WAF can help prevent SQL injection and cross-site scripting attacks using two main approaches:

1. **Built-in attack match statements**
   - Use an `SqliMatchStatement` to inspect for malicious SQL code in a selected web request component.
   - Use an `XssMatchStatement` to inspect for malicious scripts in a selected web request component.
   - These are appropriate when the system needs custom rule logic, precise request-component selection, explicit text transformations, and controlled rule actions.

2. **AWS Managed Rules**
   - Use AWS Managed Rules when the goal is to protect against application vulnerabilities or unwanted traffic without writing every rule manually.
   - Use the `SQL database` managed rule group for SQL injection protection.
   - Use the `Core rule set (CRS)` managed rule group for general web application protection, including XSS-related protections.

> **Important:** Before production enforcement, test new or changed AWS WAF rules in a non-production environment or in production `Count` mode. Use AWS WAF logs and Amazon CloudWatch metrics to evaluate matches and false positives. After testing and tuning, change the rule action to `Block`.

> **Important:** AWS WAF has maximum inspection limits for request bodies, headers, cookies, and other large components. If a rule inspects `Body`, `JSON Body`, `Headers`, or `Cookies`, configure or account for oversize handling.

---

## 11. AWS WAF Built-In SQL Injection Match Statement (`SqliMatchStatement`)

**Retrieval keywords:** AWS WAF, SQL injection, SQLI, SqliMatchStatement, FieldToMatch, TextTransformations, SensitivityLevel, query string, body, cookies, headers, URL decode, lowercase, false positives.

### Definition

An AWS WAF SQL injection attack rule statement inspects a selected web request component for malicious SQL code. Attackers insert SQL code into requests to modify or extract data from a database.

### Required rule components

A valid `SqliMatchStatement` requires:

| Component | Requirement | Rule-generation meaning |
|---|---|---|
| `FieldToMatch` | Required | Defines the part of the request AWS WAF inspects. Use one request component per statement. To inspect multiple components, create multiple statements and combine them with `OR`. |
| `TextTransformations` | Required | Defines normalization steps applied before inspection. Multiple transformations run from lowest priority to highest priority. |
| `SensitivityLevel` | Optional | Controls SQLi detection sensitivity. Valid values are `LOW` and `HIGH`. Default is `LOW`. |

### Sensitivity guidance

| Sensitivity | Use when | Trade-off |
|---|---|---|
| `HIGH` | You want stronger SQL injection detection and can tolerate more tuning | Detects more attacks but may generate more false positives |
| `LOW` | The application already has strong SQLi defenses or has low false-positive tolerance | Fewer false positives but less aggressive detection |

For bypassed SQL injection payloads containing signals such as `union select`, SQL comments, URL encoding, double URL encoding, case randomization, `sleep`, `benchmark`, or unusual whitespace, start with `HIGH` in `Count` mode, evaluate false positives, then move to `Block` when tuned.

### Console location

In the AWS WAF rule builder:

1. Choose a custom rule.
2. Under `Statement`, choose the request component to inspect.
3. For match type, choose `Attack match condition > Contains SQL injection attacks`.
4. Configure text transformations.
5. Use `Count` while testing; change to `Block` after validation.

### JSON pattern for a SQL injection match statement

```json
{
  "SqliMatchStatement": {
    "FieldToMatch": {
      "AllQueryArguments": {}
    },
    "TextTransformations": [
      {
        "Priority": 0,
        "Type": "URL_DECODE"
      },
      {
        "Priority": 1,
        "Type": "HTML_ENTITY_DECODE"
      },
      {
        "Priority": 2,
        "Type": "LOWERCASE"
      },
      {
        "Priority": 3,
        "Type": "COMPRESS_WHITE_SPACE"
      }
    ],
    "SensitivityLevel": "HIGH"
  }
}
```

### Rule-generation instruction

When generating an AWS WAF SQL injection rule:

- Prefer `AllQueryArguments` for SQL injection in query parameters.
- Use `Body` or `JsonBody` when payloads are submitted through forms or JSON APIs.
- Add separate statements for multiple request components and combine them with `OrStatement`.
- Use transformations that match the observed bypass style.
- Use `Count` during testing and `Block` for enforcement.
- Include false-positive notes when `SensitivityLevel` is `HIGH`.

---

## 12. AWS WAF Built-In XSS Match Statement (`XssMatchStatement`)

**Retrieval keywords:** AWS WAF, XSS, cross-site scripting, XssMatchStatement, FieldToMatch, TextTransformations, onerror, onload, script, svg, img, javascript, query string, body, cookies, headers.

### Definition

An AWS WAF XSS attack rule statement inspects a selected web request component for malicious scripts. In an XSS attack, an attacker uses a vulnerable website to inject malicious client-side scripts into legitimate browsers.

### Required rule components

A valid `XssMatchStatement` requires:

| Component | Requirement | Rule-generation meaning |
|---|---|---|
| `FieldToMatch` | Required | Defines the part of the request AWS WAF inspects. Use one request component per statement. To inspect multiple components, create multiple statements and combine them with `OR`. |
| `TextTransformations` | Required | Defines normalization steps applied before inspection. Multiple transformations run from lowest priority to highest priority. |

### WCU and transformation considerations

- XSS match statements have a base WCU cost.
- Additional WCU applies for some request components such as all query parameters or JSON body.
- Each text transformation adds additional WCU.
- Keep transformations purposeful: they should correspond to observed evasion in bypassed payloads.

### Console location

In the AWS WAF rule builder:

1. Choose a custom rule.
2. Under `Statement`, choose the request component to inspect.
3. For match type, choose `Attack match condition > Contains XSS injection attacks`.
4. Configure text transformations.
5. Use `Count` while testing; change to `Block` after validation.

### JSON pattern for an XSS match statement

```json
{
  "XssMatchStatement": {
    "FieldToMatch": {
      "AllQueryArguments": {}
    },
    "TextTransformations": [
      {
        "Priority": 0,
        "Type": "URL_DECODE"
      },
      {
        "Priority": 1,
        "Type": "HTML_ENTITY_DECODE"
      },
      {
        "Priority": 2,
        "Type": "LOWERCASE"
      },
      {
        "Priority": 3,
        "Type": "COMPRESS_WHITE_SPACE"
      }
    ]
  }
}
```

### Rule-generation instruction

When generating an AWS WAF XSS rule:

- If payloads contain `onerror`, `onload`, `onclick`, `img`, `svg`, `script`, `alert`, `javascript:`, or HTML entity encoding, use `XssMatchStatement`.
- Choose `AllQueryArguments` for reflected XSS in query parameters.
- Choose `Body` or `JsonBody` for form submission, stored XSS, comment fields, profile fields, or JSON APIs.
- Choose `Headers`, `SingleHeader`, or `Cookies` only when payloads actually appear there or application traffic requires it.
- Apply `URL_DECODE`, `HTML_ENTITY_DECODE`, `LOWERCASE`, and `COMPRESS_WHITE_SPACE` when bypass payloads use URL encoding, entity encoding, case mutation, or whitespace obfuscation.

---

## 13. AWS WAF Request Components (`FieldToMatch`) for Rule Generation

**Retrieval keywords:** AWS WAF, FieldToMatch, request component, QueryString, AllQueryArguments, Body, JsonBody, Headers, Cookies, SingleHeader, SingleQueryArgument, UriPath, inspect.

`FieldToMatch` defines which part of the web request a rule statement inspects. A single statement inspects one request component. To inspect multiple components, generate multiple statements and combine them using an `OrStatement`.

| FieldToMatch option | Use for | Rule-generation guidance |
|---|---|---|
| `QueryString` | Entire query string after `?` | Good when payload may appear across raw query string structure. |
| `AllQueryArguments` | All query parameter names/values | Strong default for SQL injection or reflected XSS in URL parameters. |
| `SingleQueryArgument` | One named query parameter | Use when the vulnerable parameter is known, such as `q`, `search`, `id`, `comment`, or `redirect`. |
| `UriPath` | URL path only, excluding query string | Use when payload is embedded in path segments. |
| `Body` | Plain request body | Use for form posts and non-JSON bodies. Must consider body inspection limits and oversize handling. |
| `JsonBody` | JSON body | Use for JSON APIs. Transformations apply after JSON parsing and extraction. Must consider body inspection limits and oversize handling. |
| `Headers` | Multiple request headers | Use only when payloads occur in headers. Must configure filters and oversize handling. |
| `SingleHeader` | One named header | Use for targeted header inspection such as `User-Agent` or `Referer`. Header name is not case sensitive. |
| `Cookies` | Request cookies | Use when payloads are in cookies. Must consider cookie inspection limits and oversize handling. |
| `Method` | HTTP method | Rarely useful for SQLi/XSS directly; useful in logical rules. |

### Multi-component inspection pattern

Use an `OrStatement` when the same attack may appear in multiple request components.

```json
{
  "OrStatement": {
    "Statements": [
      {
        "XssMatchStatement": {
          "FieldToMatch": { "AllQueryArguments": {} },
          "TextTransformations": [
            { "Priority": 0, "Type": "URL_DECODE" },
            { "Priority": 1, "Type": "HTML_ENTITY_DECODE" },
            { "Priority": 2, "Type": "LOWERCASE" }
          ]
        }
      },
      {
        "XssMatchStatement": {
          "FieldToMatch": {
            "Body": {
              "OversizeHandling": "MATCH"
            }
          },
          "TextTransformations": [
            { "Priority": 0, "Type": "URL_DECODE" },
            { "Priority": 1, "Type": "HTML_ENTITY_DECODE" },
            { "Priority": 2, "Type": "LOWERCASE" }
          ]
        }
      }
    ]
  }
}
```

### Rule-generation instruction

When bypassed payload location is unknown, prefer a conservative multi-component strategy:

1. Inspect `AllQueryArguments`.
2. Inspect `Body` or `JsonBody` if the application accepts POST or JSON input.
3. Inspect `Cookies` only if payloads or app flows use cookies for user-controlled content.
4. Inspect `Headers` only if payloads are delivered through headers.
5. Use separate statements for separate components.

---

## 14. AWS WAF Text Transformations for Bypass Normalization

**Retrieval keywords:** AWS WAF, TextTransformations, URL_DECODE, HTML_ENTITY_DECODE, LOWERCASE, COMPRESS_WHITE_SPACE, CSS_DECODE, JS_DECODE, SQL_HEX_DECODE, URL_DECODE_UNI, bypass normalization.

Text transformations reformat a request component before inspection. They reduce evasion caused by unusual encoding, casing, escaping, comments, null bytes, or whitespace.

AWS WAF applies multiple transformations from the lowest priority number to the highest priority number before inspecting the transformed request component.

### Common transformations for XSS and SQL injection bypass payloads

| Bypass signal in payload | Recommended transformation candidates | Why it helps |
|---|---|---|
| URL encoding such as `%3c`, `%3e`, `%27`, `%22` | `URL_DECODE` | Decodes URL-encoded characters before inspection. |
| Double URL encoding or Unicode URL encoding | `URL_DECODE`, possibly `URL_DECODE_UNI` | Helps expose encoded attack tokens. |
| HTML entities such as `&lt;script&gt;` or encoded event handlers | `HTML_ENTITY_DECODE` | Converts HTML entities to inspectable characters. |
| Random casing such as `UnIoN SeLeCt` or `OnErRoR` | `LOWERCASE` | Normalizes casing before matching. |
| Newlines, tabs, excess whitespace, encoded whitespace | `COMPRESS_WHITE_SPACE` | Normalizes whitespace used to split tokens. |
| JavaScript escape sequences | `JS_DECODE` | Helps expose escaped JavaScript XSS payloads. |
| CSS escape sequences | `CSS_DECODE` | Helps expose CSS-escaped XSS strings such as obfuscated `javascript`. |
| SQL hex encoding | `SQL_HEX_DECODE` | Helps expose SQL payloads encoded in hex. |
| SQL comments used for obfuscation | `REPLACE_COMMENTS` | Replaces comments to reduce SQL comment evasion. |
| Null byte evasion | `REMOVE_NULLS` or `REPLACE_NULLS` | Handles null-byte obfuscation. |

### Recommended baseline transformation chain for URL/body XSS bypasses

```json
[
  { "Priority": 0, "Type": "URL_DECODE" },
  { "Priority": 1, "Type": "HTML_ENTITY_DECODE" },
  { "Priority": 2, "Type": "LOWERCASE" },
  { "Priority": 3, "Type": "COMPRESS_WHITE_SPACE" }
]
```

### Recommended baseline transformation chain for SQL injection bypasses

```json
[
  { "Priority": 0, "Type": "URL_DECODE" },
  { "Priority": 1, "Type": "LOWERCASE" },
  { "Priority": 2, "Type": "COMPRESS_WHITE_SPACE" },
  { "Priority": 3, "Type": "REPLACE_COMMENTS" }
]
```

### Rule-generation instruction

When generating a rule, choose transformations based on observed bypass evidence:

- For `obf_url_encode` or `%xx` tokens, include `URL_DECODE`.
- For HTML entity encoded XSS, include `HTML_ENTITY_DECODE`.
- For mixed-case attack tokens, include `LOWERCASE`.
- For whitespace splitting or newline/tab bypasses, include `COMPRESS_WHITE_SPACE`.
- For SQL comment bypasses, include `REPLACE_COMMENTS`.
- For JavaScript or CSS escape patterns, add `JS_DECODE` or `CSS_DECODE`.
- Keep priorities unique and ordered from lowest to highest.

---

## 15. AWS WAF Console Procedure: Create a Single SQL Injection or XSS Custom Rule

**Retrieval keywords:** AWS WAF console, custom rule, SQL injection, XSS, Contains SQL injection attacks, Contains XSS injection attacks, BLOCK, Count, rule action, request component, text transformation.

### Purpose

Use this procedure when generating a custom AWS WAF rule that uses the built-in SQL injection or XSS detection engine for one request component.

### Procedure

1. Open the AWS WAF console.
2. In the navigation pane, choose `AWS WAF`.
3. Choose `Resources & protection packs`.
4. Find the relevant protection pack and choose `View and edit` beside `Rules`.
5. In the right pane, choose `Add rules`.
6. Choose `Custom rule`, then choose `Next`.
7. Choose `Custom rule` again, then choose `Next`.
8. Set the rule action:
   - Use `Count` for testing and tuning.
   - Use `Block` after validation.
9. Enter a clear rule name, such as:
   - `Block_XSS_AllQueryArguments_Normalized`
   - `Block_SQLI_Body_HighSensitivity`
10. For `If a request`, choose `Matches the statement`.
11. Under `Statement`, for `Inspect`, select the request component that the rule should evaluate.
12. For `Match Type`, select one of:
   - `Contains SQL injection attacks`
   - `Contains XSS injection attacks`
13. Choose text transformations that match observed bypass techniques.
14. Create the rule.

### Generation note

The generated rule should explicitly describe:

- selected request component
- match type
- text transformations
- rule action
- testing mode versus enforcement mode
- expected false-positive risk

---

## 16. AWS WAF Console Procedure: Create a Multi-Component SQL Injection or XSS Custom Rule

**Retrieval keywords:** AWS WAF, OR statement, multiple request components, query string, body, headers, cookies, SQL injection, XSS, text transformation.

### Purpose

Use this procedure when the same SQL injection or XSS attack may appear in multiple request components.

### Procedure

1. Open the AWS WAF console.
2. In the navigation pane, choose `AWS WAF`.
3. Choose `Resources & protection packs`.
4. Find the relevant protection pack and choose `View and edit` beside `Rules`.
5. In the right pane, choose `Add rules`.
6. Choose `Custom rule`, then choose `Next`.
7. Choose `Custom rule` again, then choose `Next`.
8. Set the rule action:
   - Use `Count` for testing and tuning.
   - Use `Block` after validation.
9. Enter a clear rule name.
10. For `If a request`, choose `matches at least one of the statements (OR)`.
11. Under `Statement 1`, choose the first request component to inspect.
12. For `Match Type`, select `Contains SQL injection attacks` or `Contains XSS injection attacks`.
13. Choose text transformations.
14. Under `Statement 2`, choose the second request component to inspect.
15. For `Match Type`, select the same attack match type or the relevant one for that component.
16. Choose text transformations.
17. Add additional statements for additional components if needed.
18. Create the rule.

### Recommended multi-component patterns

| Attack scenario | Recommended request components |
|---|---|
| Reflected XSS in URL parameters | `AllQueryArguments`, optionally `QueryString` |
| Stored XSS through forms | `Body` or `JsonBody`, plus `AllQueryArguments` if forms include query params |
| SQL injection in `id`, `search`, or `q` parameter | `SingleQueryArgument` if known, otherwise `AllQueryArguments` |
| SQL injection in JSON API body | `JsonBody`, optionally `AllQueryArguments` |
| Payloads in cookies | `Cookies` with explicit oversize handling |
| Payloads in headers | `Headers` or `SingleHeader` with explicit oversize handling |

> **Important:** For the rule to work against obfuscated payloads, apply the correct text transformations. For cookie inspection involving URL-encoded or HTML-encoded values, use transformations such as `URL_DECODE`, `HTML_ENTITY_DECODE`, and `LOWERCASE`.

---

## 17. AWS WAF Oversize Handling for Body, Headers, and Cookies

**Retrieval keywords:** AWS WAF, oversize handling, Body, JsonBody, Headers, Cookies, MATCH, CONTINUE, NO_MATCH, inspection limit, 8 KB, 16 KB, 64 KB, Block oversized components.

AWS WAF cannot inspect unlimited request content for large components. Body, JSON body, headers, and cookies have size and count limits depending on the protected resource type.

### Inspection limits relevant to rule generation

| Component | Limit summary | Generation consequence |
|---|---|---|
| `Body` / `JsonBody` for Application Load Balancer and AWS AppSync | First 8 KB | Rules cannot inspect body bytes beyond the limit. |
| `Body` / `JsonBody` for CloudFront, API Gateway, Cognito, App Runner, Verified Access | Default first 16 KB; configurable up to 64 KB for some resources | Configure body inspection size when needed. |
| `Headers` | First 8 KB and first 200 headers | Must configure oversize handling when inspecting all headers. |
| `Cookies` | First 8 KB and first 200 cookies | Must configure oversize handling when inspecting cookies. |

### Oversize handling options

| Option | Meaning | When to use |
|---|---|---|
| `CONTINUE` | Inspect only the portion AWS WAF receives within limits | Use when partial inspection is acceptable. |
| `MATCH` | Treat oversize component as matching the statement | Use with `Block` to block oversized components. |
| `NO_MATCH` | Treat oversize component as not matching the statement | Use carefully, because oversized attack payloads may pass this rule. |

### Rule-generation instruction

When generating an AWS WAF rule that inspects `Body`, `JsonBody`, `Headers`, or `Cookies`:

- Include an oversize-handling decision.
- If the security goal is strict blocking, use `MATCH` with `Block` for oversized content.
- If the application legitimately sends large bodies or cookies, recommend testing in `Count` mode and creating explicit allow rules before blocking oversize content.
- Place oversize-blocking rules before managed rule groups or custom body/header/cookie inspection rules that might otherwise allow oversized components.

### Example body oversize block concept

```json
{
  "SizeConstraintStatement": {
    "FieldToMatch": {
      "Body": {
        "OversizeHandling": "MATCH"
      }
    },
    "ComparisonOperator": "GT",
    "Size": 8192,
    "TextTransformations": [
      { "Priority": 0, "Type": "NONE" }
    ]
  }
}
```

---

## 18. AWS Managed Rules for SQL Injection and XSS Protection

**Retrieval keywords:** AWS WAF, AWS Managed Rules, SQL database managed rule group, Core rule set, CRS, AWSManagedRulesCommonRuleSet, managed rule group, false positives, Count mode, rule action override.

### When to use managed rule groups

Use AWS Managed Rules when you want predefined, maintained protection without writing every individual custom rule.

Recommended managed rule groups for this document:

| Protection goal | Managed rule group |
|---|---|
| SQL injection protection | SQL database managed rule group |
| XSS and broad web application vulnerability protection | Core rule set (CRS) managed rule group |

### Core rule set details useful for retrieval and generation

The Core rule set managed rule group provides baseline protection for common web application vulnerabilities and is generally applicable to many applications. It can help cover high-risk and commonly occurring vulnerabilities. It has vendor/name metadata such as:

```text
VendorName: AWS
Name: AWSManagedRulesCommonRuleSet
```

The Core rule set includes labels and rules such as size restrictions and other common threat detections. Labels can be used by later rules in the same web ACL.

### Managed rule group testing guidance

Before using a managed rule group in production:

1. Add the managed rule group in a non-production environment or with rule actions overridden to `Count`.
2. Monitor AWS WAF logs and CloudWatch metrics.
3. Identify false positives.
4. Use rule action overrides, scope-down statements, or exclusions when needed.
5. Move selected rules or the whole group to enforcement only after tuning.

### Add an AWS Managed Rules rule group to a web ACL

1. Open the AWS WAF console.
2. In the navigation pane, choose `AWS WAF`.
3. Choose `Resources & protection packs`.
4. Find the relevant protection pack and choose `View and edit` beside `Rules`.
5. In the right pane, choose `Add rule`.
6. Choose `AWS-managed rule group`, then choose `Next`.
7. Select the `SQL database` managed rule group for SQL injection protection or the `Core rule set` managed rule group for XSS/general baseline protection.
8. For initial testing, override actions to `Count` where appropriate.
9. Create the rule.

---

## 19. Managed Rule Group Versioning and Overrides

**Retrieval keywords:** AWS WAF, managed rule group version, default version, static version, version expiration, SNS notifications, rule action override, Count, false positives, scope-down statement.

Managed rule group providers can update rule groups over time. Some managed rule groups are versioned. A web ACL can use either:

- the provider-managed default version, or
- a specific static version.

### Versioning guidance

| Choice | Behavior | Use when |
|---|---|---|
| Default version | Provider controls recommended version and can update it | You want automatic updates and accept provider-managed changes |
| Static version | You pin a specific version until it expires or is changed | You need stability and controlled rollouts |

### Best practices

- Subscribe to notifications for version changes when available.
- Test new versions in `Count` mode or non-production before enforcement.
- Use rule action overrides to manage false positives.
- Use scope-down statements when the managed group should only apply to a subset of traffic.
- Retrieve available versions through the console, API, or CLI when you need to pin or inspect a version.

### Generation instruction

When recommending managed rule groups, include:

- the managed group purpose
- whether to start in `Count` mode
- how to handle false positives
- whether version pinning or default version is safer for the deployment
- how to override individual rule actions if required

---

## 20. Rule Action Strategy: Count First, Block After Tuning

**Retrieval keywords:** AWS WAF, rule action, Count, Block, false positive, tuning, CloudWatch metrics, WAF logs, sampled requests.

### Rule action meanings

| Action | Meaning | Use during generation |
|---|---|---|
| `Count` | Records matches but does not block requests | Default for testing new rules or managed groups |
| `Block` | Terminates matching requests | Use after validation and false-positive tuning |
| `Allow` | Allows matching requests | Use for explicit allowlist rules before blocking rules if necessary |

### Recommended deployment flow

1. Generate the rule with `Count` action first.
2. Enable logging and metrics.
3. Review sampled requests and CloudWatch metrics.
4. Adjust request components, transformations, sensitivity, and scope-down conditions.
5. Change action to `Block` when match quality is acceptable.

> **Warning:** Directly deploying broad SQLi or XSS rules in `Block` mode can cause false positives, especially for applications that legitimately accept code snippets, HTML, SQL-like text, template expressions, search syntax, or encoded content.

---

## 21. Rule Generation Decision Matrix

**Retrieval keywords:** AWS WAF, rule generation decision, XSS, SQLI, custom rule, managed rules, SqliMatchStatement, XssMatchStatement, RegexMatchStatement, ByteMatchStatement.

| Observed bypass evidence | Preferred AWS WAF rule mechanism | Required generation details |
|---|---|---|
| XSS payload with `script`, `onerror`, `onload`, `svg`, `img`, `javascript:` | `XssMatchStatement` | FieldToMatch, TextTransformations, Count/Block action |
| SQLi payload with `union select`, comments, `sleep`, `benchmark`, quotes, boolean logic | `SqliMatchStatement` | FieldToMatch, TextTransformations, SensitivityLevel, Count/Block action |
| Encoded payloads | Built-in attack statement plus transformations | Include `URL_DECODE`, `HTML_ENTITY_DECODE`, `LOWERCASE`, or other relevant transformations |
| Payload location unknown | Multi-component `OrStatement` | Inspect query args and body first; add headers/cookies only when relevant |
| High false-positive risk | Start in `Count` mode | Include tuning instructions and possible scope-down statement |
| Need broad baseline coverage | AWS Managed Rules | Use SQL database group and/or Core rule set; start with overrides to Count |
| Need exact application-specific pattern matching | Regex or byte match statement | Include exact string/regex, positional constraint, FieldToMatch, transformations |

---

## 22. Example: Generated AWS WAF XSS Rule for Reflected URL Parameter Bypass

**Retrieval keywords:** AWS WAF, XSS, reflected XSS, AllQueryArguments, URL_DECODE, HTML_ENTITY_DECODE, LOWERCASE, COMPRESS_WHITE_SPACE, onerror, svg, img, Block.

### Scenario

Bypassed payloads include XSS indicators such as:

```text
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
%3Cscript%3Ealert(1)%3C/script%3E
```

### Recommended statement

```json
{
  "Name": "Block_Normalized_XSS_QueryArguments",
  "Priority": 10,
  "Statement": {
    "XssMatchStatement": {
      "FieldToMatch": {
        "AllQueryArguments": {}
      },
      "TextTransformations": [
        { "Priority": 0, "Type": "URL_DECODE" },
        { "Priority": 1, "Type": "HTML_ENTITY_DECODE" },
        { "Priority": 2, "Type": "LOWERCASE" },
        { "Priority": 3, "Type": "COMPRESS_WHITE_SPACE" }
      ]
    }
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "BlockNormalizedXSSQueryArguments"
  }
}
```

### Why this rule matches the bypass

- `AllQueryArguments` inspects all query parameters where reflected XSS payloads commonly appear.
- `URL_DECODE` exposes `%3C`, `%3E`, and other URL-encoded HTML tokens.
- `HTML_ENTITY_DECODE` exposes entity-encoded tags and attributes.
- `LOWERCASE` normalizes case-randomized event handlers and tags.
- `COMPRESS_WHITE_SPACE` reduces whitespace-splitting evasion.
- `XssMatchStatement` uses AWS WAF's built-in XSS detection engine.

### False-positive notes

- Applications that accept user-submitted HTML, templates, code snippets, or rich text may generate false positives.
- Start with `Count` if production impact is uncertain.
- Scope down to vulnerable paths or parameters when possible.

---

## 23. Example: Generated AWS WAF SQL Injection Rule for Query Parameter Bypass

**Retrieval keywords:** AWS WAF, SQL injection, SQLI, SqliMatchStatement, AllQueryArguments, URL_DECODE, LOWERCASE, COMPRESS_WHITE_SPACE, REPLACE_COMMENTS, SensitivityLevel HIGH, union select, sleep, benchmark.

### Scenario

Bypassed payloads include SQL injection indicators such as:

```text
1 UNION SELECT NULL--
1/**/UNION/**/SELECT/**/password
1%27%20OR%201%3D1--
1; SELECT SLEEP(5)
```

### Recommended statement

```json
{
  "Name": "Block_Normalized_SQLI_QueryArguments",
  "Priority": 20,
  "Statement": {
    "SqliMatchStatement": {
      "FieldToMatch": {
        "AllQueryArguments": {}
      },
      "TextTransformations": [
        { "Priority": 0, "Type": "URL_DECODE" },
        { "Priority": 1, "Type": "LOWERCASE" },
        { "Priority": 2, "Type": "COMPRESS_WHITE_SPACE" },
        { "Priority": 3, "Type": "REPLACE_COMMENTS" }
      ],
      "SensitivityLevel": "HIGH"
    }
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "BlockNormalizedSQLIQueryArguments"
  }
}
```

### Why this rule matches the bypass

- `AllQueryArguments` inspects all query parameters where SQLi payloads often appear.
- `URL_DECODE` exposes URL-encoded quotes, spaces, and operators.
- `LOWERCASE` normalizes case-randomized SQL keywords.
- `COMPRESS_WHITE_SPACE` reduces whitespace obfuscation.
- `REPLACE_COMMENTS` helps handle SQL comment obfuscation.
- `SensitivityLevel: HIGH` increases detection coverage for evasive SQLi payloads.

### False-positive notes

- `HIGH` sensitivity may trigger on legitimate SQL-like or unusual search strings.
- Start in `Count` mode for production traffic validation.
- Scope down by URI path or parameter if false positives occur.

---

## 24. Example: Multi-Component AWS WAF Rule for XSS in Query Arguments and Body

**Retrieval keywords:** AWS WAF, XSS, OrStatement, AllQueryArguments, Body, OversizeHandling MATCH, TextTransformations, Count, Block.

### Scenario

The application accepts both URL parameters and form submissions, and bypassed XSS payloads may appear in either location.

### Recommended statement

```json
{
  "Name": "Block_XSS_QueryArguments_Or_Body",
  "Priority": 30,
  "Statement": {
    "OrStatement": {
      "Statements": [
        {
          "XssMatchStatement": {
            "FieldToMatch": {
              "AllQueryArguments": {}
            },
            "TextTransformations": [
              { "Priority": 0, "Type": "URL_DECODE" },
              { "Priority": 1, "Type": "HTML_ENTITY_DECODE" },
              { "Priority": 2, "Type": "LOWERCASE" },
              { "Priority": 3, "Type": "COMPRESS_WHITE_SPACE" }
            ]
          }
        },
        {
          "XssMatchStatement": {
            "FieldToMatch": {
              "Body": {
                "OversizeHandling": "MATCH"
              }
            },
            "TextTransformations": [
              { "Priority": 0, "Type": "URL_DECODE" },
              { "Priority": 1, "Type": "HTML_ENTITY_DECODE" },
              { "Priority": 2, "Type": "LOWERCASE" },
              { "Priority": 3, "Type": "COMPRESS_WHITE_SPACE" }
            ]
          }
        }
      ]
    }
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "BlockXSSQueryArgsOrBody"
  }
}
```

### Why this rule is useful for generation

This chunk contains the complete logic needed for rule synthesis:

- rule objective
- statement composition
- request components
- text transformations
- oversize handling
- action
- visibility configuration

---

## 25. Example: Managed Rules Baseline for SQLi and XSS

**Retrieval keywords:** AWS WAF, AWS Managed Rules, SQL database, Core rule set, CRS, AWSManagedRulesCommonRuleSet, SQL injection, XSS, Count, managed rule group.

### Recommended managed-rule baseline

Use managed rule groups when the user asks for a broad baseline defense rather than a custom rule for a specific bypass payload.

Recommended baseline:

1. Add the `SQL database` managed rule group for SQL injection protection.
2. Add the `Core rule set (CRS)` managed rule group for common web application vulnerabilities and XSS-related protections.
3. Start with rule actions overridden to `Count` where production risk is unknown.
4. Review AWS WAF logs, sampled requests, and CloudWatch metrics.
5. Tune false positives using rule overrides, exclusions, or scope-down statements.
6. Move to enforcement after validation.

### Generation instruction

When the user asks to generate a rule for specific bypassed payloads, prefer a custom `SqliMatchStatement` or `XssMatchStatement`. When the user asks for broad protection or does not want to write custom rules, recommend AWS Managed Rules with explicit testing and tuning instructions.

---

## 26. Final Rule-Generation Checklist for AWS WAF SQLi/XSS

**Retrieval keywords:** AWS WAF, generation checklist, SQL injection, XSS, FieldToMatch, TextTransformations, Count, Block, false positives, oversize handling.

Before finalizing a generated AWS WAF rule, verify all of the following:

- [ ] The attack type is explicit: `XSS` or `SQLI`.
- [ ] The WAF target is explicit: `AWS WAF`.
- [ ] The statement type is explicit: `XssMatchStatement`, `SqliMatchStatement`, managed rule group, regex match, or byte match.
- [ ] The request component is explicit in `FieldToMatch`.
- [ ] Multi-component inspection uses separate statements combined with `OrStatement`.
- [ ] Text transformations match the observed bypass techniques.
- [ ] Transformation priorities are unique and ordered.
- [ ] SQLi rules specify `SensitivityLevel` when relevant.
- [ ] Body, JSON body, headers, and cookies include an oversize-handling strategy.
- [ ] The initial deployment action is `Count` unless the user explicitly wants immediate blocking.
- [ ] The enforcement action is `Block` after testing.
- [ ] Visibility configuration enables sampled requests and CloudWatch metrics.
- [ ] False-positive risks are stated.
- [ ] Managed rules include versioning and override guidance when relevant.

---