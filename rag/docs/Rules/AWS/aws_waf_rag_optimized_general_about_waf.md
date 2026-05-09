# AWS WAF Rule Generation Knowledge Base: SQL Injection and Cross-Site Scripting
# 1. AWS WAF Core Concepts for Rule Generation
## 1.1 AWS WAF Web ACL / Protection Pack

An AWS WAF web ACL controls how protected AWS resources respond to HTTP and HTTPS requests. In the newer AWS WAF console, a web ACL may also be presented as a **protection pack**. A protection pack is still implemented as a standard AWS WAFv2 web ACL at the API level.

A web ACL contains:

- A default action.
- Custom rules.
- Managed rule groups.
- Optional custom responses.
- Visibility and logging configuration.
- Rule priorities that define evaluation order.

Protected resources can include:

- Amazon CloudFront distributions.
- Amazon API Gateway REST APIs.
- Application Load Balancers.
- AWS AppSync GraphQL APIs.
- Amazon Cognito user pools.
- AWS App Runner services.
- AWS Verified Access instances.
- AWS Amplify applications.

## 1.2 AWS WAF Rule

A rule defines:

- **Statement**: the condition to inspect in the web request.
- **Action**: what to do when the statement matches.
- **Priority**: the order in which AWS WAF evaluates the rule.
- **VisibilityConfig**: metrics and sampled request settings.

Rules can be defined directly inside a web ACL or inside reusable rule groups.

A rule is not a standalone AWS resource outside a web ACL or rule group.

## 1.3 AWS WAF Rule Statement

A rule statement defines the matching logic. For SQLi and XSS defense, the most important statement types are:

| Statement type | Use case |
|---|---|
| `SqliMatchStatement` | Built-in detection for malicious SQL code in a request component. |
| `XssMatchStatement` | Built-in detection for malicious scripts in a request component. |
| `RegexMatchStatement` | Custom regular expression matching against a selected request component. |
| `ByteMatchStatement` | Exact, contains, starts-with, ends-with, or word match against a request component. |
| `SizeConstraintStatement` | Detect oversized or suspiciously sized request components. |
| `LabelMatchStatement` | Match labels added by earlier rules or managed rule groups. |
| `AndStatement` | Require multiple statements to match. |
| `OrStatement` | Match if at least one nested statement matches. |
| `NotStatement` | Negate a nested statement, often useful for exclusions or false-positive tuning. |
| `ManagedRuleGroupStatement` | Use AWS Managed Rules or third-party managed rule groups. |

## 1.4 Rule Evaluation and Priority

AWS WAF evaluates rules in priority order, from lower numeric priority to higher numeric priority.

Generation rules:

- Place explicit allowlist or false-positive exclusion rules before broad blocking rules.
- Place oversize-blocking rules before rules or managed rule groups that inspect the same oversized component.
- Place label-consuming rules after the rules or managed rule groups that apply those labels.
- Keep priorities stable and explicit in generated JSON.

## 1.5 Rule Actions

AWS WAF rule actions include:

| Action | Meaning | Use in generated rules |
|---|---|---|
| `Count` | Count matching requests without terminating or blocking them. | Use for testing, tuning, and false-positive analysis. |
| `Block` | Block matching requests. | Use after validation or when the user explicitly requests enforcement. |
| `Allow` | Allow matching requests and stop later evaluation if terminating. | Use for explicit allowlists before broader block rules. |
| `Captcha` | Require CAPTCHA for matching requests. | Use for bot/human verification scenarios, not primary SQLi/XSS rule generation. |
| `Challenge` | Run a silent challenge for matching requests. | Use for bot mitigation scenarios, not primary SQLi/XSS rule generation. |

Recommended deployment pattern:

1. Generate the initial rule with `Count`.
2. Enable metrics and sampled requests.
3. Review AWS WAF logs and CloudWatch metrics.
4. Tune request components, transformations, sensitivity, and exclusions.
5. Change the rule action to `Block` after validation.

> **Warning:** Broad SQLi or XSS rules deployed directly in `Block` mode can produce false positives, especially for applications that legitimately accept HTML, JavaScript, SQL-like text, templates, encoded content, or rich text.

---

# 2. AWS WAF Request Components (`FieldToMatch`)

## 2.1 Definition

`FieldToMatch` specifies the part of the web request that AWS WAF inspects. Each rule statement that requires a request component can specify only **one** `FieldToMatch`.

To inspect multiple request components, generate multiple statements and combine them with `OrStatement`.

## 2.2 Common FieldToMatch Options for SQLi and XSS

| FieldToMatch | Description | Best use for rule generation |
|---|---|---|
| `AllQueryArguments` | Inspects all query parameter names and values. | Strong default for reflected XSS and SQL injection in URL parameters. |
| `QueryString` | Inspects the entire query string after `?`. | Use when payload spans raw query string structure or when parameter names are unknown. |
| `SingleQueryArgument` | Inspects one named query parameter. | Use when the vulnerable parameter is known, such as `id`, `q`, `search`, `redirect`, `comment`, or `username`. |
| `UriPath` | Inspects the request URI path. | Use when payload appears in path segments. |
| `Body` | Inspects plain request body. | Use for forms, POST bodies, and non-JSON input. Requires oversize handling. |
| `JsonBody` | Inspects JSON request body. | Use for JSON APIs. Requires match pattern and oversize handling. |
| `SingleHeader` | Inspects one named header. | Use for targeted header-based payloads, such as `User-Agent` or `Referer`. |
| `Headers` | Inspects multiple headers with filter configuration. | Use only when payload may appear across multiple headers. Requires oversize handling. |
| `Cookies` | Inspects request cookies. | Use when payloads appear in cookie names or values. Requires oversize handling. |
| `Method` | Inspects HTTP method. | Rarely useful for SQLi/XSS directly; useful in logical rules. |
| `UriFragment` | Inspects URI fragments when available to AWS WAF. | Use only when fragment inspection is relevant and configured. Requires oversize handling. |

## 2.3 FieldToMatch Selection Rules

When generating AWS WAF rules:

- Use `AllQueryArguments` for unknown parameter names in query-based SQLi or reflected XSS.
- Use `SingleQueryArgument` when the vulnerable parameter is known.
- Use `Body` for form submissions and plain POST bodies.
- Use `JsonBody` for JSON APIs.
- Use `SingleHeader` or `Headers` only when payloads are actually delivered through headers.
- Use `Cookies` only when payloads appear in cookie names or values.
- Use `UriPath` only when payloads appear in route/path segments.
- Use multiple statements with `OrStatement` when the payload location is uncertain.

## 2.4 FieldToMatch JSON Examples

### Inspect all query arguments

```json
{
  "FieldToMatch": {
    "AllQueryArguments": {}
  }
}
```

### Inspect a single query argument

```json
{
  "FieldToMatch": {
    "SingleQueryArgument": {
      "Name": "q"
    }
  }
}
```

### Inspect a single header

```json
{
  "FieldToMatch": {
    "SingleHeader": {
      "Name": "user-agent"
    }
  }
}
```

### Inspect URI path

```json
{
  "FieldToMatch": {
    "UriPath": {}
  }
}
```

### Inspect body with strict oversize handling

```json
{
  "FieldToMatch": {
    "Body": {
      "OversizeHandling": "MATCH"
    }
  }
}
```

### Inspect JSON body with strict oversize handling

```json
{
  "FieldToMatch": {
    "JsonBody": {
      "MatchPattern": {
        "All": {}
      },
      "MatchScope": "ALL",
      "InvalidFallbackBehavior": "EVALUATE_AS_STRING",
      "OversizeHandling": "MATCH"
    }
  }
}
```

---

# 3. Text Transformations for Bypass Normalization

## 3.1 Definition

Text transformations normalize request content before AWS WAF inspects it. They reduce bypass effectiveness caused by encoding, whitespace manipulation, mixed casing, comments, escape sequences, path tricks, and null bytes.

If multiple transformations are configured, AWS WAF applies them from the lowest `Priority` value to the highest. Priorities must be unique.

## 3.2 Transformation Selection by Bypass Signal

| Bypass signal | Recommended transformations | Rule-generation reason |
|---|---|---|
| URL encoding such as `%3C`, `%3E`, `%27`, `%22` | `URL_DECODE` | Exposes encoded HTML, quote, or SQL operator tokens. |
| Unicode URL encoding such as `%u003C` | `URL_DECODE_UNI` | Handles Microsoft-style `%u` encodings. |
| HTML entities such as `&lt;script&gt;`, `&#x3c;`, `&quot;` | `HTML_ENTITY_DECODE` | Converts HTML entities to inspectable characters. |
| Random casing such as `UnIoN`, `SeLeCt`, `OnErRoR` | `LOWERCASE` | Normalizes case before matching. |
| Excess spaces, tabs, newlines, non-breaking spaces | `COMPRESS_WHITE_SPACE` | Normalizes whitespace splitting and whitespace obfuscation. |
| CSS escapes such as `ja\vascript` | `CSS_DECODE` | Exposes CSS-escaped XSS payloads. |
| JavaScript escapes and ANSI C escapes | `JS_DECODE`, `ESCAPE_SEQ_DECODE` | Exposes JavaScript string escaping and C-style escape sequences. |
| SQL comments such as `/**/UNION/**/SELECT` | `REPLACE_COMMENTS` | Replaces C-style comments with spaces. |
| SQL hex payloads such as `0x414243` | `SQL_HEX_DECODE` | Decodes SQL hex data. |
| Null byte obfuscation | `REMOVE_NULLS` or `REPLACE_NULLS` | Removes or normalizes null bytes. |
| Path traversal or path normalization bypass | `NORMALIZE_PATH`, `NORMALIZE_PATH_WIN` | Normalizes repeated slashes, self references, and back references. |
| Base64-encoded suspicious content | `BASE64_DECODE` or `BASE64_DECODE_EXT` | Useful only when the application expects encoded user input. |

## 3.3 Baseline XSS Transformation Chain

Use this baseline for XSS payloads using URL encoding, HTML entity encoding, random casing, or whitespace splitting.

```json
[
  { "Priority": 0, "Type": "URL_DECODE" },
  { "Priority": 1, "Type": "HTML_ENTITY_DECODE" },
  { "Priority": 2, "Type": "LOWERCASE" },
  { "Priority": 3, "Type": "COMPRESS_WHITE_SPACE" }
]
```

Use optional additions when evidence exists:

```json
[
  { "Priority": 0, "Type": "URL_DECODE" },
  { "Priority": 1, "Type": "URL_DECODE_UNI" },
  { "Priority": 2, "Type": "HTML_ENTITY_DECODE" },
  { "Priority": 3, "Type": "JS_DECODE" },
  { "Priority": 4, "Type": "CSS_DECODE" },
  { "Priority": 5, "Type": "LOWERCASE" },
  { "Priority": 6, "Type": "COMPRESS_WHITE_SPACE" }
]
```

## 3.4 Baseline SQL Injection Transformation Chain

Use this baseline for SQL injection payloads using URL encoding, mixed casing, comments, or whitespace obfuscation.

```json
[
  { "Priority": 0, "Type": "URL_DECODE" },
  { "Priority": 1, "Type": "LOWERCASE" },
  { "Priority": 2, "Type": "COMPRESS_WHITE_SPACE" },
  { "Priority": 3, "Type": "REPLACE_COMMENTS" }
]
```

Use optional additions when evidence exists:

```json
[
  { "Priority": 0, "Type": "URL_DECODE" },
  { "Priority": 1, "Type": "URL_DECODE_UNI" },
  { "Priority": 2, "Type": "LOWERCASE" },
  { "Priority": 3, "Type": "COMPRESS_WHITE_SPACE" },
  { "Priority": 4, "Type": "REPLACE_COMMENTS" },
  { "Priority": 5, "Type": "SQL_HEX_DECODE" },
  { "Priority": 6, "Type": "REMOVE_NULLS" }
]
```

## 3.5 Transformation Generation Rules

When generating transformations:

- Always include at least one text transformation because AWS WAF statement APIs require `TextTransformations`.
- Use `NONE` only when no normalization is needed.
- Use unique priority values.
- Choose transformations based on observed payload evidence.
- Do not add excessive transformations without evidence because each transformation adds WCU cost.
- For evasive payloads, prefer a transformation chain that exposes the canonical attack string before the built-in match statement evaluates it.

---

# 4. SQL Injection Rule Generation with `SqliMatchStatement`

## 4.1 Definition

`SqliMatchStatement` inspects a selected request component for malicious SQL code. Attackers use SQL injection to modify database behavior, extract data, bypass authentication, or trigger database-side time delays.

## 4.2 Required Components

A valid `SqliMatchStatement` includes:

| Component | Required | Meaning |
|---|---:|---|
| `FieldToMatch` | Yes | The request component to inspect. |
| `TextTransformations` | Yes | Normalization steps applied before inspection. |
| `SensitivityLevel` | No | SQLi detection sensitivity. Valid values: `LOW`, `HIGH`. Default: `LOW`. |

## 4.3 SensitivityLevel Guidance

| SensitivityLevel | Use when | False-positive risk |
|---|---|---|
| `LOW` | Application has low false-positive tolerance or already has other SQLi defenses. | Lower |
| `HIGH` | Bypassed payloads are evasive or coverage is more important than false-positive minimization. | Higher |

Use `HIGH` for payloads containing:

- `union select`
- SQL comments such as `/**/`
- `or 1=1`
- `and 1=1`
- SQL time-delay functions such as `sleep` or `benchmark`
- SQL metadata access such as `information_schema`
- URL-encoded SQL syntax
- random casing
- whitespace splitting
- double URL encoding

## 4.4 WCU Considerations

For `SqliMatchStatement`:

- Base WCU depends on sensitivity:
  - `LOW`: lower base cost.
  - `HIGH`: higher base cost.
- Add WCU for `AllQueryArguments`.
- Double base WCU for `JsonBody`.
- Add WCU for each text transformation.

Generation instruction:

- Mention WCU trade-off when generating broad SQLi rules.
- Use `HIGH` only when justified by bypass evidence.
- Prefer specific `SingleQueryArgument` if the vulnerable parameter is known and false positives matter.

## 4.5 SQLi Rule for All Query Arguments

```json
{
  "Name": "Block_Normalized_SQLi_AllQueryArguments",
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
    "MetricName": "BlockNormalizedSQLiAllQueryArguments"
  }
}
```

## 4.6 SQLi Rule for a Known Parameter

Use this pattern when the vulnerable parameter is known, for example `id`, `q`, `search`, `product`, `category`, or `username`.

```json
{
  "Name": "Block_SQLi_SingleQueryArgument_id",
  "Priority": 21,
  "Statement": {
    "SqliMatchStatement": {
      "FieldToMatch": {
        "SingleQueryArgument": {
          "Name": "id"
        }
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
    "MetricName": "BlockSQLiSingleQueryArgumentId"
  }
}
```

## 4.7 SQLi Rule for JSON Body

Use this pattern when SQLi payloads are submitted through JSON APIs.

```json
{
  "Name": "Block_SQLi_JSONBody",
  "Priority": 22,
  "Statement": {
    "SqliMatchStatement": {
      "FieldToMatch": {
        "JsonBody": {
          "MatchPattern": {
            "All": {}
          },
          "MatchScope": "ALL",
          "InvalidFallbackBehavior": "EVALUATE_AS_STRING",
          "OversizeHandling": "MATCH"
        }
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
    "MetricName": "BlockSQLiJSONBody"
  }
}
```

## 4.8 SQLi Generation Checklist

Before finalizing a SQLi rule:

- [ ] `SqliMatchStatement` is used for built-in SQLi detection.
- [ ] `FieldToMatch` matches the observed payload location.
- [ ] Use `OrStatement` if multiple components must be inspected.
- [ ] Text transformations address observed bypass patterns.
- [ ] `SensitivityLevel` is set intentionally.
- [ ] Body, JSON body, headers, cookies, and URI fragments include oversize handling.
- [ ] Rule action starts as `Count` for testing unless enforcement is explicitly requested.
- [ ] False-positive risk is documented.

---

# 5. XSS Rule Generation with `XssMatchStatement`

## 5.1 Definition

`XssMatchStatement` inspects a selected request component for malicious client-side scripts. In XSS attacks, attackers inject scripts into web pages or request parameters so that legitimate users' browsers execute attacker-controlled code.

## 5.2 Required Components

A valid `XssMatchStatement` includes:

| Component | Required | Meaning |
|---|---:|---|
| `FieldToMatch` | Yes | The request component to inspect. |
| `TextTransformations` | Yes | Normalization steps applied before inspection. |

## 5.3 XSS Payload Signals

Use `XssMatchStatement` when bypassed payloads include signals such as:

- `<script>`
- `</script>`
- `alert(`
- `prompt(`
- `confirm(`
- `onerror`
- `onload`
- `onclick`
- `onmouseover`
- `svg`
- `img`
- `iframe`
- `src=`
- `href=`
- `javascript:`
- `document.cookie`
- URL-encoded HTML tags such as `%3Cscript%3E`
- HTML entity encoded tags or attributes
- case-randomized HTML or JavaScript
- whitespace-obfuscated event handlers

## 5.4 WCU Considerations

For `XssMatchStatement`:

- There is a base WCU cost.
- Add WCU for `AllQueryArguments`.
- Double base WCU for `JsonBody`.
- Add WCU for each text transformation.

Generation instruction:

- Use transformations based on observed bypass evidence.
- Prefer targeted `SingleQueryArgument`, `SingleHeader`, or scoped body inspection when false positives are likely.
- Use `Count` during validation for applications accepting HTML, rich text, or templates.

## 5.5 XSS Rule for All Query Arguments

```json
{
  "Name": "Block_Normalized_XSS_AllQueryArguments",
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
    "MetricName": "BlockNormalizedXSSAllQueryArguments"
  }
}
```

## 5.6 XSS Rule for Body

Use this pattern for stored XSS through forms, comments, profile fields, or rich text submissions.

```json
{
  "Name": "Block_Normalized_XSS_Body",
  "Priority": 11,
  "Statement": {
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
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "BlockNormalizedXSSBody"
  }
}
```

## 5.7 XSS Rule for JSON Body

Use this pattern when XSS payloads are submitted through JSON APIs.

```json
{
  "Name": "Block_XSS_JSONBody",
  "Priority": 12,
  "Statement": {
    "XssMatchStatement": {
      "FieldToMatch": {
        "JsonBody": {
          "MatchPattern": {
            "All": {}
          },
          "MatchScope": "ALL",
          "InvalidFallbackBehavior": "EVALUATE_AS_STRING",
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
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "BlockXSSJSONBody"
  }
}
```

## 5.8 XSS Generation Checklist

Before finalizing an XSS rule:

- [ ] `XssMatchStatement` is used for built-in XSS detection.
- [ ] `FieldToMatch` matches the observed payload location.
- [ ] Text transformations expose encoded or obfuscated script tokens.
- [ ] Body, JSON body, headers, cookies, and URI fragments include oversize handling.
- [ ] Applications accepting HTML, Markdown, templates, code snippets, or rich text are treated as high false-positive risk.
- [ ] Rule action starts as `Count` when production impact is uncertain.
- [ ] False-positive tuning guidance is included.

---

# 6. Multi-Component SQLi and XSS Rules with `OrStatement`

## 6.1 Purpose

Use `OrStatement` when SQLi or XSS payloads may appear in multiple request components. Each nested statement must specify its own `FieldToMatch`.

## 6.2 Recommended Multi-Component Strategy

When the exact payload location is unknown:

1. Inspect `AllQueryArguments`.
2. Inspect `Body` or `JsonBody` if the application accepts POST or JSON input.
3. Inspect `Cookies` only if payloads are cookie-based.
4. Inspect `Headers` only if payloads are header-based.
5. Use `UriPath` only if payloads are in path segments.

## 6.3 Multi-Component XSS Example

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

## 6.4 Multi-Component SQLi Example

```json
{
  "Name": "Block_SQLi_QueryArguments_Or_JSONBody",
  "Priority": 31,
  "Statement": {
    "OrStatement": {
      "Statements": [
        {
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
        {
          "SqliMatchStatement": {
            "FieldToMatch": {
              "JsonBody": {
                "MatchPattern": {
                  "All": {}
                },
                "MatchScope": "ALL",
                "InvalidFallbackBehavior": "EVALUATE_AS_STRING",
                "OversizeHandling": "MATCH"
              }
            },
            "TextTransformations": [
              { "Priority": 0, "Type": "URL_DECODE" },
              { "Priority": 1, "Type": "LOWERCASE" },
              { "Priority": 2, "Type": "COMPRESS_WHITE_SPACE" },
              { "Priority": 3, "Type": "REPLACE_COMMENTS" }
            ],
            "SensitivityLevel": "HIGH"
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
    "MetricName": "BlockSQLiQueryArgsOrJSONBody"
  }
}
```

---

# 7. Oversize Handling for Body, JSON Body, Headers, Cookies, and URI Fragment

## 7.1 Definition

AWS WAF cannot inspect unlimited request content. For large request components, AWS WAF receives only the portion forwarded by the protected host service. Oversize handling defines how AWS WAF treats requests when the inspected component exceeds inspection limits.

## 7.2 Inspection Limits

| Component | Inspection limit |
|---|---|
| `Body` / `JsonBody` for Application Load Balancer and AWS AppSync | First 8 KB |
| `Body` / `JsonBody` for CloudFront, API Gateway, Cognito, App Runner, Verified Access | Default first 16 KB; configurable up to 64 KB for some resources |
| `Headers` | First 8 KB and first 200 headers |
| `Cookies` | First 8 KB and first 200 cookies |
| `UriFragment` | First 8 KB and first 200 fragments |

## 7.3 OversizeHandling Values

| OversizeHandling | Meaning | Security effect |
|---|---|---|
| `CONTINUE` | Inspect only available content within the limit. | May miss attacks beyond the inspected portion. |
| `MATCH` | Treat the request as matching the statement. | With `Block`, blocks oversize requests. Stronger security. |
| `NO_MATCH` | Treat the request as not matching the statement. | Can allow oversize attacks if no later rule blocks them. |

## 7.4 Oversize Generation Rules

When generating rules that inspect `Body`, `JsonBody`, `Headers`, `Cookies`, or `UriFragment`:

- Always include oversize handling.
- Use `MATCH` when strict blocking is acceptable.
- Use `CONTINUE` when legitimate large components are common and partial inspection is acceptable.
- Avoid `NO_MATCH` unless there is a clear allowlist or business requirement.
- If a managed rule group inspects oversized content with unsuitable behavior, add a custom oversize-blocking rule before the managed rule group.
- If the application legitimately sends large bodies, add allowlist rules before oversize-blocking rules.

## 7.5 Example: Block Oversized Body Before Body Inspection Rules

```json
{
  "Name": "Block_Oversized_Body",
  "Priority": 1,
  "Statement": {
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
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "BlockOversizedBody"
  }
}
```

## 7.6 Example: Block Oversized Headers

```json
{
  "Name": "Block_Oversized_Headers",
  "Priority": 2,
  "Statement": {
    "SizeConstraintStatement": {
      "FieldToMatch": {
        "Headers": {
          "MatchPattern": {
            "All": {}
          },
          "MatchScope": "ALL",
          "OversizeHandling": "MATCH"
        }
      },
      "ComparisonOperator": "GT",
      "Size": 8192,
      "TextTransformations": [
        { "Priority": 0, "Type": "NONE" }
      ]
    }
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "BlockOversizedHeaders"
  }
}
```

---

# 8. Regex and Byte Match Statements for Rule Generation

## 8.1 When to Use RegexMatchStatement

Use `RegexMatchStatement` when:

- The built-in SQLi or XSS statement is too broad or too narrow.
- You need to match a specific evasive pattern.
- You need to combine multiple regex conditions with `AndStatement`, `OrStatement`, or `NotStatement`.
- You need a scope-down condition for a managed rule group.
- You need to exclude known false positives while retaining detection.

`RegexMatchStatement` operates on one request component and supports text transformations.

## 8.2 RegexMatchStatement Example for Event Handler XSS

```json
{
  "Name": "Block_XSS_EventHandler_Regex_QueryArguments",
  "Priority": 40,
  "Statement": {
    "RegexMatchStatement": {
      "FieldToMatch": {
        "AllQueryArguments": {}
      },
      "RegexString": "(?i)<[^>]+\\son[a-z]+\\s*=",
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
    "MetricName": "BlockXSSEventHandlerRegexQueryArgs"
  }
}
```

## 8.3 When to Use ByteMatchStatement

Use `ByteMatchStatement` when:

- You know an exact string or word to match.
- The payload includes a stable literal indicator.
- You want a simpler rule than regex.
- You need exact control over `CONTAINS`, `EXACTLY`, `STARTS_WITH`, `ENDS_WITH`, or `CONTAINS_WORD`.

## 8.4 ByteMatchStatement Example for `javascript:` URI

```json
{
  "Name": "Block_Javascript_URI_QueryArguments",
  "Priority": 41,
  "Statement": {
    "ByteMatchStatement": {
      "FieldToMatch": {
        "AllQueryArguments": {}
      },
      "PositionalConstraint": "CONTAINS",
      "SearchString": "javascript:",
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
    "MetricName": "BlockJavascriptURIQueryArgs"
  }
}
```

## 8.5 Regex and Byte Match Caution

Prefer built-in `XssMatchStatement` or `SqliMatchStatement` when the target is general XSS or SQLi detection.

Use regex or byte match when:

- You need exact application-specific matching.
- You need to reduce false positives.
- You need a supplementary detection rule for a bypass pattern that built-in statements miss.

---

# 9. AWS Managed Rules for SQL Injection and XSS

## 9.1 When to Use Managed Rule Groups

Use AWS Managed Rules when the goal is broad baseline protection and the user does not want to author every custom rule manually.

For SQLi and XSS:

| Protection goal | Managed rule group |
|---|---|
| SQL injection protection | SQL database managed rule group |
| XSS and common web application vulnerability protection | Core rule set (CRS) managed rule group |

## 9.2 Core Rule Set for XSS

The Core rule set (CRS) is a broad baseline managed rule group for common web application vulnerabilities. It includes XSS-related protections such as cross-site scripting rules for request components including body, cookies, query arguments, and URI path.

Relevant rule name patterns include:

```text
CrossSiteScripting_BODY
CrossSiteScripting_COOKIE
CrossSiteScripting_QUERYARGUMENTS
CrossSiteScripting_URIPATH
```

Use CRS when:

- The user wants baseline web application protection.
- The exact vulnerable parameter is unknown.
- The application needs broad XSS coverage.
- You want managed labels for later label-based rules.

## 9.3 SQL Database Managed Rule Group for SQLi

The SQL database managed rule group protects against SQL injection attacks. It includes SQLi-related protections for common request components.

Relevant rule name patterns include:

```text
SQLi_BODY
SQLi_COOKIE
SQLi_URIPATH
SQLi_QUERYARGUMENTS
SQLiExtendedPatterns_QUERYARGUMENTS
```

Use the SQL database managed rule group when:

- The user wants baseline SQLi protection.
- Multiple SQLi request components require coverage.
- You want AWS-managed updates for SQLi detection logic.
- You want managed labels for later label-based rules.

## 9.4 Managed Rule Group Action Overrides

When adding a managed rule group to a web ACL, start with action overrides to `Count` when production impact is unknown.

Generation instruction:

- Use `RuleActionOverrides` to override specific managed rules to `Count`.
- Use `OverrideAction` only when you want the rule group result to count while leaving internal rule evaluation unchanged.
- Prefer rule-level overrides for testing managed rules.
- Use scope-down statements to restrict managed rule evaluation to relevant paths, hosts, or request methods.

## 9.5 Managed Rule Group JSON Pattern

```json
{
  "Name": "AWSManagedRulesCommonRuleSet",
  "Priority": 100,
  "Statement": {
    "ManagedRuleGroupStatement": {
      "VendorName": "AWS",
      "Name": "AWSManagedRulesCommonRuleSet"
    }
  },
  "OverrideAction": {
    "None": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "AWSManagedRulesCommonRuleSet"
  }
}
```

## 9.6 Managed Rule Group Testing Pattern

```json
{
  "Name": "AWSManagedRulesSQLiRuleSet_Testing",
  "Priority": 101,
  "Statement": {
    "ManagedRuleGroupStatement": {
      "VendorName": "AWS",
      "Name": "AWSManagedRulesSQLiRuleSet",
      "RuleActionOverrides": [
        {
          "Name": "SQLi_QUERYARGUMENTS",
          "ActionToUse": {
            "Count": {}
          }
        },
        {
          "Name": "SQLi_BODY",
          "ActionToUse": {
            "Count": {}
          }
        }
      ]
    }
  },
  "OverrideAction": {
    "None": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "AWSManagedRulesSQLiRuleSetTesting"
  }
}
```

## 9.7 Managed Rule Versioning

Managed rule groups can change over time. Some managed rule groups support static versions.

Generation guidance:

- Use the default version when the user wants AWS-managed updates.
- Pin a static version when the user wants controlled rollout and predictable behavior.
- Test new versions in `Count` mode.
- Monitor version expiration and update schedules.
- Document rule action overrides and scope-down statements.

---

# 10. Label-Based Rule Generation

## 10.1 Definition

AWS WAF can add labels to matching requests. Later rules in the same web ACL can match labels using `LabelMatchStatement`.

A label match statement can only see labels from rules that were evaluated earlier in the web ACL.

## 10.2 Use Cases

Use label matching when:

- A managed rule group identifies a category of traffic.
- You want to apply a custom action after a managed rule labels a request.
- You want to combine managed detection with application-specific conditions.
- You want to tune false positives without disabling the managed rule entirely.

## 10.3 Label Match Example

```json
{
  "Name": "Block_After_Managed_SQLi_Label",
  "Priority": 200,
  "Statement": {
    "LabelMatchStatement": {
      "Scope": "LABEL",
      "Key": "awswaf:managed:aws:sql-database:SQLi_QueryArguments"
    }
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "BlockAfterManagedSQLiLabel"
  }
}
```

## 10.4 Label Rule Generation Constraints

- The label-producing rule must have lower numeric priority than the label-consuming rule.
- Use labels only when the label namespace and rule group are known.
- Include the label source in generated explanations.
- Use `Count` for label experiments before enforcement.

---

# 11. False Positive Tuning Patterns

## 11.1 Scope-Down by URI Path

Use scope-down logic when SQLi or XSS inspection should only apply to vulnerable application areas.

Example: apply XSS inspection only to paths under `/search` or `/comment`.

```json
{
  "AndStatement": {
    "Statements": [
      {
        "ByteMatchStatement": {
          "FieldToMatch": {
            "UriPath": {}
          },
          "PositionalConstraint": "STARTS_WITH",
          "SearchString": "/search",
          "TextTransformations": [
            { "Priority": 0, "Type": "NONE" }
          ]
        }
      },
      {
        "XssMatchStatement": {
          "FieldToMatch": {
            "AllQueryArguments": {}
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

## 11.2 Exclude Known Benign Parameters

Use `NotStatement` or targeted `SingleQueryArgument` rules when one parameter legitimately contains SQL-like or HTML-like content.

Generation guidance:

- Prefer inspecting known vulnerable parameters rather than all parameters when false positives are high.
- Use `NotStatement` to exclude known safe paths or parameters.
- Start in `Count` mode and inspect sampled requests.

## 11.3 High False-Positive Request Types

Treat the following as higher false-positive risk:

- Admin panels that submit templates.
- CMS rich-text editors.
- Markdown editors.
- Code snippet forms.
- Search boxes that accept special query syntax.
- Database administration or reporting tools.
- Developer APIs that legitimately carry HTML, SQL, JavaScript, or JSON templates.

---

# 12. Testing, Logging, and Monitoring

## 12.1 Testing Flow

Before enforcing generated rules:

1. Deploy rules with action `Count`.
2. Enable `SampledRequestsEnabled`.
3. Enable `CloudWatchMetricsEnabled`.
4. Enable AWS WAF logging where possible.
5. Review matched requests.
6. Identify legitimate traffic that matched.
7. Tune rule scope, transformations, sensitivity, and exclusions.
8. Move rule action to `Block` only after validation.

## 12.2 VisibilityConfig Requirements

Every generated rule should include `VisibilityConfig`.

```json
{
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "MeaningfulMetricName"
  }
}
```

## 12.3 Metric Naming Guidance

Metric names should be:

- Stable.
- Descriptive.
- Free of spaces.
- Specific to the rule objective.

Examples:

```text
BlockNormalizedXSSAllQueryArguments
BlockSQLiJSONBody
CountManagedSQLiRuleSetTesting
BlockOversizedBody
```

---

# 13. Decision Matrix for Rule Generation

| Input evidence | Recommended AWS WAF rule |
|---|---|
| Payload contains XSS indicators such as `script`, `onerror`, `onload`, `svg`, `img`, `javascript:` | Generate `XssMatchStatement`. |
| Payload contains SQLi indicators such as `union select`, `or 1=1`, `sleep`, `benchmark`, SQL comments | Generate `SqliMatchStatement`. |
| Payload is URL encoded | Add `URL_DECODE`; consider `URL_DECODE_UNI` for `%u` encoding. |
| Payload uses HTML entities | Add `HTML_ENTITY_DECODE`. |
| Payload uses mixed casing | Add `LOWERCASE`. |
| Payload uses whitespace splitting | Add `COMPRESS_WHITE_SPACE`. |
| Payload uses SQL comments | Add `REPLACE_COMMENTS`. |
| Payload appears in query parameters | Use `AllQueryArguments` or `SingleQueryArgument`. |
| Payload appears in JSON body | Use `JsonBody` with oversize handling. |
| Payload appears in form body | Use `Body` with oversize handling. |
| Payload appears in cookies | Use `Cookies` with oversize handling. |
| Payload appears in headers | Use `SingleHeader` or `Headers` with oversize handling. |
| Exact bypass pattern is known and built-in match is insufficient | Add `RegexMatchStatement` or `ByteMatchStatement`. |
| Broad protection requested | Add AWS Managed Rules: CRS for XSS/general protection and SQL database managed rule group for SQLi. |
| Production safety is uncertain | Use `Count`, logging, sampled requests, and CloudWatch metrics first. |
| Oversize body/header/cookie risk exists | Add explicit oversize-blocking rule before inspection rules. |

---

# 14. Complete Example: XSS Defense for URL-Encoded Event Handler Payloads

## 14.1 Scenario

Observed bypass payloads:

```text
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
%3Cimg%20src=x%20onerror=alert(1)%3E
%3Csvg%20onload=alert(1)%3E
```

## 14.2 Recommended Custom Rule

```json
{
  "Name": "Block_XSS_EventHandlers_QueryArguments",
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
    "MetricName": "BlockXSSEventHandlersQueryArguments"
  }
}
```

## 14.3 Why This Rule Matches

- `AllQueryArguments` inspects all query parameters, which is appropriate for reflected XSS.
- `URL_DECODE` exposes `%3C`, `%3E`, and encoded spaces.
- `HTML_ENTITY_DECODE` handles entity-encoded tags and attributes.
- `LOWERCASE` handles mixed-case tags and event handlers.
- `COMPRESS_WHITE_SPACE` reduces whitespace obfuscation.
- `XssMatchStatement` uses AWS WAF's built-in XSS detection engine.

## 14.4 False Positive Notes

Potential false positives:

- Search fields that legitimately include HTML.
- Rich text editors.
- Developer tools that submit code snippets.
- CMS admin panels.

Mitigation:

- Start with `Count`.
- Scope down to public search/comment paths if needed.
- Use `SingleQueryArgument` when vulnerable parameter names are known.

---

# 15. Complete Example: SQLi Defense for Comment and Encoding Bypasses

## 15.1 Scenario

Observed bypass payloads:

```text
1 UNION SELECT NULL--
1/**/UNION/**/SELECT/**/password
1%27%20OR%201%3D1--
1; SELECT SLEEP(5)
```

## 15.2 Recommended Custom Rule

```json
{
  "Name": "Block_SQLi_Evasive_QueryArguments",
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
        { "Priority": 3, "Type": "REPLACE_COMMENTS" },
        { "Priority": 4, "Type": "SQL_HEX_DECODE" }
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
    "MetricName": "BlockSQLiEvasiveQueryArguments"
  }
}
```

## 15.3 Why This Rule Matches

- `AllQueryArguments` covers SQLi in unknown query parameter names.
- `URL_DECODE` exposes encoded quotes, spaces, and operators.
- `LOWERCASE` normalizes SQL keywords.
- `COMPRESS_WHITE_SPACE` handles whitespace splitting.
- `REPLACE_COMMENTS` reduces C-style SQL comment evasion.
- `SQL_HEX_DECODE` helps when SQL hex encoding is used.
- `SensitivityLevel: HIGH` increases coverage for evasive SQLi payloads.

## 15.4 False Positive Notes

Potential false positives:

- Advanced search syntax.
- SQL training platforms.
- Admin dashboards.
- Developer APIs.
- Logs or reports that include SQL fragments.

Mitigation:

- Start in `Count`.
- Use `SingleQueryArgument` if the vulnerable parameter is known.
- Scope down to vulnerable URI paths.
- Lower sensitivity to `LOW` if false positives are unacceptable.

---

# 16. Complete Example: Managed Rule Baseline with Custom Oversize Protection

## 16.1 Scenario

The user wants broad baseline protection for SQLi and XSS, but also wants strict handling of oversized bodies.

## 16.2 Recommended Rule Order

1. Explicit allowlist rules, if required.
2. `Block_Oversized_Body`.
3. AWS Managed Rules Core rule set.
4. AWS Managed Rules SQL database rule group.
5. Custom SQLi/XSS rules for observed bypass payloads.
6. Label-based or tuning rules.

## 16.3 Example Oversize Rule

```json
{
  "Name": "Block_Oversized_Body_Before_Managed_Rules",
  "Priority": 1,
  "Statement": {
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
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "BlockOversizedBodyBeforeManagedRules"
  }
}
```

## 16.4 Example Managed Rule Groups

```json
[
  {
    "Name": "AWSManagedRulesCommonRuleSet",
    "Priority": 100,
    "Statement": {
      "ManagedRuleGroupStatement": {
        "VendorName": "AWS",
        "Name": "AWSManagedRulesCommonRuleSet"
      }
    },
    "OverrideAction": {
      "None": {}
    },
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "AWSManagedRulesCommonRuleSet"
    }
  },
  {
    "Name": "AWSManagedRulesSQLiRuleSet",
    "Priority": 101,
    "Statement": {
      "ManagedRuleGroupStatement": {
        "VendorName": "AWS",
        "Name": "AWSManagedRulesSQLiRuleSet"
      }
    },
    "OverrideAction": {
      "None": {}
    },
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "AWSManagedRulesSQLiRuleSet"
    }
  }
]
```

## 16.5 Deployment Guidance

- Start managed rule groups in `Count` or with rule action overrides when production impact is unknown.
- Review labels, sampled requests, logs, and CloudWatch metrics.
- Tune scope-down statements and rule action overrides.
- Move to blocking after validation.

---

# 17. Final Rule Generation Output Template

Use this template when generating AWS WAF defenses.

```markdown
## Rule Objective

Describe the attack type, bypass behavior, and protected request component.

## Proposed AWS WAF Rule

Provide JSON rule configuration.

## Why This Rule Matches the Bypass

Explain:
- selected `FieldToMatch`
- selected statement type
- selected text transformations
- selected action
- oversize handling
- sensitivity level if SQLi

## Deployment Mode

State whether the rule should start in `Count` or `Block`.

## False Positive and Tuning Notes

List:
- likely false-positive scenarios
- recommended scope-down conditions
- request components to narrow
- managed rule overrides if relevant

## Monitoring

Mention:
- sampled requests
- CloudWatch metrics
- AWS WAF logs
- metric name
```

---

# 18. Final Checklist for AWS WAF SQLi/XSS Rule Generation

- [ ] Attack type is explicit: `XSS` or `SQLI`.
- [ ] AWS WAF target is explicit.
- [ ] Rule type is explicit: custom statement, managed rule group, regex, byte match, label match, or oversize rule.
- [ ] Request component is explicit in `FieldToMatch`.
- [ ] Multiple request components use separate statements combined with `OrStatement`.
- [ ] Text transformations match the bypass technique.
- [ ] Transformation priorities are unique.
- [ ] SQLi rules specify `SensitivityLevel` intentionally.
- [ ] Body, JSON body, headers, cookies, and URI fragments include oversize handling.
- [ ] Rule action is `Count` for testing unless enforcement is explicitly required.
- [ ] Rule action is `Block` after validation.
- [ ] VisibilityConfig enables sampled requests and CloudWatch metrics.
- [ ] False-positive risks are documented.
- [ ] Managed rule groups include action override and versioning guidance when relevant.
- [ ] Rule priority is consistent with allowlists, oversize blocking, managed rules, labels, and custom rules.
