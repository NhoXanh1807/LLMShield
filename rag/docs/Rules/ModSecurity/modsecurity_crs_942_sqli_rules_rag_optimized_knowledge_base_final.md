# OWASP CRS 4.27 ModSecurity SQL Injection Rules Knowledge Base for RAG and WAF Rule Generation
# 1. RAG Metadata Header

```yaml
rag_document_type: waf_rule_knowledge_base
source_document: REQUEST-942-APPLICATION-ATTACK-SQLI.md
source_rule_group: REQUEST-942-APPLICATION-ATTACK-SQLI
source_project: OWASP CRS
source_version: 4.27.0-dev
waf_type: ModSecurity
data_type: Rules
primary_attack_type: SQLI
secondary_attack_labels:
  - SQL injection
  - SQLi
  - blind SQL injection
  - boolean-based SQL injection
  - time-based SQL injection
  - UNION SELECT SQL injection
  - authentication bypass SQL injection
  - JSON-based SQL injection
  - MySQL comment bypass
  - SQL operator injection
  - SQL function injection
  - MongoDB operator injection
recommended_chunking:
  strategy: structure_aware_v2
  chunk_size: 3600
  min_chunk_size: 500
  hard_chunk_size: 5200
  keep_rule_blocks_intact: true
```

## 1.1 Why this structure matches the current RAG system

The current RAG implementation is optimized for WAF rule-authoring documents. It preserves procedural steps, syntax blocks, rule snippets, tables, and JSON examples; uses global chunk IDs; expands neighbor chunks from the FAISS docstore; and uses `attack_type` provided by the caller as the primary signal rather than guessing from payloads.

For this document, the most retrieval-useful units are:

1. one SQLi concept or rule family per section
2. one or a small group of related CRS rule IDs per section
3. a concise rule-generation explanation before the rule block
4. the complete `SecRule` block kept intact
5. false-positive and tuning notes next to broad patterns
6. explicit keywords that match `attack_type=SQLI`, payload signals, and ModSecurity syntax

---

# 2. CRS 942 Rule Group Overview

## 2.1 Rule Group Identity

```text
Rule group: REQUEST-942-APPLICATION-ATTACK-SQLI
CRS version: OWASP_CRS/4.27.0-dev
Primary attack class: SQL Injection / SQLi
ModSecurity directive type: SecRule
Default enforcement model: CRS anomaly scoring with block action
```

The uploaded source begins with OWASP CRS 4.27.0-dev metadata and then defines paranoia-level skip gates followed by SQL injection detection rules. The first detection rule is `942100`, a libinjection SQLi check over request cookies, cookie names, User-Agent, Referer, argument names, argument values, and XML values.

## 2.2 High-Level Rule Families

| Family | Purpose | Representative rule IDs |
|---|---|---|
| Libinjection SQLi | Generic parser/tokenizer-based SQLi detection. | `942100`, `942101` |
| Database names and schema discovery | Detect metadata objects such as `information_schema`, `pg_catalog`, `sqlite_master`, `tempdb`. | `942140` |
| SQL function names | Detect dangerous or SQL-specific functions across database engines. | `942151`, `942150`, `942152`, `942410`, `942470`, `942480` |
| Time-based blind SQLi | Detect `sleep()`, `benchmark()`, `pg_sleep`, `waitfor delay`. | `942160`, `942170`, `942280` |
| Boolean / tautology SQLi | Detect `1=1`, `1!=2`, equality/inequality logic. | `942130`, `942131`, `942390` |
| SQL operators | Detect operators like `&&`, `||`, `regexp`, `rlike`, `like`, `in(...)`, `is null`. | `942120` |
| UNION / SELECT / data manipulation | Detect `union select`, `select from`, DDL/DML, `load_file`, `group_concat`. | `942270`, `942350`, `942360`, `942361`, `942362` |
| Authentication bypass | Detect quote termination, `OR`, `AND`, semicolon split query, escaped quotes. | `942180`, `942260`, `942340`, `942520`, `942521`, `942522`, `942540`, `942530` |
| SQL comments and obfuscation | Detect MySQL comments, inline comments, comment-sequence bypasses. | `942200`, `942300`, `942440`, `942500` |
| JSON / NoSQL-like SQLi | Detect JSON SQL syntax and MongoDB-style operators. | `942550`, `942290` |
| Numeric and encoding anomalies | Detect integer overflows, scientific notation, hex/bin, special-character anomalies. | `942220`, `942560`, `942450`, `942420`, `942421`, `942430`, `942431`, `942432`, `942460` |
| Stored procedure / code execution | Detect `exec`, `xp_cmdshell`, functions/procedures, UDF, PostgreSQL/MySQL procedural calls. | `942190`, `942320`, `942321`, `942350` |

---

# 3. ModSecurity CRS Rule Generation Model

## 3.1 Canonical CRS SQLi Rule Shape

```apache
SecRule <TARGET_VARIABLES> "<OPERATOR> <PATTERN>" \
    "id:<RULE_ID>,\
    phase:<PHASE>,\
    block,\
    capture,\
    t:none,<TRANSFORMATIONS>,\
    msg:'<SQLI MESSAGE>',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/<PL>',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl<PL>=+%{tx.critical_anomaly_score}'"
```

## 3.2 Target Variable Selection

| Observed SQLi location | Recommended target |
|---|---|
| Any request argument value | `ARGS` |
| Argument or parameter names | `ARGS_NAMES` |
| Cookie value | `REQUEST_COOKIES` |
| Cookie name | `REQUEST_COOKIES_NAMES` |
| User-Agent payload | `REQUEST_HEADERS:User-Agent` |
| Referer payload | `REQUEST_HEADERS:Referer` |
| URI path segment | `REQUEST_BASENAME` |
| Full request filename/path | `REQUEST_FILENAME` |
| XML body values | `XML:/*` |
| Broad CRS-style request input coverage | `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer|ARGS_NAMES|ARGS|XML:/*` |

## 3.3 Operator Selection

| SQLi detection need | Recommended operator |
|---|---|
| Generic SQLi parser/fingerprint detection | `@detectSQLi` |
| Regex family for known SQLi syntax | `@rx` |
| Paranoia-level gate | `@lt` |
| Chained equality comparison of captured values | `@streq` |
| Chained inequality comparison of captured values | `!@streq` |

## 3.4 Transformation Selection

| Transformation | Use in CRS SQLi rules |
|---|---|
| `t:none` | Always start with explicit transformation reset. |
| `t:utf8toUnicode` | Normalize Unicode before libinjection or operator detection. |
| `t:urlDecodeUni` | Decode URL encoding and `%uXXXX` style encoding. Very common baseline. |
| `t:removeNulls` | Remove null-byte obfuscation, used by libinjection rules. |
| `t:replaceComments` | Normalize SQL comments for time-based and tautology patterns. |
| `t:removeCommentsChar` | Remove comment characters for MSSQL / information gathering pattern. |
| `t:removeWhitespace` | Detect JSON-based SQL syntax after removing whitespace. |

## 3.5 CRS Anomaly Scoring

CRS SQLi rules usually add to both SQLi-specific and inbound anomaly scores:

```apache
setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}'
setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'
```

For stricter rules, the PL-specific score changes:

```apache
setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'
setvar:'tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}'
setvar:'tx.inbound_anomaly_score_pl4=+%{tx.warning_anomaly_score}'
```

Rule-generation guidance:

- Use CRS-style `block` + `setvar` if integrating into an anomaly-scoring deployment.
- Use standalone `deny,status:403,log,auditlog` only when writing a custom immediate-block rule outside CRS scoring.
- Use PL1 for high-confidence and lower false-positive patterns.
- Use PL2/PL3/PL4 for stricter or noisier patterns.

---

# 4. SQLi Payload to CRS Reference Mapping

| Payload / bypass signal | Best CRS reference IDs | Retrieval keywords |
|---|---|---|
| Generic SQLi, unknown syntax | `942100` | libinjection, detectSQLi, SQL injection parser |
| SQLi in URI path | `942101` | REQUEST_BASENAME, REQUEST_FILENAME, path SQLi |
| `union select from` | `942270`, `942360`, `942361`, `942362` | union select, basic SQL injection, select from |
| `sleep()`, `benchmark()` | `942160`, `942170` | blind SQLi, sleep benchmark, time delay |
| `pg_sleep`, `waitfor delay`, shutdown | `942280`, `942240` | PostgreSQL pg_sleep, MSSQL waitfor delay |
| `1=1`, `1 != 2`, boolean true/false | `942130`, `942131`, `942390` | tautology, boolean-based SQLi, equality, inequality |
| `information_schema`, `sqlite_master`, `pg_catalog` | `942140`, `942190` | database names, schema discovery, metadata |
| `xp_cmdshell`, `execute master`, `dumpfile`, `outfile` | `942190` | MSSQL code execution, information gathering |
| `/*! ... */`, `/*+ ... */` | `942500`, `942440`, `942200`, `942300` | MySQL inline comment, optimizer hint, comments |
| Semicolon split query after quote | `942540`, `942530` | authentication bypass, split query, query termination |
| JSON SQL operators / `json_extract()` | `942550` | JSON-based SQL injection, JSON SQL syntax |
| MongoDB `$where`, `$ne`, `$regex`, `$or` style operators | `942290` | MongoDB SQL injection, NoSQL operator injection |
| Stored procedure / UDF / `create function` | `942320`, `942321`, `942350` | stored procedure, UDF, create function |
| Scientific notation bypass | `942560` | MySQL scientific notation, numeric bypass |
| Too many SQL metacharacters | `942420`, `942421`, `942430`, `942431`, `942432`, `942460` | character anomaly, meta-character anomaly |

---

# 5. External Link-Derived Knowledge Integrated for Rule Generation

The source comments reference public resources. Only rule-generation-relevant knowledge is integrated here.

## 5.1 libinjection

`libinjection` is a SQL / SQLi tokenizer, parser, and analyzer. In CRS 942, libinjection is exposed through ModSecurity operator `@detectSQLi`. Use this as a broad generic detection reference when payload syntax is varied, unknown, or hard to reduce to one regex.

Rule-generation implication:

```apache
SecRule ARGS "@detectSQLi" "id:...,phase:2,t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,block,capture,msg:'SQL Injection Attack Detected via libinjection'"
```

## 5.2 CRS regex assembly

Many CRS 942 regexes are generated from `regex-assembly/*.ra` files. The source comments repeatedly say to update expressions with commands such as:

```bash
crs-toolchain regex update 942170
```

Rule-generation implication:

- For CRS-style contributions, do not manually edit a huge assembled regex without keeping the source `.ra` pattern list synchronized.
- For custom project rules, generate simpler targeted regexes instead of copying massive CRS assemblies unless exact CRS behavior is needed.

## 5.3 MySQL comments and optimizer hints

MySQL supports executable version comments and optimizer hint comments such as:

```sql
SELECT /*! STRAIGHT_JOIN */ col1 FROM table1,table2 WHERE ...
SELECT /*+ BKA(t1) */ FROM ... ;
```

Rule-generation implication:

- SQLi payloads using `/*!...*/` and `/*+...*/` can bypass naive keyword matching.
- Use rule `942500` or a custom equivalent when payloads contain MySQL inline comments or optimizer hints.

## 5.4 SQLMap tamper and WAF bypass context

SQLMap supports tamper scripts through `--tamper`, which transforms payloads to bypass weak validation or WAF/IPS filtering.

Rule-generation implication:

- If bypassed payloads look like random casing, comments, alternate whitespace, encoding, or operator substitution, retrieve sections for comments, SQL operators, time delay, and auth bypass rather than generic SQLi only.

## 5.5 JSON-based SQL injection

The source includes CRS rule `942550` for JSON-based SQL injection and cites research on SQL JSON syntax being used to bypass WAFs.

Rule-generation implication:

- Retrieve `942550` when payloads include JSON operators such as `->`, `->>`, `@>`, `<@`, `?`, `?|`, `?&`, JSON strings, JSON path expressions, or `json_extract()`.
- Use `t:urlDecodeUni,t:removeWhitespace` as the CRS transformation baseline for this pattern family.

---

# 6. Paranoia Level Sections

## 6.1 PL1: Default SQLi Detection

PL1 contains the strongest baseline SQLi detections: libinjection, DB names, SQL function names, time-based blind SQLi, MSSQL information gathering, conditional SQLi, data manipulation, JSON SQLi, MySQL inline comments, split query authentication bypass, scientific notation bypass, and MongoDB-style operator injection.

Use PL1 when the rule should be suitable for ordinary production anomaly scoring with lower false-positive risk than stricter levels.

## 6.2 PL2: Stricter SQLi Detection

PL2 contains stricter operator, tautology, auth bypass, chained SQLi, probing, function-name, path, and header-specific rules. These rules increase coverage but can be noisier.

Use PL2 when the application tolerates additional false positives or the specific bypass payload matches a PL2 family.

## 6.3 PL3: Aggressive SQLi Probing and Query Termination

PL3 includes HAVING injections, classic probing 3/3, stricter character anomalies, and tick/query-termination variants.

Use PL3 for higher-security deployments or very specific payloads after scoping to parameter/path/header.

## 6.4 PL4: Restricted SQL Character Anomaly Detection

PL4 includes stricter character anomaly rules for cookies and arguments with warning severity.

Use PL4 only with careful tuning because anomaly detection based on metacharacter counts can false positive on encoded data, logs, search strings, or developer content.

---

# 7. Rule Inventory Table

This table is intentionally compact. Detailed, self-contained rule cards follow after the inventory.

| Rule ID | PL | Phase | Operator | Family | Message | Main target | Transformations |
|---:|---:|---:|---|---|---|---|---|
| `942011` | - | 1 | `@lt` | Paranoia-level gate / skip marker | Paranoia gate / control rule | `TX:DETECTION_PARANOIA_LEVEL` | `-` |
| `942012` | - | 2 | `@lt` | Paranoia-level gate / skip marker | Paranoia gate / control rule | `TX:DETECTION_PARANOIA_LEVEL` | `-` |
| `942100` | 1 | 2 | `@detectSQLi` | Libinjection SQLi detection | SQL Injection Attack Detected via libinjection | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|REQUEST_HEADERS:User-Agent\|REQUEST_HEADERS:Referer\|…` | `none,utf8toUnicode,urlDecodeUni,removeNulls` |
| `942140` | 1 | 2 | `@rx` | Database-name reconnaissance | SQL Injection Attack: Common DB Names Detected | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942151` | 1 | 2 | `@rx` | SQL function / stored procedure / UDF | SQL Injection Attack: SQL function name detected | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942160` | 1 | 2 | `@rx` | Time-based blind SQLi / delay function | Detects blind sqli tests using sleep() or benchmark() | `REQUEST_FILENAME\|REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni,replaceComments` |
| `942170` | 1 | 2 | `@rx` | Time-based blind SQLi / delay function | Detects SQL benchmark and sleep injection attempts including conditional queries | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942190` | 1 | 2 | `@rx` | MSSQL command execution / information gathering | Detects MSSQL code execution and information gathering attempts | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni,removeCommentsChar` |
| `942220` | 1 | 2 | `@rx` | Numeric/overflow/scientific-notation SQLi | Looking for integer overflow attacks, these are taken from skipfish, except 2.2.2250738585072011e-308 is the \"magic number\" crash | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942230` | 1 | 2 | `@rx` | General SQLi pattern | Detects conditional SQL injection attempts | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942240` | 1 | 2 | `@rx` | MSSQL command execution / information gathering | Detects MySQL charset switch and MSSQL DoS attempts | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942250` | 1 | 2 | `@rx` | General SQLi pattern | Detects MATCH AGAINST, MERGE and EXECUTE IMMEDIATE injections | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942270` | 1 | 2 | `@rx` | Union/select/data manipulation SQLi | Looking for basic sql injection. Common attack string for mysql, oracle and others | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942280` | 1 | 2 | `@rx` | Time-based blind SQLi / delay function | Detects Postgres pg_sleep injection, waitfor delay attacks and database shutdown attempts | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|REQUEST_HEADERS:User-Agent\|REQUEST_HEADERS:Referer\|…` | `none,urlDecodeUni` |
| `942290` | 1 | 2 | `@rx` | JSON-based SQLi / NoSQL operator syntax | Finds basic MongoDB SQL injection attempts | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942320` | 1 | 2 | `@rx` | SQL function / stored procedure / UDF | Detects MySQL and PostgreSQL stored procedure/function injections | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942350` | 1 | 2 | `@rx` | SQL function / stored procedure / UDF | Detects MySQL UDF injection and other data/structure manipulation attempts | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni,replaceComments` |
| `942360` | 1 | 2 | `@rx` | Union/select/data manipulation SQLi | Detects concatenated basic SQL injection and SQLLFI attempts | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942500` | 1 | 2 | `@rx` | SQL comments / obfuscation comments | MySQL in-line comment detected | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942540` | 1 | 2 | `@rx` | Authentication bypass / query termination | SQL Authentication bypass (split query) | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni,replaceComments` |
| `942560` | 1 | 2 | `@rx` | Numeric/overflow/scientific-notation SQLi | MySQL Scientific Notation payload detected | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni,replaceComments` |
| `942550` | 1 | 2 | `@rx` | JSON-based SQLi / NoSQL operator syntax | JSON-Based SQL Injection | `REQUEST_FILENAME\|REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni,removeWhitespace` |
| `942013` | - | 1 | `@lt` | Paranoia-level gate / skip marker | Paranoia gate / control rule | `TX:DETECTION_PARANOIA_LEVEL` | `-` |
| `942014` | - | 2 | `@lt` | Paranoia-level gate / skip marker | Paranoia gate / control rule | `TX:DETECTION_PARANOIA_LEVEL` | `-` |
| `942120` | 2 | 2 | `@rx` | SQL operators | SQL Injection Attack: SQL Operator Detected | `ARGS_NAMES\|ARGS\|REQUEST_FILENAME\|XML:/*` | `none,utf8toUnicode,urlDecodeUni` |
| `942130` | 2 | 2 | `@rx` | Boolean tautology / inequality SQLi | SQL Injection Attack: SQL Boolean-based attack detected | `ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni,replaceComments` |
| `942131` | 2 | 2 | `@rx` | Boolean tautology / inequality SQLi | SQL Injection Attack: SQL Boolean-based attack detected | `ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni,replaceComments` |
| `942150` | 2 | 2 | `@rx` | SQL function / stored procedure / UDF | SQL Injection Attack: SQL function name detected | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942180` | 2 | 2 | `@rx` | Authentication bypass / query termination | Detects basic SQL authentication bypass attempts 1/3 | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942200` | 2 | 2 | `@rx` | SQL comments / obfuscation comments | Detects MySQL comment-/space-obfuscated injections and backtick termination | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|REQUEST_HEADERS:User-Agent\|REQUEST_HEADERS:Referer\|…` | `none,urlDecodeUni` |
| `942210` | 2 | 2 | `@rx` | General SQLi pattern | Detects chained SQL injection attempts 1/2 | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942260` | 2 | 2 | `@rx` | Authentication bypass / query termination | Detects basic SQL authentication bypass attempts 2/3 | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942300` | 2 | 2 | `@rx` | SQL comments / obfuscation comments | Detects MySQL comments, conditions and ch(a)r injections | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942310` | 2 | 2 | `@rx` | General SQLi pattern | Detects chained SQL injection attempts 2/2 | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942330` | 2 | 2 | `@rx` | SQL probing payloads | Detects classic SQL injection probings 1/3 | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942340` | 2 | 2 | `@rx` | Authentication bypass / query termination | Detects basic SQL authentication bypass attempts 3/3 | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942361` | 2 | 2 | `@rx` | Union/select/data manipulation SQLi | Detects basic SQL injection based on keyword alter or union | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942362` | 2 | 2 | `@rx` | Union/select/data manipulation SQLi | Detects concatenated basic SQL injection and SQLLFI attempts | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942370` | 2 | 2 | `@rx` | SQL probing payloads | Detects classic SQL injection probings 2/3 | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|REQUEST_HEADERS:Referer\|REQUEST_HEADERS:User-Agent\|…` | `none,urlDecodeUni` |
| `942380` | 2 | 2 | `@rx` | General SQLi pattern | SQL Injection Attack | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942390` | 2 | 2 | `@rx` | General SQLi pattern | SQL Injection Attack | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942400` | 2 | 2 | `@rx` | General SQLi pattern | SQL Injection Attack | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942410` | 2 | 2 | `@rx` | General SQLi pattern | SQL Injection Attack | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942470` | 2 | 2 | `@rx` | General SQLi pattern | SQL Injection Attack | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942480` | 2 | 2 | `@rx` | General SQLi pattern | SQL Injection Attack | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|REQUEST_HEADERS\|!REQUEST_HEADERS:Cookie\|ARGS_NAMES\|…` | `none,urlDecodeUni` |
| `942430` | 2 | 2 | `@rx` | Character anomaly / meta-character detection | Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (12) | `ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942440` | 2 | 2 | `@rx` | SQL comments / obfuscation comments | SQL Comment Sequence Detected | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942450` | 2 | 2 | `@rx` | General SQLi pattern | SQL Bin or Hex Encoding Identified | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942510` | 2 | 2 | `@rx` | General SQLi pattern | SQLi bypass attempt by ticks or backticks detected | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942520` | 2 | 2 | `@rx` | Authentication bypass / query termination | Detects basic SQL authentication bypass attempts 4.0/4 | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942521` | 2 | 2 | `@rx` | Authentication bypass / query termination | Detects basic SQL authentication bypass attempts 4.1/4 | `REQUEST_HEADERS:User-Agent\|REQUEST_HEADERS:Referer\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942522` | 2 | 2 | `@rx` | Authentication bypass / query termination | Detects basic SQL authentication bypass attempts 4.1/4 | `ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942101` | 2 | 1 | `@detectSQLi` | Libinjection SQLi detection | SQL Injection Attack Detected via libinjection | `REQUEST_BASENAME\|REQUEST_FILENAME` | `none,utf8toUnicode,urlDecodeUni,removeNulls` |
| `942152` | 2 | 1 | `@rx` | SQL function / stored procedure / UDF | SQL Injection Attack: SQL function name detected | `REQUEST_HEADERS:Referer\|REQUEST_HEADERS:User-Agent` | `none,urlDecodeUni` |
| `942321` | 2 | 1 | `@rx` | SQL function / stored procedure / UDF | Detects MySQL and PostgreSQL stored procedure/function injections | `REQUEST_HEADERS:Referer\|REQUEST_HEADERS:User-Agent` | `none,urlDecodeUni` |
| `942015` | - | 1 | `@lt` | Paranoia-level gate / skip marker | Paranoia gate / control rule | `TX:DETECTION_PARANOIA_LEVEL` | `-` |
| `942016` | - | 2 | `@lt` | Paranoia-level gate / skip marker | Paranoia gate / control rule | `TX:DETECTION_PARANOIA_LEVEL` | `-` |
| `942251` | 3 | 2 | `@rx` | Libinjection SQLi detection | Detects HAVING injections | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942490` | 3 | 2 | `@rx` | SQL probing payloads | Detects classic SQL injection probings 3/3 | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942420` | 3 | 1 | `@rx` | Character anomaly / meta-character detection | Restricted SQL Character Anomaly Detection (cookies): # of special characters exceeded (8) | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES` | `none,urlDecodeUni` |
| `942431` | 3 | 2 | `@rx` | Character anomaly / meta-character detection | Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (6) | `ARGS_NAMES\|!ARGS_NAMES:/^[\w]+\[[\w\-]+\]\[[\w\-]*?\]$/\|!ARGS_NAMES:/^[\w]+\[[\w\-]+\]\[[…` | `none,urlDecodeUni` |
| `942460` | 3 | 2 | `@rx` | Character anomaly / meta-character detection | Meta-Character Anomaly Detection Alert - Repetitive Non-Word Characters | `ARGS` | `none` |
| `942511` | 3 | 2 | `@rx` | General SQLi pattern | SQLi bypass attempt by ticks detected | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942530` | 3 | 2 | `@rx` | Authentication bypass / query termination | SQLi query termination detected | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |
| `942017` | - | 1 | `@lt` | Paranoia-level gate / skip marker | Paranoia gate / control rule | `TX:DETECTION_PARANOIA_LEVEL` | `-` |
| `942018` | - | 2 | `@lt` | Paranoia-level gate / skip marker | Paranoia gate / control rule | `TX:DETECTION_PARANOIA_LEVEL` | `-` |
| `942421` | 4 | 1 | `@rx` | Character anomaly / meta-character detection | Restricted SQL Character Anomaly Detection (cookies): # of special characters exceeded (3) | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES` | `none,urlDecodeUni` |
| `942432` | 4 | 2 | `@rx` | Character anomaly / meta-character detection | Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (2) | `ARGS_NAMES\|ARGS\|XML:/*` | `none,urlDecodeUni` |

---

# 8. High-Value Rule Family Cards

## 8.1 Libinjection SQLi Detection: `942100` and `942101`

Use this family when the payload is SQLi but the exact syntax is unknown or varied.

Targets:

- `942100`: cookies, cookie names, User-Agent, Referer, argument names, arguments, XML
- `942101`: `REQUEST_BASENAME` and `REQUEST_FILENAME`, useful when SQLi is embedded in URL path segments

Recommended transformation stack:

```apache
t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls
```

Standalone custom-rule template:

```apache
SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_HEADERS:User-Agent "@detectSQLi" \
  "id:100942100,phase:2,t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,deny,status:403,log,auditlog,msg:'SQL injection detected via libinjection',tag:'attack-sqli',severity:'CRITICAL'"
```

## 8.2 Time-Based Blind SQLi: `942160`, `942170`, `942280`, `942240`

Use this family when payloads contain delay functions or DBMS-specific sleep primitives:

```text
sleep(5)
benchmark(1000000,md5(1))
select pg_sleep(5)
waitfor delay '0:0:5'
```

CRS transformation patterns:

```apache
t:none,t:urlDecodeUni,t:replaceComments
```

or:

```apache
t:none,t:urlDecodeUni
```

Standalone custom-rule template:

```apache
SecRule ARGS|REQUEST_COOKIES|REQUEST_HEADERS:User-Agent "@rx (?i)(sleep\s*\(|benchmark\s*\(|pg_sleep|waitfor\s+delay)" \
  "id:100942160,phase:2,t:none,t:urlDecodeUni,t:replaceComments,deny,status:403,log,auditlog,msg:'Time-based SQL injection payload detected',tag:'attack-sqli',severity:'CRITICAL'"
```

## 8.3 Boolean-Based SQLi / Tautology: `942130`, `942131`, `942390`

Use this family when payloads contain always-true or always-false logic:

```text
1=1
1 != 2
'or'1'='1
' or 'x'='x
```

CRS `942130` and `942131` use chained rules. They first capture two operands into `TX.1` and `TX.2`, then compare them with `@streq` or `!@streq`.

Custom-rule fallback:

```apache
SecRule ARGS|ARGS_NAMES "@rx (?i)(?:or|and)\s+[0-9a-z_]+\s*(?:=|!=|<>)\s*[0-9a-z_]+" \
  "id:100942130,phase:2,t:none,t:urlDecodeUni,t:replaceComments,deny,status:403,log,auditlog,msg:'Boolean-based SQL injection payload detected',tag:'attack-sqli',severity:'CRITICAL'"
```

## 8.4 UNION / SELECT / Metadata Extraction: `942140`, `942190`, `942270`, `942360`, `942361`, `942362`

Use this family for payloads containing:

```text
union select
select ... from
information_schema
schema_name
load_file
outfile
dumpfile
group_concat
```

Recommended custom-rule template:

```apache
SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES "@rx (?i)(union\s+select|select.+from|information_schema|load_file\s*\(|into\s+(?:dump|out)file|group_concat\s*\()" \
  "id:100942270,phase:2,t:none,t:urlDecodeUni,t:replaceComments,deny,status:403,log,auditlog,msg:'UNION SELECT or SQL metadata extraction payload detected',tag:'attack-sqli',severity:'CRITICAL'"
```

False-positive warning:

- `select` alone is too broad.
- `union` alone can false positive.
- Scope to parameter/path when possible.

## 8.5 Authentication Bypass / Query Termination: `942180`, `942260`, `942340`, `942520`, `942521`, `942522`, `942530`, `942540`

Use this family when payloads attempt to close a quoted expression and append logic:

```text
' or 'x'='x
admin'--
admin';&password=foo
\' or 1=1
```

CRS contains both broad detection and chained rules to reduce false positives.

Generated custom-rule template:

```apache
SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES "@rx (?i)(['\"`][\s\x0b]*(?:or|and)\b|^(?:[^']*'|[^\"]*\"|[^`]*`)[\s\x0b]*;)" \
  "id:100942540,phase:2,t:none,t:urlDecodeUni,t:replaceComments,deny,status:403,log,auditlog,msg:'SQL authentication bypass or split-query payload detected',tag:'attack-sqli',severity:'CRITICAL'"
```

## 8.6 MySQL Inline Comments and Comment Obfuscation: `942200`, `942300`, `942440`, `942500`

Use this family when payloads contain comment-based bypasses:

```sql
UN/**/ION SEL/**/ECT
/*!50000select*/
/*+ BKA(t1) */
--
#
```

CRS `942500` specifically detects MySQL inline comments and optimizer-hint style comments:

```apache
@rx (?i)/\*[\s\x0b]*?[!\+](?:[\s\x0b\(\)\-0-9=A-Z_a-z]+)?\*/
```

Generated custom-rule template:

```apache
SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES "@rx (?i)(/\*[\s\x0b]*?[!\+].*?\*/|/\*.*?\*/|--|#)" \
  "id:100942500,phase:2,t:none,t:urlDecodeUni,deny,status:403,log,auditlog,msg:'SQL comment obfuscation detected',tag:'attack-sqli',severity:'CRITICAL'"
```

## 8.7 JSON-Based SQL Injection: `942550`

Use this family when payloads contain SQL JSON syntax that can bypass WAF parsing:

```text
'{"a":1}'::jsonb @> '{"a":1}'::jsonb
json_extract(...)
->
->>
@>
<@
?| 
?&
```

CRS transformation stack:

```apache
t:none,t:urlDecodeUni,t:removeWhitespace
```

Generated custom-rule template:

```apache
SecRule REQUEST_FILENAME|ARGS|ARGS_NAMES|REQUEST_COOKIES "@rx (?i)(json_extract\s*\(|->>|->|@>|<@|\?[|&]?)" \
  "id:100942550,phase:2,t:none,t:urlDecodeUni,t:removeWhitespace,deny,status:403,log,auditlog,msg:'JSON-based SQL injection syntax detected',tag:'attack-sqli',severity:'CRITICAL'"
```

## 8.8 MongoDB / NoSQL-Style Operator Injection: `942290`

Use this family when payloads include MongoDB-style operators or JSON-like database operators:

```text
$where
$ne
$regex
$or
$and
$jsonSchema
$function
```

Generated custom-rule template:

```apache
SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES "@rx (?i)\$(?:where|ne|regex|or|and|jsonSchema|function|expr)\b" \
  "id:100942290,phase:2,t:none,t:urlDecodeUni,deny,status:403,log,auditlog,msg:'MongoDB or NoSQL operator injection detected',tag:'attack-sqli',severity:'CRITICAL'"
```

## 8.9 Stored Procedure, UDF, and DB Code Execution: `942190`, `942320`, `942321`, `942350`

Use this family for payloads involving procedures, functions, command execution, or database-specific code execution:

```text
xp_cmdshell
exec master
create function
create procedure
lo_import
procedure analyse
execute immediate
```

Generated custom-rule template:

```apache
SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_HEADERS:User-Agent "@rx (?i)(xp_cmdshell|exec(?:ute)?\s+master|create\s+(?:function|procedure)|procedure\s+analyse|lo_(?:import|get)|execute\s+immediate)" \
  "id:100942320,phase:2,t:none,t:urlDecodeUni,t:replaceComments,deny,status:403,log,auditlog,msg:'SQL stored procedure or code execution payload detected',tag:'attack-sqli',severity:'CRITICAL'"
```

## 8.10 Numeric, Scientific-Notation, Hex/Binary, and Character Anomaly Rules

Use these families when payloads are mostly encoded or numeric rather than obvious SQL keywords.

Relevant rules:

- `942220`: integer overflow / PHP strtod magic number
- `942560`: MySQL scientific notation payload
- `942450`: binary or hex encoding
- `942420`, `942421`, `942430`, `942431`, `942432`: special-character anomaly detection
- `942460`: repetitive non-word meta-character anomaly

Use anomaly-based rules carefully. They can false positive on encoded data, long tokens, analytics parameters, search strings, and developer tooling.

---

# 9. Retrieval Query Patterns

Use these query patterns to maximize top-k retrieval precision:

```text
ModSecurity CRS SQLI SecRule union select REQUEST_COOKIES ARGS t:urlDecodeUni
ModSecurity CRS SQL injection libinjection @detectSQLi ARGS REQUEST_HEADERS
ModSecurity CRS SQLI sleep benchmark pg_sleep waitfor delay blind SQL injection
ModSecurity CRS SQLI boolean tautology 1=1 1 != 2 chain TX.1 TX.2
ModSecurity CRS SQLI MySQL inline comment /*! */ /*+ */ t:urlDecodeUni
ModSecurity CRS SQLI JSON based SQL injection json_extract ->> @> <@
ModSecurity CRS SQLI authentication bypass quote semicolon split query OR AND
ModSecurity CRS SQLI stored procedure xp_cmdshell create function procedure
```

---

# 10. Complete Rule Cards

Each rule card below keeps the source comment context close to the `SecRule` block. This is intentional: RAG chunks should preserve the conceptual explanation, CRS metadata, and exact syntax together.

## Rule `942011` — Paranoia-level gate / skip marker

**Family:** Paranoia-level gate / skip marker

**Paranoia level:** `control/gate`  
**Phase:** `1`  
**Operator:** `@lt`  
**Target:** `TX:DETECTION_PARANOIA_LEVEL`  
**Transformations:** `-`  
**Actions:** `pass, nolog`  

**Rule-generation use:** Use this rule when the observed payload matches the message, family, target, and pattern shown below. Scope to the vulnerable parameter or path when possible to reduce false positives.

**Source context and comments:**

```text
------------------------------------------------------------------------
OWASP CRS ver.4.27.0-dev
Copyright (c) 2006-2020 Trustwave and contributors. All rights reserved.
Copyright (c) 2021-2026 CRS project. All rights reserved.

The OWASP CRS is distributed under
Apache Software License (ASL) version 2
Please see the enclosed LICENSE file for full details.
------------------------------------------------------------------------

-= Paranoia Level 0 (empty) =- (apply unconditionally)
```

**Source `SecRule` block:**

```apache
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:942011,phase:1,pass,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.27.0-dev',skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI"
```

## Rule `942012` — Paranoia-level gate / skip marker

**Family:** Paranoia-level gate / skip marker

**Paranoia level:** `control/gate`  
**Phase:** `2`  
**Operator:** `@lt`  
**Target:** `TX:DETECTION_PARANOIA_LEVEL`  
**Transformations:** `-`  
**Actions:** `pass, nolog`  

**Rule-generation use:** Use this rule when the observed payload matches the message, family, target, and pattern shown below. Scope to the vulnerable parameter or path when possible to reduce false positives.

**Source `SecRule` block:**

```apache
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:942012,phase:2,pass,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.27.0-dev',skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI"
```

## Rule `942100` — SQL Injection Attack Detected via libinjection

**Family:** Libinjection SQLi detection

**Paranoia level:** `1`  
**Phase:** `2`  
**Operator:** `@detectSQLi`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, utf8toUnicode, urlDecodeUni, removeNulls`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture, multiMatch`  
**Score updates:** `tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}; tx.sql_injection_score=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Generic libinjection SQLi detector for cookies, cookie names, User-Agent, Referer, argument names, arguments, and XML values. Best first reference for unknown SQLi payloads.

**Source context and comments:**

```text
-= Paranoia Level 1 (default) =- (apply only when tx.detection_paranoia_level is sufficiently high: 1 or higher)


References:

SQL Injection Knowledgebase (via @LightOS) -
http://websec.ca/kb/sql_injection

SQLi Filter Evasion Cheat Sheet -
http://websec.wordpress.com/2010/12/04/sqli-filter-evasion-cheat-sheet-mysql/

SQL Injection Cheat Sheet -
http://ferruh.mavituna.com/sql-injection-cheatsheet-oku/

SQLMap's Tamper Scripts (for evasions)
https://github.com/sqlmapproject/sqlmap


-=[ LibInjection Check ]=-

There is a stricter sibling of this rule at 942101. It covers REQUEST_BASENAME and REQUEST_FILENAME.

Ref: https://github.com/libinjection/libinjection
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer|ARGS_NAMES|ARGS|XML:/* "@detectSQLi" \
    "id:942100,\
    phase:2,\
    block,\
    capture,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,\
    msg:'SQL Injection Attack Detected via libinjection',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    multiMatch,\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}'"
```

## Rule `942140` — SQL Injection Attack: Common DB Names Detected

**Family:** Database-name reconnaissance

**Paranoia level:** `1`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Detects common database and metadata names such as information_schema, master..sysdatabases, mysql.db, pg_catalog, sqlite_master, tempdb, schema_name.

**Source context and comments:**

```text
-=[ Detect DB Names ]=-

Regular expression generated from regex-assembly/942140.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942140
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)\b(?:d(?:atabas|b_nam)e[^0-9A-Z_a-z]*\(|(?:information_schema|m(?:aster\.\.sysdatabases|s(?:db|ys(?:ac(?:cess(?:objects|storage|xml)|es)|modules2?|(?:object|querie|relationship)s))|ysql\.db)|northwind|pg_(?:catalog|toast)|tempdb)\b|s(?:chema(?:_name\b|[^0-9A-Z_a-z]*\()|(?:qlite_(?:temp_)?master|ys(?:aux|\.database_name))\b))" \
    "id:942140,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Injection Attack: Common DB Names Detected',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## Rule `942151` — SQL Injection Attack: SQL function name detected

**Family:** SQL function / stored procedure / UDF

**Paranoia level:** `1`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Large SQL function-name detector covering DBMS functions, including JSON and PostgreSQL/MySQL/SQLite functions, in cookies, args, arg names, and XML.

**Source context and comments:**

```text
-=[ SQL Function Names ]=-

This rule has a stricter sibling to this rule (942152) that checks for SQL function names in
request headers referer and user-agent.

Regular expression generated from regex-assembly/942151.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942151
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)\b(?:a(?:dd(?:dat|tim)e|es_(?:de|en)crypt|s(?:cii(?:str)?|in)|tan2?)|b(?:enchmark|i(?:n_to_num|t_(?:and|count|length|x?or)))|c(?:har(?:acter)?_length|eil(?:ing)?|o(?:alesce|ercibility|llation|(?:mpres)?s|n(?:cat(?:_ws)?|nection_id|v(?:ert_tz)?)|t)|rc32|ur(?:(?:dat|tim)e|rent_(?:date|setting|time(?:stamp)?|user)))|d(?:a(?:t(?:abase(?:_to_xml)?|e(?:_(?:add|format|sub)|diff))|y(?:name|of(?:month|week|year)))|count|e(?:code|s_(?:de|en)crypt)|ump)|e(?:n(?:c(?:ode|rypt)|ds_?with)|x(?:p(?:ort_set)?|tract(?:value)?))|f(?:i(?:el|n)d_in_set|ound_rows|rom_(?:base64|days|unixtime))|g(?:e(?:ometrycollection|t(?:_(?:format|lock)|pgusername))|(?:r(?:eates|oup_conca)|tid_subse)t)|hex(?:toraw)?|i(?:fnull|n(?:et6?_(?:aton|ntoa)|s(?:ert|tr)|terval)|s(?:_(?:(?:free|used)_lock|ipv(?:4(?:_(?:compat|mapped))?|6)|n(?:ot(?:_null)?|ull)|superuser)|null))|json(?:_(?:a(?:gg|rray(?:_(?:elements(?:_text)?|length))?)|build_(?:array|object)|e(?:ac|xtract_pat)h(?:_text)?|object(?:_(?:agg|keys))?|populate_record(?:set)?|strip_nulls|t(?:o_record(?:set)?|ypeof))|b(?:_(?:array(?:_(?:elements(?:_text)?|length))?|build_(?:array|object)|e(?:ac|xtract_pat)h(?:_text)?|insert|object(?:_(?:agg|keys))?|p(?:ath_(?:(?:exists|match)(?:_tz)?|query(?:_(?:(?:array|first)(?:_tz)?|tz))?)|opulate_record(?:set)?|retty)|s(?:et(?:_lax)?|trip_nulls)|t(?:o_record(?:set)?|ypeof)))?|path)?|l(?:ast_(?:day|insert_id)|case|east|i(?:kely|nestring)|o(?:_(?:from_bytea|put)|ad_file|ca(?:ltimestamp|te)|g(?:10|2))|pad|trim)|m(?:a(?:ke(?:_set|date)|ster_pos_wait)|d5|i(?:crosecon)?d|onthname|ulti(?:linestring|po(?:int|lygon)))|n(?:ame_const|ot_in|ullif)|o(?:ct(?:et_length)?|(?:ld_passwo)?rd)|p(?:eriod_(?:add|diff)|g_(?:client_encoding|(?:databas|read_fil)e|l(?:argeobject|s_dir)|sleep|user)|o(?:lygon|w)|rocedure_analyse)|qu(?:ery_to_xml|ote)|r(?:a(?:dians|nd|wtohex)|elease_lock|ow_(?:count|to_json)|pad|trim)|s(?:chema|e(?:c_to_time|ssion_user)|ha[12]?|in|oundex|q(?:lite_(?:compileoption_(?:get|used)|source_id)|rt)|t(?:arts_?with|d(?:dev_(?:po|sam)p)?|r(?:_to_date|cmp))|ub(?:(?:dat|tim)e|str(?:ing(?:_index)?)?)|ys(?:date|tem_user))|t(?:ime(?:_(?:format|to_sec)|diff|stamp(?:add|diff)?)|o(?:_(?:base64|jsonb?)|n?char|(?:day|second)s)|r(?:im|uncate))|u(?:case|n(?:compress(?:ed_length)?|hex|i(?:str|x_timestamp))|(?:pdatexm|se_json_nul)l|tc_(?:date|time(?:stamp)?)|uid(?:_short)?)|var(?:_(?:po|sam)p|iance)|we(?:ek(?:day|ofyear)|ight_string)|xmltype|yearweek)[^0-9A-Z_a-z]*\(" \
    "id:942151,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Injection Attack: SQL function name detected',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## Rule `942160` — Detects blind sqli tests using sleep() or benchmark()

**Family:** Time-based blind SQLi / delay function

**Paranoia level:** `1`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_FILENAME|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni, replaceComments`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Time-based blind SQLi detector for sleep() and benchmark(,) with replaceComments normalization.

**Source context and comments:**

```text
-=[ PHPIDS - Converted SQLI Filters ]=-

https://raw.githubusercontent.com/PHPIDS/PHPIDS/master/lib/IDS/default_filter.xml

The rule 942160 prevents time-based blind SQL injection attempts
by prohibiting sleep() or benchmark(,) functions:

* The sleep command takes a number of seconds as an argument.
* The benchmark command executes the specified expression multiple times.

Using a long sleep time or high number of executions, you can create a delay
with the response from the server.  This allows to determine whether the
query has been executed or not.  A high response time proves that the SQLi
worked successfully. It can now be equipped with the real payload.

Therefore this rule does not prevent the attack itself, but blocks an
attacker from using the standard utils to tinker with blind SQLi.

A positive side effect is that it prevents certain DoS attacks via the directives
described above.
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_FILENAME|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i:sleep\s*?\(.*?\)|benchmark\s*?\(.*?\,.*?\))" \
    "id:942160,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,t:replaceComments,\
    msg:'Detects blind sqli tests using sleep() or benchmark()',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## Rule `942170` — Detects SQL benchmark and sleep injection attempts including conditional queries

**Family:** Time-based blind SQLi / delay function

**Paranoia level:** `1`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Detects select/semicolon followed by benchmark/if/sleep conditional time-based constructs.

**Source context and comments:**

```text
Regular expression generated from regex-assembly/942170.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942170
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)(?:select|;)[\s\x0b]+(?:benchmark|if|sleep)[\s\x0b]*?\([\s\x0b]*?\(?[\s\x0b]*?[0-9A-Z_a-z]+" \
    "id:942170,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects SQL benchmark and sleep injection attempts including conditional queries',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## Rule `942190` — Detects MSSQL code execution and information gathering attempts

**Family:** MSSQL command execution / information gathering

**Paranoia level:** `1`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni, removeCommentsChar`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** MSSQL and information-gathering payload detector: union select, information_schema, dump/outfile, xp_cmdshell, execute master.

**Source context and comments:**

```text
Regular expression generated from regex-assembly/942190.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942190
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)[\"'`](?:[\s\x0b]*![\s\x0b]*[\"'0-9A-Z_-z]|;?[\s\x0b]*(?:having|select|union\b[\s\x0b]*(?:all|(?:distin|sele)ct))\b[\s\x0b]*[^\s\x0b])|\b(?:(?:(?:c(?:onnection_id|urrent_user)|database|schema|user)[\s\x0b]*?|select.*?[0-9A-Z_a-z]?user)\(|exec(?:ute)?[\s\x0b]+master\.|from[^0-9A-Z_a-z]+information_schema[^0-9A-Z_a-z]|into[\s\x0b\+]+(?:dump|out)file[\s\x0b]*?[\"'`]|union(?:[\s\x0b]select[\s\x0b]@|[\s\x0b\(0-9A-Z_a-z]*?select))|[\s\x0b]*?exec(?:ute)?.*?[^0-9A-Z_a-z]xp_cmdshell|[^0-9A-Z_a-z]iif[\s\x0b]*?\(" \
    "id:942190,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,t:removeCommentsChar,\
    msg:'Detects MSSQL code execution and information gathering attempts',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## Rule `942220` — Looking for integer overflow attacks, these are taken from skipfish, except 2.2.2250738585072011e-308 is the \"magic number\" crash

**Family:** Numeric/overflow/scientific-notation SQLi

**Paranoia level:** `1`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Numeric crash / integer overflow magic values including PHP strtod magic number.

**Source context and comments:**

```text
Magic number crash in PHP strtod from 2011:
https://www.exploringbinary.com/php-hangs-on-numeric-value-2-2250738585072011e-308/

Regular expression generated from regex-assembly/942220.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942220
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)^(?:429496729[56]|2(?:14748364[78]|.22507385850720(?:07|11)e-308)|-(?:214748364[89]|0000023456)|00000(?:12345|23456)|1e309)$" \
    "id:942220,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Looking for integer overflow attacks, these are taken from skipfish, except 2.2.2250738585072011e-308 is the \"magic number\" crash',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## Rule `942230` — Detects conditional SQL injection attempts

**Family:** General SQLi pattern

**Paranoia level:** `1`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Conditional SQLi detector for CASE WHEN THEN, LIKE subqueries, SELECT HAVING, IF comparisons.

**Source context and comments:**

```text
Regular expression generated from regex-assembly/942230.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942230
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)[\s\x0b\(\)]case[\s\x0b]+when.*?then|\)[\s\x0b]*?like[\s\x0b]*?\(|select.*?having[\s\x0b]*?[^\s\x0b]+[\s\x0b]*?[^\s\x0b0-9A-Z_a-z]|if[\s\x0b]?\([0-9A-Z_a-z]+[\s\x0b]*?[<->~]" \
    "id:942230,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects conditional SQL injection attempts',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## Rule `942240` — Detects MySQL charset switch and MSSQL DoS attempts

**Family:** MSSQL command execution / information gathering

**Paranoia level:** `1`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** MySQL charset switch and MSSQL WAITFOR TIME/DELAY or GOTO/DoS-style constructs.

**Source context and comments:**

```text
Regular expression generated from regex-assembly/942240.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942240
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)alter[\s\x0b]*?[0-9A-Z_a-z]+.*?char(?:acter)?[\s\x0b]+set[\s\x0b]+[0-9A-Z_a-z]+|[\"'`](?:;*?[\s\x0b]*?waitfor[\s\x0b]+(?:time|delay)[\s\x0b]+[\"'`]|;.*?:[\s\x0b]*?goto)" \
    "id:942240,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects MySQL charset switch and MSSQL DoS attempts',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## Rule `942250` — Detects MATCH AGAINST, MERGE and EXECUTE IMMEDIATE injections

**Family:** General SQLi pattern

**Paranoia level:** `1`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** MATCH AGAINST, MERGE USING, and EXECUTE IMMEDIATE injection detector.

**Source context and comments:**

```text
Regular expression generated from regex-assembly/942250.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942250
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)m(?:erge.*?using|atch[\s\x0b]*?[\(\)\+-\-0-9A-Z_a-z]+[\s\x0b]*?against)[\s\x0b]*?\(|execute[\s\x0b]*?immediate[\s\x0b]*?[\"'`]" \
    "id:942250,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects MATCH AGAINST, MERGE and EXECUTE IMMEDIATE injections',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## Rule `942270` — Looking for basic sql injection. Common attack string for mysql, oracle and others

**Family:** Union/select/data manipulation SQLi

**Paranoia level:** `1`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Basic union-select-from detector for common SQLi across MySQL, Oracle, and others.

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)union.*?select.*?from" \
    "id:942270,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Looking for basic sql injection. Common attack string for mysql, oracle and others',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## Rule `942280` — Detects Postgres pg_sleep injection, waitfor delay attacks and database shutdown attempts

**Family:** Time-based blind SQLi / delay function

**Paranoia level:** `1`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** PostgreSQL pg_sleep, MSSQL waitfor delay, and shutdown attempt detector.

**Source context and comments:**

```text
Regular expression generated from regex-assembly/942280.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942280
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer|ARGS_NAMES|ARGS|XML:/* "@rx (?i)select[\s\x0b]*?pg_sleep|waitfor[\s\x0b]*?delay[\s\x0b]?[\"'`]+[\s\x0b]?[0-9]|;[\s\x0b]*?shutdown[\s\x0b]*?(?:[#;\{]|/\*|--)" \
    "id:942280,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects Postgres pg_sleep injection, waitfor delay attacks and database shutdown attempts',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## Rule `942290` — Finds basic MongoDB SQL injection attempts

**Family:** JSON-based SQLi / NoSQL operator syntax

**Paranoia level:** `1`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** MongoDB/NoSQL operator and function injection detector using $-prefixed operators and JSON-like API terms.

**Source context and comments:**

```text
Regular expression generated from regex-assembly/942290.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942290
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)\[?\$(?:a(?:bs|c(?:cumulator|osh?)|dd(?:ToSet)?|ll(?:ElementsTrue)?|n(?:d|yElementTrue)|rray(?:ElemA|ToObjec)t|sinh?|tan[2h]?|vg)|b(?:etween|i(?:narySize|t(?:And|Not|(?:O|Xo)r)?)|ottomN?|sonSize|ucket(?:Auto)?)|c(?:eil|mp|o(?:n(?:cat(?:Arrays)?|d|vert)|sh?|unt|variance(?:Po|Sam)p)|urrentDate)|d(?:a(?:te(?:Add|Diff|From(?:Parts|String)|Subtract|T(?:o(?:Parts|String)|runc))|yOf(?:Month|Week|Year))|e(?:greesToRadians|nseRank|rivative)|iv(?:ide)?|ocumentNumber)|e(?:(?:a|lemMat)ch|q|x(?:ists|p(?:MovingAvg|r)?))|f(?:i(?:lter|rstN?)|loor|unction)|g(?:etField|roup|te?)|(?:hou|xo|yea)r|i(?:fNull|n(?:c|dexOf(?:Array|Bytes|CP)|tegral)?|s(?:Array|Number|o(?:DayOfWeek|Week(?:Year)?)))|jsonSchema|l(?:astN?|et|i(?:ke|(?:nearFil|tera)l)|n|o(?:cf|g(?:10)?)|t(?:e|rim)?)|m(?:a(?:p|xN?)|e(?:dian|rgeObjects|ta)|i(?:llisecond|n(?:N|ute)?)|o(?:d|nth)|ul(?:tiply)?)|n(?:atural|e|in|o[rt])|o(?:bjectToArray|r)|p(?:ercentile|o(?:[pw]|sition)|roject|u(?:ll(?:All)?|sh))|r(?:a(?:diansToDegrees|n(?:[dk]|ge))|e(?:(?:duc|nam)e|gex(?:Find(?:All)?|Match)?|place(?:All|One)|verseArray)|ound|trim)|s(?:(?:ampleRat|lic)e|e(?:cond|t(?:Difference|(?:Equal|WindowField)s|Field|I(?:ntersection|sSubset)|OnInsert|Union)?)|(?:hif|pli|qr)t|i(?:nh?|ze)|ort(?:Array)?|t(?:dDev(?:Po|Sam)p|r(?:Len(?:Bytes|CP)|casecmp))|u(?:b(?:str(?:Bytes|CP)?|tract)|m)|witch)|t(?:anh?|ext|o(?:Bool|D(?:(?:at|oubl)e|ecimal)|HashedIndexKey|Int|Lo(?:ng|wer)|ObjectId|String|U(?:UID|pper)|pN?)|r(?:im|unc)|s(?:Increment|Second)|ype)|unset|w(?:eek|here)|zip)\b\]?" \
    "id:942290,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Finds basic MongoDB SQL injection attempts',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## Rule `942320` — Detects MySQL and PostgreSQL stored procedure/function injections

**Family:** SQL function / stored procedure / UDF

**Paranoia level:** `1`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Stored procedure/function injection detector for MySQL and PostgreSQL constructs such as create function/procedure, declare, exec, lo_import, casts.

**Source context and comments:**

```text
This rule has a stricter sibling (942321) that checks for MySQL and PostgreSQL procedures / functions in
request headers referer and user-agent.

Regular expression generated from regex-assembly/942320.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942320
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)create[\s\x0b]+(?:function|procedure)[\s\x0b]*?[0-9A-Z_a-z]+[\s\x0b]*?\([\s\x0b]*?\)[\s\x0b]*?-|d(?:eclare[^0-9A-Z_a-z]+[#@][\s\x0b]*?[0-9A-Z_a-z]+|iv[\s\x0b]*?\([\+\-]*[\s\x0b\.0-9]+,[\+\-]*[\s\x0b\.0-9]+\))|exec[\s\x0b]*?\([\s\x0b]*?@|(?:lo_(?:impor|ge)t|procedure[\s\x0b]+analyse)[\s\x0b]*?\(|;[\s\x0b]*?(?:declare|open)[\s\x0b]+[\-0-9A-Z_a-z]+|::(?:b(?:igint|ool)|double[\s\x0b]+precision|int(?:eger)?|numeric|oid|real|(?:tex|smallin)t)" \
    "id:942320,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects MySQL and PostgreSQL stored procedure/function injections',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## Rule `942350` — Detects MySQL UDF injection and other data/structure manipulation attempts

**Family:** SQL function / stored procedure / UDF

**Paranoia level:** `1`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni, replaceComments`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** MySQL UDF and data/structure manipulation: create function returns, alter/create/truncate/update/rename/delete/drop/insert/select/load.

**Source context and comments:**

```text
Regular expression generated from regex-assembly/942350.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942350
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)create[\s\x0b]+function[\s\x0b].+[\s\x0b]returns|;[\s\x0b]*?(?:alter|(?:(?:cre|trunc|upd)at|re(?:nam|plac))e|d(?:e(?:lete|sc)|rop)|(?:inser|selec)t|load)\b[\s\x0b]*?[\(\[]?[0-9A-Z_a-z]{2,}" \
    "id:942350,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,t:replaceComments,\
    msg:'Detects MySQL UDF injection and other data/structure manipulation attempts',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## Rule `942360` — Detects concatenated basic SQL injection and SQLLFI attempts

**Family:** Union/select/data manipulation SQLi

**Paranoia level:** `1`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Concatenated basic SQLi and SQL LFI attempts; includes load_file, group_concat, regexp, AS FROM, and many ALTER statement variants.

**Source context and comments:**

```text
This rule has two stricter sibling: 942361 and 942362.
The keywords 'alter' and 'union' led to false positives.
Therefore they have been moved to PL2 and the keywords have been extended on PL1.
The original version also had loose word boundaries and context checksum cause further false positives.
Because fixing those introduced bypass, the original variant was moved to PL2 as 942362.

Sources for SQL ALTER statements:
MySQL: https://dev.mysql.com/doc/refman/5.7/en/sql-syntax-data-definition.html
Oracle/PLSQL: https://docs.oracle.com/search/?q=alter&size=60&category=database
PostgreQSL: https://www.postgresql.org/search/?u=%2Fdocs&q=alter
MSSQL: https://learn.microsoft.com/en-us/sql/t-sql/statements/statements?view=sql-server-ver16
DB2: https://www.ibm.com/docs/en/search/alter?scope=SSEPGG_9.5.0

Regular expression generated from regex-assembly/942360.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942360
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)\b(?:(?:alter|(?:(?:cre|trunc|upd)at|renam)e|de(?:lete|sc)|(?:inser|selec)t|load)[\s\x0b]+(?:char|group_concat|load_file)\b[\s\x0b]*\(?|end[\s\x0b]*?\);)|[\s\x0b\(]load_file[\s\x0b]*?\(|[\"'`][\s\x0b]+regexp[^0-9A-Z_a-z]|[\"'0-9A-Z_-z][\s\x0b]+as\b[\s\x0b]*[\"'0-9A-Z_-z]+[\s\x0b]*\bfrom|^[^A-Z_a-z]+[\s\x0b]*?(?:(?:(?:(?:cre|trunc)at|renam)e|d(?:e(?:lete|sc)|rop)|(?:inser|selec)t|load)[\s\x0b]+[0-9A-Z_a-z]+|u(?:pdate[\s\x0b]+[0-9A-Z_a-z]+|nion[\s\x0b]*(?:all|(?:sele|distin)ct)\b)|alter[\s\x0b]*(?:a(?:(?:ggregat|pplication[\s\x0b]*rol)e|s(?:sembl|ymmetric[\s\x0b]*ke)y|u(?:dit|thorization)|vailability[\s\x0b]*group)|b(?:roker[\s\x0b]*priority|ufferpool)|c(?:ertificate|luster|o(?:l(?:latio|um)|nversio)n|r(?:edential|yptographic[\s\x0b]*provider))|d(?:atabase|efault|i(?:mension|skgroup)|omain)|e(?:(?:ndpoi|ve)nt|xte(?:nsion|rnal))|f(?:lashback|oreign|u(?:lltext|nction))|hi(?:erarchy|stogram)|group|in(?:dex(?:type)?|memory|stance)|java|l(?:a(?:ngua|r)ge|ibrary|o(?:ckdown|g(?:file[\s\x0b]*group|in)))|m(?:a(?:s(?:k|ter[\s\x0b]*key)|terialized)|e(?:ssage[\s\x0b]*type|thod)|odule)|(?:nicknam|queu)e|o(?:perator|utline)|p(?:a(?:ckage|rtition)|ermission|ro(?:cedur|fil)e)|r(?:e(?:mot|sourc)e|o(?:l(?:e|lback)|ute))|s(?:chema|e(?:arch|curity|rv(?:er|ice)|quence|ssion)|y(?:mmetric[\s\x0b]*key|nonym)|togroup)|t(?:able(?:space)?|ext|hreshold|r(?:igger|usted)|ype)|us(?:age|er)|view|w(?:ork(?:load)?|rapper)|x(?:ml[\s\x0b]*schema|srobject))\b)" \
    "id:942360,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects concatenated basic SQL injection and SQLLFI attempts',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## Rule `942500` — MySQL in-line comment detected

**Family:** SQL comments / obfuscation comments

**Paranoia level:** `1`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture, multiMatch`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** MySQL inline comment detector for /*!...*/ and /*+...*/ optimizer-hint style comments.

**Source context and comments:**

```text
-=[ Detect MySQL in-line comments ]=-

MySQL in-line comments can be used to bypass SQLi detection.

Ref: https://dev.mysql.com/doc/refman/8.0/en/comments.html:
SELECT /*! STRAIGHT_JOIN */ col1 FROM table1,table2 WHERE ...
CREATE TABLE t1(a INT, KEY (a)) /*!50110 KEY_BLOCK_SIZE=1024 */;
SELECT /*+ BKA(t1) */ FROM ... ;

http://localhost/test.php?id=9999+or+{if+length((/*!5000select+username/*!50000from*/user+where+id=1))>0}

The minimal string that triggers this regexp is: /*!*/ or /*+*/.
The rule 942500 is related to 942440 which catches both /*! and */ independently.

Regular expression generated from regex-assembly/942500.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942500
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)/\*[\s\x0b]*?[!\+](?:[\s\x0b\(\)\-0-9=A-Z_a-z]+)?\*/" \
    "id:942500,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'MySQL in-line comment detected',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    multiMatch,\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## Rule `942540` — SQL Authentication bypass (split query)

**Family:** Authentication bypass / query termination

**Paranoia level:** `1`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni, replaceComments`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Split-query authentication bypass using semicolon after unmatched quote/backtick.

**Source context and comments:**

```text
This rule catches an authentication bypass via SQL injection that abuses semi-colons to end the SQL query early.
Any characters after the semi-colon are ignored by some DBMSes (e.g. SQLite).

An example of this would be:
email=admin%40juice-sh.op';&password=foo

The server then turns this into:
SELECT * FROM users WHERE email='admin@juice-sh.op';' AND password='foo'

Regular expression generated from regex-assembly/942540.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942540
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx ^(?:[^']*'|[^\"]*\"|[^`]*`)[\s\x0b]*;" \
    "id:942540,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,t:replaceComments,\
    msg:'SQL Authentication bypass (split query)',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'paranoia-level/1',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## Rule `942560` — MySQL Scientific Notation payload detected

**Family:** Numeric/overflow/scientific-notation SQLi

**Paranoia level:** `1`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni, replaceComments`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** MySQL scientific notation payload detector.

**Source context and comments:**

```text
This rule catches on Scientific Notation bypass payloads in MySQL
Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md#scientific-notation

Regular expression generated from regex-assembly/942560.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942560
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)1\.e(?:[\(\),]|\.[\$0-9A-Z_a-z])" \
    "id:942560,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,t:replaceComments,\
    msg:'MySQL Scientific Notation payload detected',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## Rule `942550` — JSON-Based SQL Injection

**Family:** JSON-based SQLi / NoSQL operator syntax

**Paranoia level:** `1`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_FILENAME|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni, removeWhitespace`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** JSON-based SQL injection detector inspired by Claroty research; detects JSON strings/operators and json_extract().

**Source context and comments:**

```text
This rule tries to match JSON SQL syntax that could be used as a bypass technique.
Referring to this research: https://claroty.com/team82/research/js-on-security-off-abusing-json-based-sql-to-bypass-waf

Regular expression generated from regex-assembly/942550.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942550
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_FILENAME|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)[\"'`][\[\{][^#\]\}]*[\]\}]+[\"'`]|(?:[\-@]>?|<@|@[\?@]|\?(?:(?:)|&|\|#>)|#(?:>>|-)|->>|[<>])[\"'`](?:[\[\{][^#\]\}]*[\]\}]+[\"'`]|\$[\.\[])|\bjson_extract\b[^\(]*\([^\)]*\)" \
    "id:942550,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,t:removeWhitespace,\
    msg:'JSON-Based SQL Injection',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

## Rule `942013` — Paranoia-level gate / skip marker

**Family:** Paranoia-level gate / skip marker

**Paranoia level:** `control/gate`  
**Phase:** `1`  
**Operator:** `@lt`  
**Target:** `TX:DETECTION_PARANOIA_LEVEL`  
**Transformations:** `-`  
**Actions:** `pass, nolog`  

**Rule-generation use:** Use this rule when the observed payload matches the message, family, target, and pattern shown below. Scope to the vulnerable parameter or path when possible to reduce false positives.

**Source `SecRule` block:**

```apache
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" "id:942013,phase:1,pass,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.27.0-dev',skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI"
```

## Rule `942014` — Paranoia-level gate / skip marker

**Family:** Paranoia-level gate / skip marker

**Paranoia level:** `control/gate`  
**Phase:** `2`  
**Operator:** `@lt`  
**Target:** `TX:DETECTION_PARANOIA_LEVEL`  
**Transformations:** `-`  
**Actions:** `pass, nolog`  

**Rule-generation use:** Use this rule when the observed payload matches the message, family, target, and pattern shown below. Scope to the vulnerable parameter or path when possible to reduce false positives.

**Source `SecRule` block:**

```apache
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" "id:942014,phase:2,pass,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.27.0-dev',skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI"
```

## Rule `942120` — SQL Injection Attack: SQL Operator Detected

**Family:** SQL operators

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `ARGS_NAMES|ARGS|REQUEST_FILENAME|XML:/*`  
**Transformations:** `none, utf8toUnicode, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** SQL operator detector for equality, logical operators, JSON arrows, comparison operators, regexp/rlike/like, collate, null tests, and IN/ALL forms. PL2 due false-positive risk.

**Source context and comments:**

```text
-= Paranoia Level 2 =- (apply only when tx.detection_paranoia_level is sufficiently high: 2 or higher)


-=[ SQL Operators ]=-

This rule is also triggered by the following exploit(s):
[ SAP CRM Java vulnerability CVE-2018-2380 - Exploit tested: https://www.exploit-db.com/exploits/44292 ]

Regular expression generated from regex-assembly/942120.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942120
```

**Source `SecRule` block:**

```apache
SecRule ARGS_NAMES|ARGS|REQUEST_FILENAME|XML:/* "@rx (?i)[!=]=|&&|\|\||->|>[=>]|<(?:[<=]|>(?:[\s\x0b]+binary)?)|\b(?:(?:xor|r(?:egexp|like)|i(?:snull|like)|notnull)\b|collate(?:[^0-9A-Z_a-z]*?(?:U&)?[\"'`]|[^0-9A-Z_a-z]+(?:(?:binary|nocase|rtrim)\b|[0-9A-Z_a-z]*?_))|(?:likel(?:ihood|y)|unlikely)[\s\x0b]*\()|r(?:egexp|like)[\s\x0b]+binary|not[\s\x0b]+between[\s\x0b]+(?:0[\s\x0b]+and|(?:'[^']*'|\"[^\"]*\")[\s\x0b]+and[\s\x0b]+(?:'[^']*'|\"[^\"]*\"))|is[\s\x0b]+null|like[\s\x0b]+(?:null|[0-9A-Z_a-z]+[\s\x0b]+escape\b)|(?:^|[^0-9A-Z_a-z])in[\s\x0b\+]*\([\s\x0b\"0-9]+[^\(\)]*\)|[!<->][\s\x0b]*all\b" \
    "id:942120,\
    phase:2,\
    block,\
    capture,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,\
    msg:'SQL Injection Attack: SQL Operator Detected',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942130` — SQL Injection Attack: SQL Boolean-based attack detected

**Family:** Boolean tautology / inequality SQLi

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni, replaceComments`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture, chain`  
**Score updates:** `tx.942130_matched_var_name=%{matched_var_name}; tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Boolean tautology equality rule; captures left and right side and chains with TX:1 @streq %{TX.2}. Use for 1=1 style payloads.

**Source context and comments:**

```text
-=[ SQL Tautologies ]=-

Boolean-based SQL injection or tautology attack. Boolean values (True or False) are used to carry out
this type of SQL injection. The malicious SQL query forces the web application to return a different result de-
pending on whether the query returns a TRUE or FALSE result.

The original 942130 was split in two rules:
- 942130 targets tautologies using equalities (e.g. 1 = 1)
- 942131 targets tautologies using inequalities (e.g. 1 != 2)

We use captures to check for (in)equality in the regexp. So TX.1 will capture the left hand side (LHS) of the inequality,
and TX.2 will capture the right hand side (RHS) of the logical query.

Regular expression generated from regex-assembly/942130.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942130
```

**Source `SecRule` block:**

```apache
SecRule ARGS_NAMES|ARGS|XML:/* "@rx (?i)[\s\x0b\"'-\)`]*?\b([0-9A-Z_a-z]+)\b[\s\x0b\"'-\)`]*?(?:=|<=>|(?:sounds[\s\x0b]+)?like|glob|r(?:like|egexp))[\s\x0b\"'-\)`]*?\b([0-9A-Z_a-z]+)\b" \
    "id:942130,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,t:replaceComments,\
    msg:'SQL Injection Attack: SQL Boolean-based attack detected',\
    logdata:'Matched Data: %{TX.0} found within %{TX.942130_MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.942130_matched_var_name=%{matched_var_name}',\
    chain"
    SecRule TX:1 "@streq %{TX.2}" \
        "t:none,\
        setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
        setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942131` — SQL Injection Attack: SQL Boolean-based attack detected

**Family:** Boolean tautology / inequality SQLi

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni, replaceComments`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture, multiMatch, chain`  
**Score updates:** `tx.942131_matched_var_name=%{matched_var_name}; tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Boolean tautology inequality rule; captures left and right side and chains with TX:1 !@streq %{TX.2}. Use for 1!=2 style payloads.

**Source context and comments:**

```text
Rule Targeting logical inequalities that return TRUE (e.g. 1 != 2)


We use captures to check for (in)equality in the regexp. So TX.1 will capture the left hand side (LHS) of the inequality,
and TX.2 will capture the right hand side (RHS) of the logical query.

Regular expression generated from regex-assembly/942131.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942131
```

**Source `SecRule` block:**

```apache
SecRule ARGS_NAMES|ARGS|XML:/* "@rx (?i)[\s\x0b\"'-\)`]*?\b([0-9A-Z_a-z]+)\b[\s\x0b\"'-\)`]*?(?:![<->]|<[=>]?|>=?|\^|is[\s\x0b]+not|not[\s\x0b]+(?:like|r(?:like|egexp)))[\s\x0b\"'-\)`]*?\b([0-9A-Z_a-z]+)\b" \
    "id:942131,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,t:replaceComments,\
    msg:'SQL Injection Attack: SQL Boolean-based attack detected',\
    logdata:'Matched Data: %{TX.0} found within %{TX.942131_MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    multiMatch,\
    setvar:'tx.942131_matched_var_name=%{matched_var_name}',\
    chain"
    SecRule TX:1 "!@streq %{TX.2}" \
        "t:none,\
        setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
        setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942150` — SQL Injection Attack: SQL function name detected

**Family:** SQL function / stored procedure / UDF

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Use this rule when the observed payload matches the message, family, target, and pattern shown below. Scope to the vulnerable parameter or path when possible to reduce false positives.

**Source context and comments:**

```text
-=[ SQL Function Names ]=-

This rule is also triggered by the following exploit(s):
[ SAP CRM Java vulnerability CVE-2018-2380 - Exploit tested: https://www.exploit-db.com/exploits/44292 ]

Regular expression generated from regex-assembly/942150.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942150
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)\b(?:json(?:_[0-9A-Z_a-z]+)?|a(?:bs|(?:cos|sin)h?|tan[2h]?|vg)|c(?:eil(?:ing)?|h(?:a(?:nges|r(?:set)?)|r)|o(?:alesce|sh?|unt)|ast)|d(?:e(?:grees|fault)|a(?:te|y))|exp|f(?:loor(?:avg)?|ormat|ield)|g(?:lob|roup_concat)|h(?:ex|our)|i(?:f(?:null)?|if|n(?:str)?)|l(?:ast(?:_insert_rowid)?|ength|ike(?:l(?:ihood|y))?|n|o(?:ad_extension|g(?:10|2)?|wer(?:pi)?|cal)|trim)|m(?:ax|in(?:ute)?|o(?:d|nth))|n(?:ullif|ow)|p(?:i|ow(?:er)?|rintf|assword)|quote|r(?:a(?:dians|ndom(?:blob)?)|e(?:p(?:lace|eat)|verse)|ound|trim|ight)|s(?:i(?:gn|nh?)|oundex|q(?:lite_(?:compileoption_(?:get|used)|offset|source_id|version)|rt)|u(?:bstr(?:ing)?|m)|econd|leep)|t(?:anh?|otal(?:_changes)?|r(?:im|unc)|ypeof|ime)|u(?:n(?:icode|likely)|(?:pp|s)er)|zeroblob|bin|v(?:alues|ersion)|week|year)[^0-9A-Z_a-z]*\(" \
    "id:942150,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Injection Attack: SQL function name detected',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942180` — Detects basic SQL authentication bypass attempts 1/3

**Family:** Authentication bypass / query termination

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Authentication bypass detector for quoted OR/AND/LIKE/BETWEEN/operator patterns. PL2.

**Source context and comments:**

```text
-=[ SQL Authentication Bypasses ]=-

Authentication bypass occurs when the attacker can log in as another user
without knowing the user's password. The example bypass could look like this:

x' OR 'x

Because of the quantity of different rules they are split into:
- 942540 PL1
- 942180 PL2
- 942260 PL2
- 942340 PL2
- 942520 PL2
- 942521 PL2
- 942522 PL2
Regular expression generated from regex-assembly/942180.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942180
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)(?:/\*)+[\"'`]+[\s\x0b]?(?:--|[#\{]|/\*)?|[\"'`](?:[\s\x0b]*(?:(?:x?or|and|div|like|between)[\s\x0b\-0-9A-Z_a-z]+[\(\)\+-\-<->][\s\x0b]*[\"'0-9`]|[!=\|](?:[\s\x0b!\+\-0-9=]+[^\[]*[\"'\(`].*|[\s\x0b!0-9=]+[^0-9]*[0-9]+)$|(?:like|print)[^0-9A-Z_a-z]+[\"'\(0-9A-Z_-z]|;)|(?:[<>~]+|[\s\x0b]*[^\s\x0b0-9A-Z_a-z]?=[\s\x0b]*|[^0-9A-Z_a-z]*?[\+=]+[^0-9A-Z_a-z]*?)[\"'`])|[0-9][\"'`][\s\x0b]+[\"'`][\s\x0b]+[0-9]|^admin[\s\x0b]*?[\"'`]|[\s\x0b\"'\(`][\s\x0b]*?glob[^0-9A-Z_a-z]+[\"'\(0-9A-Z_-z]|[\s\x0b]is[\s\x0b]*?0[^0-9A-Z_a-z]|where[\s\x0b][\s\x0b,-\.0-9A-Z_a-z]+[\s\x0b]=" \
    "id:942180,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects basic SQL authentication bypass attempts 1/3',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942200` — Detects MySQL comment-/space-obfuscated injections and backtick termination

**Family:** SQL comments / obfuscation comments

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture, chain`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** MySQL comment/space obfuscated injections and backtick termination; chained rule validates MATCHED_VARS to reduce false positives.

**Source context and comments:**

```text
This rule is also triggered by the following exploit(s):
[ SAP CRM Java vulnerability CVE-2018-2380 - Exploit tested: https://www.exploit-db.com/exploits/44292 ]

Regular expression generated from regex-assembly/942200.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942200 942200-chain1
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer|ARGS_NAMES|ARGS|XML:/* "@rx (?i)(?:,[^\)]*?(?:[0-9a-f]+|\([0-9a-f]+\))|\([^,]+(?:,[\s\x0b]*[0-9a-f]+)+\))(?:$|[\"'`](?:$|[^\"'`]+[\"'`])|(?:\r?\n)?\z)|,[^\)]*?[\"'`][^\"'`]+[\"'`]|[^0-9A-Z_a-z]select.+[^0-9A-Z_a-z]*?from|(?:alter|(?:(?:cre|trunc|upd)at|renam)e|d(?:e(?:lete|sc)|rop)|(?:inser|selec)t|load)[\s\x0b]*?\([\s\x0b]*?space[\s\x0b]*?\(" \
    "id:942200,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects MySQL comment-/space-obfuscated injections and backtick termination',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    chain"
    SecRule MATCHED_VARS "!@rx ^[,\-0-9=A-Z_a-z]+$" \
        "t:none,\
        setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
        setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942210` — Detects chained SQL injection attempts 1/2

**Family:** General SQLi pattern

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Chained SQLi attempts with AND/OR/BETWEEN/DIV/LIKE, comments, SET @variable, select assignments.

**Source context and comments:**

```text
This rule is also triggered by the following exploit(s):
[ SAP CRM Java vulnerability CVE-2018-2380 - Exploit tested: https://www.exploit-db.com/exploits/44292 ]

Regular expression generated from regex-assembly/942210.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942210
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)(?:&&|\|\||and|between|div|like|n(?:and|ot)|(?:xx?)?or)[\s\x0b\(]+[0-9A-Z_a-z]+[\s\x0b\)]*?[!\+=]+[\s\x0b0-9]*?[\"'-\)=`]|[0-9](?:[\s\x0b]*?(?:and|between|div|like|x?or)[\s\x0b]*?[0-9]+[\s\x0b]*?[\+\-]|[\s\x0b]+group[\s\x0b]+by.+\()|/[0-9A-Z_a-z]+;?[\s\x0b]+(?:and|between|div|having|like|x?or|select)[^0-9A-Z_a-z]|(?:[#;]|--)[\s\x0b]*?(?:alter|drop|(?:insert|update)[\s\x0b]*?[0-9A-Z_a-z]{2,})|@.+=[\s\x0b]*?\([\s\x0b]*?select|[^0-9A-Z_a-z]SET[\s\x0b]*?@[0-9A-Z_a-z]+" \
    "id:942210,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects chained SQL injection attempts 1/2',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942260` — Detects basic SQL authentication bypass attempts 2/3

**Family:** Authentication bypass / query termination

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Basic auth bypass 2/3: quoted AND/OR/LIKE/BETWEEN forms and SELECT FROM patterns.

**Source context and comments:**

```text
Regular expression generated from regex-assembly/942260.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942260
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)[\"'`][\s\x0b]*?(?:(?:and|n(?:and|ot)|(?:xx?)?or|div|like|between|\|\||&&)[\s\x0b]+[\s\x0b0-9A-Z_a-z]+=[\s\x0b]*?[0-9A-Z_a-z]+[\s\x0b]*?having[\s\x0b]+|like[^0-9A-Z_a-z]*?[\"'0-9`])|[0-9A-Z_a-z][\s\x0b]+like[\s\x0b]+[\"'`]|like[\s\x0b]*?[\"'`]%|select[\s\x0b]+?[\s\x0b\"'-\),-\.0-9A-\[\]_-z]+from[\s\x0b]+" \
    "id:942260,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects basic SQL authentication bypass attempts 2/3',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942300` — Detects MySQL comments, conditions and ch(a)r injections

**Family:** SQL comments / obfuscation comments

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** MySQL comments, conditional expressions, char/chr function injection, logical operator with parentheses.

**Source context and comments:**

```text
Regular expression generated from regex-assembly/942300.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942300
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)\)[\s\x0b]*?when[\s\x0b]*?[0-9]+[\s\x0b]*?then|[\"'`][\s\x0b]*?(?:[#\{]|--)|/\*![\s\x0b]?[0-9]+|\b(?:(?:binary|cha?r)[\s\x0b]*?\([\s\x0b]*?[0-9]|(?:and|n(?:and|ot)|(?:xx?)?or|div|like|between|r(?:egexp|like))[\s\x0b]+[0-9A-Z_a-z]+\()|(?:\|\||&&)[\s\x0b]*?[0-9A-Z_a-z]+\(" \
    "id:942300,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects MySQL comments, conditions and ch(a)r injections',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942310` — Detects chained SQL injection attempts 2/2

**Family:** General SQLi pattern

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Chained SQLi 2/2: select inside parentheses, coalesce, order by if, */from, @@ variables, case/when patterns.

**Source context and comments:**

```text
Regular expression generated from regex-assembly/942310.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942310
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)(?:\([\s\x0b]*?select[\s\x0b]*?[0-9A-Z_a-z]+|coalesce|order[\s\x0b]+by[\s\x0b]+if[0-9A-Z_a-z]*?)[\s\x0b]*?\(|\*/from|\+[\s\x0b]*?[0-9]+[\s\x0b]*?\+[\s\x0b]*?@|[0-9A-Z_a-z][\"'`][\s\x0b]*?(?:(?:[\+\-=@\|]+[\s\x0b]+?)+|[\+\-=@\|]+)[\(0-9]|@@[0-9A-Z_a-z]+[\s\x0b]*?[^\s\x0b0-9A-Z_a-z]|[^0-9A-Z_a-z]!+[\"'`][0-9A-Z_a-z]|[\"'`](?:;[\s\x0b]*?(?:if|while|begin)|[\s\x0b0-9]+=[\s\x0b]*?[0-9])|[\s\x0b\(]+case[0-9]*?[^0-9A-Z_a-z].+[tw]hen[\s\x0b\(]" \
    "id:942310,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects chained SQL injection attempts 2/2',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942330` — Detects classic SQL injection probings 1/3

**Family:** SQL probing payloads

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Classic SQL probing 1/3: quote/operator combinations, hex escapes, information_schema, table_name.

**Source context and comments:**

```text
-=[ SQL Injection Probings ]=-

This is a group of three similar rules aiming to detect SQL injection probings.

942330 PL 2
942370 PL 2
942490 PL 3
Regular expression generated from regex-assembly/942330.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942330
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)[\"'`][\s\x0b]*?\b(?:x?or|div|like|between|and)\b[\s\x0b]*?[\"'`]?[0-9]|\x5cx(?:2[37]|3d)|^(?:.?[\"'`]$|[\"'\x5c`]*?(?:[\"'0-9`]+|[^\"'`]+[\"'`])[\s\x0b]*?\b(?:and|n(?:and|ot)|(?:xx?)?or|div|like|between|\|\||&&)\b[\s\x0b]*?[\"'0-9A-Z_-z][!&\(\)\+-\.@])|[^\s\x0b0-9A-Z_a-z][0-9A-Z_a-z]+[\s\x0b]*?[\-\|][\s\x0b]*?[\"'`][\s\x0b]*?[0-9A-Z_a-z]|@(?:[0-9A-Z_a-z]+[\s\x0b]+(?:and|x?or|div|like|between)\b[\s\x0b]*?[\"'0-9`]+|[\-0-9A-Z_a-z]+[\s\x0b](?:and|x?or|div|like|between)\b[\s\x0b]*?[^\s\x0b0-9A-Z_a-z])|[^\s\x0b0-:A-Z_a-z][\s\x0b]*?[0-9][^0-9A-Z_a-z]+[^\s\x0b0-9A-Z_a-z][\s\x0b]*?[\"'`].|[^0-9A-Z_a-z]information_schema|table_name[^0-9A-Z_a-z]" \
    "id:942330,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects classic SQL injection probings 1/3',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942340` — Detects basic SQL authentication bypass attempts 3/3

**Family:** Authentication bypass / query termination

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Basic auth bypass 3/3 with IN SELECT, boolean/logical operator variants, EXCEPT SELECT/VALUES.

**Source context and comments:**

```text
Regular expression generated from regex-assembly/942340.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942340

Note that part of 942340.data is already optimized, to avoid a
Regexp::Assemble behaviour, where the regex is not optimized very nicely.
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)in[\s\x0b]*?\(+[\s\x0b]*?select|(?:(?:and|n(?:and|ot)|(?:xx?)?or|div|like|between)[\s\x0b]+|(?:\|\||&&)[\s\x0b]*?)[\s\x0b\+0-9A-Z_a-z]+(?:regexp[\s\x0b]*?\(|sounds[\s\x0b]+like[\s\x0b]*?[\"'`]|[0-9=]+x)|[\"'`](?:[\s\x0b]*?(?:(?:[0-9]+[\s\x0b]*?(?:--|#)|is[\s\x0b]*?(?:[0-9][^\"'`]+[\"'`]?[0-9A-Z_a-z]|[\.0-9]+[\s\x0b]*?[^0-9A-Z_a-z][^\"'`]*[\"'`])|(?:and|n(?:and|ot)|(?:xx?)?or|div|like|between)[\s\x0b]+|(?:\|\||&&)[\s\x0b]*?)(?:array[\s\x0b]*?\[|(?:tru|fals)e\b|[0-9A-Z_a-z]+(?:[\s\x0b]*?!?~|[\s\x0b]+(?:not[\s\x0b]+)?similar[\s\x0b]+to[\s\x0b]+))|[%&<->\^]+[0-9]+[\s\x0b]*?(?:and|n(?:and|ot)|(?:xx?)?or|div|like|between)=)|(?:[^0-9A-Z_a-z]+[\+\-0-9A-Z_a-z]+[\s\x0b]*?=[\s\x0b]*?[0-9][^0-9A-Z_a-z]+|\|?[\-0-9A-Z_a-z]{3,}[^\s\x0b,\.0-9A-Z_a-z]+)[\"'`])|\bexcept[\s\x0b]+(?:select\b|values[\s\x0b]*?\()" \
    "id:942340,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects basic SQL authentication bypass attempts 3/3',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942361` — Detects basic SQL injection based on keyword alter or union

**Family:** Union/select/data manipulation SQLi

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** PL2 stricter sibling of 942360 for leading non-word/digit followed by alter or union.

**Source context and comments:**

```text
This rule is a stricter sibling of 942360.
The keywords 'alter' and 'union' led to false positives.
Therefore they have been moved to PL2 and the keywords have been extended on PL1.
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i:^[\W\d]+\s*?(?:alter|union)\b)" \
    "id:942361,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects basic SQL injection based on keyword alter or union',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942362` — Detects concatenated basic SQL injection and SQLLFI attempts

**Family:** Union/select/data manipulation SQLi

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** PL2 looser sibling of 942360 moved from PL1 due false positives but broader payload coverage.

**Source context and comments:**

```text
This rule is a stricter sibling of 942360.
The loose word boundaries and light context led to false positives.
Because the stricter variant does miss quite a few legitimate payloads, the loose version was moved to PL2.

Regular expression generated from regex-assembly/942362.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942362
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)(?:alter|(?:(?:cre|trunc|upd)at|renam)e|de(?:lete|sc)|(?:inser|selec)t|load)[\s\x0b]+(?:char|group_concat|load_file)[\s\x0b]?\(?|end[\s\x0b]*?\);|[\s\x0b\(]load_file[\s\x0b]*?\(|[\"'`][\s\x0b]+regexp[^0-9A-Z_a-z]|[^A-Z_a-z][\s\x0b]+as\b[\s\x0b]*[\"'0-9A-Z_-z]+[\s\x0b]*\bfrom|^[^A-Z_a-z]+[\s\x0b]*?(?:create[\s\x0b]+[0-9A-Z_a-z]+|(?:d(?:e(?:lete|sc)|rop)|(?:inser|selec)t|load|(?:renam|truncat)e|u(?:pdate|nion[\s\x0b]*(?:all|(?:sele|distin)ct))|alter[\s\x0b]*(?:a(?:(?:ggregat|pplication[\s\x0b]*rol)e|s(?:sembl|ymmetric[\s\x0b]*ke)y|u(?:dit|thorization)|vailability[\s\x0b]*group)|b(?:roker[\s\x0b]*priority|ufferpool)|c(?:ertificate|luster|o(?:l(?:latio|um)|nversio)n|r(?:edential|yptographic[\s\x0b]*provider))|d(?:atabase|efault|i(?:mension|skgroup)|omain)|e(?:(?:ndpoi|ve)nt|xte(?:nsion|rnal))|f(?:lashback|oreign|u(?:lltext|nction))|hi(?:erarchy|stogram)|group|in(?:dex(?:type)?|memory|stance)|java|l(?:a(?:ngua|r)ge|ibrary|o(?:ckdown|g(?:file[\s\x0b]*group|in)))|m(?:a(?:s(?:k|ter[\s\x0b]*key)|terialized)|e(?:ssage[\s\x0b]*type|thod)|odule)|(?:nicknam|queu)e|o(?:perator|utline)|p(?:a(?:ckage|rtition)|ermission|ro(?:cedur|fil)e)|r(?:e(?:mot|sourc)e|o(?:l(?:e|lback)|ute))|s(?:chema|e(?:arch|curity|rv(?:er|ice)|quence|ssion)|y(?:mmetric[\s\x0b]*key|nonym)|togroup)|t(?:able(?:space)?|ext|hreshold|r(?:igger|usted)|ype)|us(?:age|er)|view|w(?:ork(?:load)?|rapper)|x(?:ml[\s\x0b]*schema|srobject)))\b)" \
    "id:942362,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects concatenated basic SQL injection and SQLLFI attempts',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942370` — Detects classic SQL injection probings 2/3

**Family:** SQL probing payloads

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:Referer|REQUEST_HEADERS:User-Agent|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Classic SQL probing 2/3 for quote/operator/comment patterns and header targets.

**Source context and comments:**

```text
This rule is a sibling of 942330. See that rule for a description and overview.

This rule is also triggered by the following exploit(s):
[ SAP CRM Java vulnerability CVE-2018-2380 - Exploit tested: https://www.exploit-db.com/exploits/44292 ]

Regular expression generated from regex-assembly/942370.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942370
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:Referer|REQUEST_HEADERS:User-Agent|ARGS_NAMES|ARGS|XML:/* "@rx (?i)[\"'`](?:[\s\x0b]*?(?:(?:\*.+(?:x?or|div|like|between|(?:an|i)d)[^0-9A-Z_a-z]*?[\"'`]|(?:x?or|div|like|between|and)[\s\x0b][^0-9]+[\-0-9A-Z_a-z]+[^0-9]*)[0-9]|[^\s\x0b0-9\?A-Z_a-z]+[\s\x0b]*?[^\s\x0b0-9A-Z_a-z]+[\s\x0b]*?[\"'`]|[^\s\x0b0-9A-Z_a-z]+[\s\x0b]*?[^A-Z_a-z](?:[^#]*#|.*?--))|[^\*]*\*[\s\x0b]*?[0-9])|\^[\"'`]|[%\(-\+\-<>][\-0-9A-Z_a-z]+[^\s\x0b0-9A-Z_a-z]+[\"'`][^,]" \
    "id:942370,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects classic SQL injection probings 2/3',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942380` — SQL Injection Attack

**Family:** General SQLi pattern

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** General SQLi detector: having comparisons, execute, exists select, create table, order by, from limit.

**Source context and comments:**

```text
Regular expression generated from regex-assembly/942380.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942380
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)\b(?:having\b(?:[\s\x0b]+(?:[0-9]{1,10}|'[^=]{1,10}')[\s\x0b]*?[<->]| ?(?:[0-9]{1,10} ?[<->]+|[\"'][^=]{1,10}[ \"'<-\?\[]+))|ex(?:ecute(?:\(|[\s\x0b]{1,5}[\$\.0-9A-Z_a-z]{1,5}[\s\x0b]{0,3})|ists[\s\x0b]*?\([\s\x0b]*?select\b)|(?:create[\s\x0b]+?table.{0,20}?|like[^0-9A-Z_a-z]*?char[^0-9A-Z_a-z]*?)\()|select.*?case|from.*?limit|order[\s\x0b]by|exists[\s\x0b](?:[\s\x0b]select|s(?:elect[^\s\x0b](?:if(?:null)?[\s\x0b]\(|top|concat)|ystem[\s\x0b]\()|\bhaving\b[\s\x0b]+[0-9]{1,10}|'[^=]{1,10}')" \
    "id:942380,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Injection Attack',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942390` — SQL Injection Attack

**Family:** General SQLi pattern

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** General OR/XOR comparison attack detector, including quoted OR payloads.

**Source context and comments:**

```text
Regular expression generated from regex-assembly/942390.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942390
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)\b(?:or\b(?:[\s\x0b]?(?:[0-9]{1,10}|[\"'][^=]{1,10}[\"'])[\s\x0b]?[<->]+|[\s\x0b]+(?:[0-9]{1,10}|'[^=]{1,10}')(?:[\s\x0b]*?[<->])?)|xor\b[\s\x0b]+(?:[0-9]{1,10}|'[^=]{1,10}')(?:[\s\x0b]*?[<->])?)|'[\s\x0b]+x?or[\s\x0b]+.{1,20}[!\+\-<->]" \
    "id:942390,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Injection Attack',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942400` — SQL Injection Attack

**Family:** General SQLi pattern

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** General SQLi pattern detector; keep with neighboring CRS source for exact semantics.

**Source context and comments:**

```text
Regular expression generated from regex-assembly/942400.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942400
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)\band\b(?:[\s\x0b]+(?:[0-9]{1,10}[\s\x0b]*?[<->]|'[^=]{1,10}')| ?(?:[0-9]{1,10}|[\"'][^=]{1,10}[\"']) ?[<->]+)" \
    "id:942400,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Injection Attack',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942410` — SQL Injection Attack

**Family:** General SQLi pattern

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** SQL function keyword detector split from older 942410 rule set.

**Source context and comments:**

```text
The former rule id 942410 was split into three new rules: 942410, 942470, 942480

This rule is also triggered by the following exploit(s):
[ SAP CRM Java vulnerability CVE-2018-2380 - Exploit tested: https://www.exploit-db.com/exploits/44292 ]

Regular expression generated from regex-assembly/942410.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942410
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)\b(?:a(?:(?:b|co)s|vg)|bin|c(?:(?:as|o(?:nver|un))t|h(?:ar(?:set)?|r))|d(?:a(?:te|y)|e(?:fault|grees))|elt|f(?:ield|loor|ormat)|(?:hou|quarte|yea)r|i[fns]|l(?:ast|e(?:ft|ngth)|n|ikelihood|o(?:cal|g|wer))|m(?:ax|in(?:ute)?|o(?:d|nth))|now|p(?:assword|i|o(?:sition|wer))|r(?:awtonhex(?:toraw)?|e(?:p(?:eat|lace)|verse)|ight|ound)|s(?:econd|ign|leep|pace|tddev|um)|t(?:an|ime|o_(?:n?char|(?:day|second)s))|u(?:nlikely|(?:pp|s)er)|v(?:alues|ersion)|week)[^0-9A-Z_a-z]*?\(" \
    "id:942410,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Injection Attack',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942470` — SQL Injection Attack

**Family:** General SQLi pattern

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** SQL function keyword detector split from former 942410.

**Source context and comments:**

```text
The former rule id 942410 was split into three new rules: 942410, 942470, 942480

Regular expression generated from regex-assembly/942470.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942470
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)autonomous_transaction|(?:current_use|n?varcha|tbcreato)r|db(?:a_users|ms_java)|open(?:owa_util|query|rowset)|s(?:p_(?:(?:addextendedpro|sqlexe)c|execute(?:sql)?|help|is_srvrolemember|makewebtask|oacreate|p(?:assword|repare)|replwritetovarbin)|ql_(?:longvarchar|variant))|utl_(?:file|http)|xp_(?:availablemedia|(?:cmdshel|servicecontro)l|dirtree|e(?:numdsn|xecresultset)|filelist|loginconfig|makecab|ntsec(?:_enumdomains)?|reg(?:addmultistring|delete(?:key|value)|enum(?:key|value)s|re(?:ad|movemultistring)|write)|terminate(?:_process)?)" \
    "id:942470,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Injection Attack',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942480` — SQL Injection Attack

**Family:** General SQLi pattern

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS|!REQUEST_HEADERS:Cookie|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** SQL function keyword detector split from former 942410.

**Source context and comments:**

```text
The former rule id 942410 was split into three new rules: 942410, 942470, 942480

Regular expression generated from regex-assembly/942480.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942480
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS|!REQUEST_HEADERS:Cookie|ARGS_NAMES|ARGS|XML:/* "@rx (?i)\b(?:(?:d(?:bms_[0-9A-Z_a-z]+\.|elete\b[^0-9A-Z_a-z]*?\bfrom)|(?:group\b.*?\bby\b.{1,100}?\bhav|overlay\b[^0-9A-Z_a-z]*?\(.*?\b[^0-9A-Z_a-z]*?plac)ing|in(?:ner\b[^0-9A-Z_a-z]*?\bjoin|sert\b[^0-9A-Z_a-z]*?\binto|to\b[^0-9A-Z_a-z]*?\b(?:dump|out)file)|load\b[^0-9A-Z_a-z]*?\bdata\b.*?\binfile|s(?:elect\b.{1,100}?\b(?:(?:.*?\bdump\b.*|(?:count|length)\b.{1,100}?)\bfrom|(?:data_typ|from\b.{1,100}?\bwher)e|instr|to(?:_(?:cha|numbe)r|p\b.{1,100}?\bfrom))|ys_context)|u(?:nion\b.{1,100}?\bselect|tl_inaddr))\b|print\b[^0-9A-Z_a-z]*?@@)|(?:collation[^0-9A-Z_a-z]*?\(a|@@version|;[^0-9A-Z_a-z]*?\b(?:drop|shutdown))\b|'(?:dbo|msdasql|s(?:a|qloledb))'" \
    "id:942480,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Injection Attack',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942430` — Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (12)

**Family:** Character anomaly / meta-character detection

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `WARNING`  
**Actions:** `block, capture`  
**Score updates:** `tx.inbound_anomaly_score_pl2=+%{tx.warning_anomaly_score}; tx.sql_injection_score=+%{tx.warning_anomaly_score}`  

**Rule-generation use:** Character anomaly detection for args: high count of special SQL metacharacters. Warning severity.

**Source context and comments:**

```text
[ SQL Injection Character Anomaly Usage ]

This rule is also triggered by the following exploit(s):
[ SAP CRM Java vulnerability CVE-2018-2380 - Exploit tested: https://www.exploit-db.com/exploits/44292 ]

This rules attempts to gauge when there is an excessive use of
meta-characters within a single parameter payload.

Expect a lot of false positives with this rule.
The most likely false positive instances will be free-form text fields.
This will make it necessary to disable the rule for certain known parameters.
The following directive is an example to switch off the rule globally for
the parameter foo. Place this instruction in your configuration after
the include directive for the Core Rules Set.

SecRuleUpdateTargetById 942430 "!ARGS:foo"

Regular expression generated from regex-assembly/942430.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942430
```

**Source `SecRule` block:**

```apache
SecRule ARGS_NAMES|ARGS|XML:/* "@rx ((?:(?:[!-\+\-:->@\[\]\^`\{-~]|\x{c2}\x{b4}|\x{e2}\x80[\x98\x99])[^!-\+\-:->@\[\]\^`\{-~]*?){12})" \
    "id:942430,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (12)',\
    logdata:'Matched Data: %{TX.1} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'WARNING',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.warning_anomaly_score}',\
    setvar:'tx.sql_injection_score=+%{tx.warning_anomaly_score}'"
```

## Rule `942440` — SQL Comment Sequence Detected

**Family:** SQL comments / obfuscation comments

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture, chain`  
**Score updates:** `tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}; tx.sql_injection_score=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** SQL comment sequence detector: catches comments independently and complements inline-comment rule 942500.

**Source context and comments:**

```text
-=[ Detect SQL Comment Sequences ]=-

Example Payloads Detected:
-------------------------
OR 1#
DROP sampletable;--
admin'--
DROP/*comment*/sampletable
DR/**/OP/*bypass deny listing*/sampletable
SELECT/*avoid-spaces*/password/**/FROM/**/Members
SELECT /*!32302 1/0, */ 1 FROM tablename
‘ or 1=1#
‘ or 1=1-- -
‘ or 1=1/*
' or 1=1;\x00
1='1' or-- -
' /*!50000or*/1='1
' /*!or*/1='1
0/**/union/*!50000select*/table_name`foo`/**/
-------------------------

The chained rule is designed to prevent false positives by specifically
targeting JWT tokens and common tokens (brid, fbclid, gclid, recaptcha, ttclid, etc).

Starting with 'ey' targets JWT tokens, where the 'ey'
prefix corresponds to the beginning of the Base64-encoded header section.

example:
$ echo '{"' | base64
eyIK

Regular expressions generated from regex-assembly/942440.ra and regex-assembly/942440-chain1.ra.
To update the regular expressions run the following shell scripts
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942440
crs-toolchain regex update 942440-chain1
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx /\*!?|\*/|[';]--|--(?:[\s\x0b]|[^\-]*?-)|[^&\-]#.*?[\s\x0b]|;?\x00" \
    "id:942440,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Comment Sequence Detected',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    chain"
    SecRule MATCHED_VARS "!@rx ^(?:ey[\-0-9A-Z_a-z]+\.ey[\-0-9A-Z_a-z]+\.)?[\-0-9A-Z_a-z]+$" \
        "t:none,\
        setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}',\
        setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}'"
```

## Rule `942450` — SQL Bin or Hex Encoding Identified

**Family:** General SQLi pattern

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** SQL binary or hex encoding detector.

**Source context and comments:**

```text
-=[ SQL Bin / Hex Evasion Methods ]=-

Hex encoding detection:
(?i:\b0x[a-f\d]{3,}) will match any 3 or more hex bytes after "0x", together forming a hexadecimal payload(e.g 0xf00, 0xf00d and so on)

Regular expression generated from regex-assembly/942450.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942450
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)\b0x[0-9a-f]{3,}|(?:x'[0-9a-f]{3,}|b'[01]{10,})'" \
    "id:942450,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Bin or Hex Encoding Identified',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942510` — SQLi bypass attempt by ticks or backticks detected

**Family:** General SQLi pattern

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Ticks or backticks SQLi bypass detector.

**Source context and comments:**

```text
-=[ Detect SQLi bypass: backticks ]=-

Quotes and backticks can be used to bypass SQLi detection.

Example:
GET http://localhost/test.php?id=9999%20or+{`if`(2=(select+2+from+wp_users+where+user_login='admin'))}

The minimum text between the ticks or backticks must be 2 (if, for example) and a maximum of 29.
29 is a compromise: The lower this number (29), the lower the probability of FP and the higher the probability of false negatives.
In tests we got a minimum number of FP with {2,29}.

Base64 encoding detection:
(?:[A-Za-z0-9+/]{4})+ #match any number of 4-letter blocks of the base64 char set
(?:[A-Za-z0-9+/]{2}== #match 2-letter block of the base64 char set followed by "==", together forming a 4-letter block
|                     # or
[A-Za-z0-9+/]{3}=     #match 3-letter block of the base64 char set followed by "=", together forming a 4-letter block
)?

The minimal string that triggers this regexp is: `if`

The rule 942511 is similar to this rule, but triggers on normal quotes
('if'). That rule runs in paranoia level 3 or higher since it is prone to
false positives in natural text.

Regular expression generated from regex-assembly/942510.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942510
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx `(?:[\s\x0b\(\)\+\-0-9<=@-Z_a-\{\}]{2,29}|(?:[\+/-9A-Za-z]{4})+(?:(?:[\+/-9A-Za-z]{2}=|[\+/-9A-Za-z]{3})=)?)`" \
    "id:942510,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQLi bypass attempt by ticks or backticks detected',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942520` — Detects basic SQL authentication bypass attempts 4.0/4

**Family:** Authentication bypass / query termination

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Authentication bypass 4.0/4: broad operator and keyword detector.

**Source context and comments:**

```text
Regular expression generated from regex-assembly/942520.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942520
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)[\"'`][\s\x0b]*?(?:(?:is[\s\x0b]+not|not[\s\x0b]+(?:like|glob|(?:betwee|i)n|null|regexp|match)|mod|div|sounds[\s\x0b]+like)\b|[%&\*\+\-/<->\^\|]{1,3})" \
    "id:942520,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects basic SQL authentication bypass attempts 4.0/4',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942521` — Detects basic SQL authentication bypass attempts 4.1/4

**Family:** Authentication bypass / query termination

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture, chain`  
**Score updates:** `tx.942521_matched_var_name=%{matched_var_name}; tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Authentication bypass 4.1/4: odd number of quotes followed by AND/OR; chained to validate token.

**Source context and comments:**

```text
Complementary rule to PL2 942520 that block and/or-based bypasses.
It blocks data with odd number of quotes and then (and|or).

The rule uses the expression ^b*a*(b*a*b*a*)* to odd number of a's. It's not
vulnerable to ReDos as it executes linearly many steps compared to input size.

Regular expression generated from regex-assembly/942521.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942521
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer|ARGS_NAMES|ARGS|XML:/* "@rx (?i)^(?:[^']*?(?:'[^']*?'[^']*?)*?'|[^\"]*?(?:\"[^\"]*?\"[^\"]*?)*?\"|[^`]*?(?:`[^`]*?`[^`]*?)*?`)[\s\x0b]*([0-9A-Z_a-z]+)\b" \
    "id:942521,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects basic SQL authentication bypass attempts 4.1/4',\
    logdata:'Matched Data: %{TX.0} found within %{TX.942521_MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.942521_matched_var_name=%{matched_var_name}',\
    chain"
    SecRule TX:1 "@rx ^(?:and|or)$" \
        "t:none,\
        setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
        setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942522` — Detects basic SQL authentication bypass attempts 4.1/4

**Family:** Authentication bypass / query termination

**Paranoia level:** `2`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Complement to 942521 for escaped quotes followed by AND/OR.

**Source context and comments:**

```text
Complementary rule to PL2 942521 that block escaped quotes followed by (and|or)
```

**Source `SecRule` block:**

```apache
SecRule ARGS_NAMES|ARGS|XML:/* "@rx ^.*?\x5c['\"`](?:.*?['\"`])?\s*(?:and|or)\b" \
    "id:942522,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects basic SQL authentication bypass attempts 4.1/4',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942101` — SQL Injection Attack Detected via libinjection

**Family:** Libinjection SQLi detection

**Paranoia level:** `2`  
**Phase:** `1`  
**Operator:** `@detectSQLi`  
**Target:** `REQUEST_BASENAME|REQUEST_FILENAME`  
**Transformations:** `none, utf8toUnicode, urlDecodeUni, removeNulls`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Stricter libinjection sibling that checks URL path components through REQUEST_BASENAME and REQUEST_FILENAME. Use when SQLi appears in URI path rather than parameters.

**Source context and comments:**

```text
This is a sibling of rule 942100 that adds checking of the path.

REQUEST_BASENAME provides the last url segment (slash excluded).
This segment is the most likely to be used for injections. Stripping out
the slash permits libinjection to do not consider it as a payload starting
with not unary arithmetical operators (not a valid SQL command, e.g.
'/9 union all'). The latter would lead to do not detect malicious payloads.

REQUEST_FILENAME matches SQLi payloads inside (or across) other segments
of the path. Here, libinjection will detect a true positive only if
the url leading slash is considered as part of a comment block or part
of a string (with a quote or double quote after it). In these circumstances,
previous slashes do not affect libinjection result, making it able to detect
some SQLi inside the path.
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_BASENAME|REQUEST_FILENAME "@detectSQLi" \
    "id:942101,\
    phase:1,\
    block,\
    capture,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,\
    msg:'SQL Injection Attack Detected via libinjection',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942152` — SQL Injection Attack: SQL function name detected

**Family:** SQL function / stored procedure / UDF

**Paranoia level:** `2`  
**Phase:** `1`  
**Operator:** `@rx`  
**Target:** `REQUEST_HEADERS:Referer|REQUEST_HEADERS:User-Agent`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Header-focused stricter sibling of 942151 for Referer and User-Agent function names.

**Source context and comments:**

```text
-=[ SQL Function Names ]=-

This rule is a stricter sibling of 942151.
This rule 942152 checks for the same regex in request headers referer and user-agent.

Regular expression generated from regex-assembly/942152.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942152
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_HEADERS:Referer|REQUEST_HEADERS:User-Agent "@rx (?i)\b(?:a(?:dd(?:dat|tim)e|es_(?:de|en)crypt|s(?:cii(?:str)?|in)|tan2?)|b(?:enchmark|i(?:n_to_num|t_(?:and|count|length|x?or)))|c(?:har(?:acter)?_length|eil(?:ing)?|o(?:alesce|ercibility|llation|(?:mpres)?s|n(?:cat(?:_ws)?|nection_id|v(?:ert(?:_tz)?)?)|t)|rc32|ur(?:(?:dat|tim)e|rent_(?:date|setting|time(?:stamp)?|user)))|d(?:a(?:t(?:abase(?:_to_xml)?|e(?:_(?:add|format|sub)|diff))|y(?:name|of(?:month|week|year)))|count|e(?:code|grees|s_(?:de|en)crypt)|ump)|e(?:lt|n(?:c(?:ode|rypt)|ds_?with)|x(?:p(?:ort_set)?|tract(?:value)?))|f(?:i(?:el|n)d_in_set|ound_rows|rom_(?:base64|days|unixtime))|g(?:e(?:ometrycollection|t(?:_(?:format|lock)|pgusername))|(?:r(?:eates|oup_conca)|tid_subse)t)|hex(?:toraw)?|i(?:fnull|n(?:et6?_(?:aton|ntoa)|s(?:ert|tr)|terval)|s(?:_(?:(?:free|used)_lock|ipv(?:4(?:_(?:compat|mapped))?|6)|n(?:ot(?:_null)?|ull)|superuser)|null))|json(?:_(?:a(?:gg|rray(?:_(?:elements(?:_text)?|length))?)|build_(?:array|object)|e(?:ac|xtract_pat)h(?:_text)?|object(?:_(?:agg|keys))?|populate_record(?:set)?|strip_nulls|t(?:o_record(?:set)?|ypeof))|b(?:_(?:array(?:_(?:elements(?:_text)?|length))?|build_(?:array|object)|object(?:_(?:agg|keys))?|e(?:ac|xtract_pat)h(?:_text)?|insert|p(?:ath_(?:(?:exists|match)(?:_tz)?|query(?:_(?:(?:array|first)(?:_tz)?|tz))?)|opulate_record(?:set)?|retty)|s(?:et(?:_lax)?|trip_nulls)|t(?:o_record(?:set)?|ypeof)))?|path)?|l(?:ast_(?:day|insert_id)|case|e(?:as|f)t|i(?:kel(?:ihood|y)|nestring)|o(?:_(?:from_bytea|put)|ad_file|ca(?:ltimestamp|te)|g(?:10|2)|wer)|pad|trim)|m(?:a(?:ke(?:_set|date)|ster_pos_wait)|d5|i(?:crosecon)?d|onthname|ulti(?:linestring|po(?:int|lygon)))|n(?:ame_const|ot_in|ullif)|o(?:ct(?:et_length)?|(?:ld_passwo)?rd)|p(?:eriod_(?:add|diff)|g_(?:client_encoding|(?:databas|read_fil)e|l(?:argeobject|s_dir)|sleep|user)|o(?:(?:lyg|siti)on|w)|rocedure_analyse)|qu(?:arter|ery_to_xml|ote)|r(?:a(?:dians|nd|wtohex)|elease_lock|ow_(?:count|to_json)|pad|trim)|s(?:chema|e(?:c_to_time|ssion_user)|ha[12]?|in|oundex|pace|q(?:lite_(?:compileoption_(?:get|used)|source_id)|rt)|t(?:arts_?with|d(?:dev_(?:po|sam)p)?|r(?:_to_date|cmp))|ub(?:(?:dat|tim)e|str(?:ing(?:_index)?)?)|ys(?:date|tem_user))|t(?:ime(?:_(?:format|to_sec)|diff|stamp(?:add|diff)?)|o(?:_(?:base64|jsonb?)|n?char|(?:day|second)s)|r(?:im|uncate))|u(?:case|n(?:compress(?:ed_length)?|hex|i(?:str|x_timestamp)|likely)|(?:pdatexm|se_json_nul)l|tc_(?:date|time(?:stamp)?)|uid(?:_short)?)|var(?:_(?:po|sam)p|iance)|we(?:ek(?:day|ofyear)|ight_string)|xmltype|yearweek)[^0-9A-Z_a-z]*\(" \
    "id:942152,\
    phase:1,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Injection Attack: SQL function name detected',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942321` — Detects MySQL and PostgreSQL stored procedure/function injections

**Family:** SQL function / stored procedure / UDF

**Paranoia level:** `2`  
**Phase:** `1`  
**Operator:** `@rx`  
**Target:** `REQUEST_HEADERS:Referer|REQUEST_HEADERS:User-Agent`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Header-specific stricter sibling of 942320 for Referer and User-Agent.

**Source context and comments:**

```text
This rule is a stricter sibling of 942320.
It checks for the same regex in request headers referer and user-agent.

Regular expression generated from regex-assembly/942321.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942321
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_HEADERS:Referer|REQUEST_HEADERS:User-Agent "@rx (?i)create[\s\x0b]+(?:function|procedure)[\s\x0b]*?[0-9A-Z_a-z]+[\s\x0b]*?\([\s\x0b]*?\)[\s\x0b]*?-|d(?:eclare[^0-9A-Z_a-z]+[#@][\s\x0b]*?[0-9A-Z_a-z]+|iv[\s\x0b]*?\([\+\-]*[\s\x0b\.0-9]+,[\+\-]*[\s\x0b\.0-9]+\))|exec[\s\x0b]*?\([\s\x0b]*?@|(?:lo_(?:impor|ge)t|procedure[\s\x0b]+analyse)[\s\x0b]*?\(|;[\s\x0b]*?(?:declare|open)[\s\x0b]+[\-0-9A-Z_a-z]+|::(?:b(?:igint|ool)|double[\s\x0b]+precision|int(?:eger)?|numeric|oid|real|(?:tex|smallin)t)" \
    "id:942321,\
    phase:1,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects MySQL and PostgreSQL stored procedure/function injections',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/2',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

## Rule `942015` — Paranoia-level gate / skip marker

**Family:** Paranoia-level gate / skip marker

**Paranoia level:** `control/gate`  
**Phase:** `1`  
**Operator:** `@lt`  
**Target:** `TX:DETECTION_PARANOIA_LEVEL`  
**Transformations:** `-`  
**Actions:** `pass, nolog`  

**Rule-generation use:** Use this rule when the observed payload matches the message, family, target, and pattern shown below. Scope to the vulnerable parameter or path when possible to reduce false positives.

**Source `SecRule` block:**

```apache
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 3" "id:942015,phase:1,pass,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.27.0-dev',skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI"
```

## Rule `942016` — Paranoia-level gate / skip marker

**Family:** Paranoia-level gate / skip marker

**Paranoia level:** `control/gate`  
**Phase:** `2`  
**Operator:** `@lt`  
**Target:** `TX:DETECTION_PARANOIA_LEVEL`  
**Transformations:** `-`  
**Actions:** `pass, nolog`  

**Rule-generation use:** Use this rule when the observed payload matches the message, family, target, and pattern shown below. Scope to the vulnerable parameter or path when possible to reduce false positives.

**Source `SecRule` block:**

```apache
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 3" "id:942016,phase:2,pass,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.27.0-dev',skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI"
```

## Rule `942251` — Detects HAVING injections

**Family:** Libinjection SQLi detection

**Paranoia level:** `3`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** PL3 stricter HAVING detector split off due false positives; comments say libinjection should detect HAVING SQLi.

**Source context and comments:**

```text
-= Paranoia Level 3 =- (apply only when tx.detection_paranoia_level is sufficiently high: 3 or higher)


[ SQL HAVING queries ]

This pattern was split off from rule 942250 due to frequent
false positives in English text. Testing showed that SQL
injections with HAVING should be detected by libinjection
(rule 942100).

This is a stricter sibling of rule 942250.
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)\W+\d*?\s*?\bhaving\b\s*?[^\s\-]" \
    "id:942251,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects HAVING injections',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/3',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}'"
```

## Rule `942490` — Detects classic SQL injection probings 3/3

**Family:** SQL probing payloads

**Paranoia level:** `3`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** PL3 classic SQL probing 3/3 stricter sibling of 942330.

**Source context and comments:**

```text
This rule is a stricter sibling of 942330. See that rule for a
description and overview.
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx [\"'`][\s\d]*?[^\w\s]\W*?\d\W*?.*?[\"'`\d]" \
    "id:942490,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Detects classic SQL injection probings 3/3',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/3',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}'"
```

## Rule `942420` — Restricted SQL Character Anomaly Detection (cookies): # of special characters exceeded (8)

**Family:** Character anomaly / meta-character detection

**Paranoia level:** `3`  
**Phase:** `1`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `WARNING`  
**Actions:** `block, capture`  
**Score updates:** `tx.inbound_anomaly_score_pl3=+%{tx.warning_anomaly_score}; tx.sql_injection_score=+%{tx.warning_anomaly_score}`  

**Rule-generation use:** Use this rule when the observed payload matches the message, family, target, and pattern shown below. Scope to the vulnerable parameter or path when possible to reduce false positives.

**Source context and comments:**

```text
[ SQL Injection Character Anomaly Usage ]

This rule attempts to gauge when there is an excessive use of
meta-characters within a single parameter payload.

It is similar to 942430, but focuses on Cookies instead of
GET/POST parameters.

Expect a lot of false positives with this rule.
The most likely false positive instances will be complex session ids.
This will make it necessary to disable the rule for certain known cookies.
The following directive is an example to switch off the rule globally for
the cookie foo_id. Place this instruction in your configuration after
the include directive for the Core Rules Set.

SecRuleUpdateTargetById 942420 "!REQUEST_COOKIES:foo_id"

Regular expression generated from regex-assembly/942420.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942420
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES "@rx ((?:(?:[!-\+\-:->@\[\]\^`\{-~]|\x{c2}\x{b4}|\x{e2}\x80[\x98\x99])[^!-\+\-:->@\[\]\^`\{-~]*?){8})" \
    "id:942420,\
    phase:1,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Restricted SQL Character Anomaly Detection (cookies): # of special characters exceeded (8)',\
    logdata:'Matched Data: %{TX.1} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/3',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'WARNING',\
    setvar:'tx.inbound_anomaly_score_pl3=+%{tx.warning_anomaly_score}',\
    setvar:'tx.sql_injection_score=+%{tx.warning_anomaly_score}'"
```

## Rule `942431` — Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (6)

**Family:** Character anomaly / meta-character detection

**Paranoia level:** `3`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `ARGS_NAMES|!ARGS_NAMES:/^[\w]+\[[\w\-]+\]\[[\w\-]*?\]$/|!ARGS_NAMES:/^[\w]+\[[\w\-]+\]\[[\w\-]+\]\[[\w\-]*?\]$/|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `WARNING`  
**Actions:** `block, capture`  
**Score updates:** `tx.inbound_anomaly_score_pl3=+%{tx.warning_anomaly_score}; tx.sql_injection_score=+%{tx.warning_anomaly_score}`  

**Rule-generation use:** Use this rule when the observed payload matches the message, family, target, and pattern shown below. Scope to the vulnerable parameter or path when possible to reduce false positives.

**Source context and comments:**

```text
This is a stricter sibling of rule 942430.

This rule is also triggered by the following exploit(s):
[ SAP CRM Java vulnerability CVE-2018-2380 - Exploit tested: https://www.exploit-db.com/exploits/44292 ]

Regular expression generated from regex-assembly/942431.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942431
```

**Source `SecRule` block:**

```apache
SecRule ARGS_NAMES|!ARGS_NAMES:/^[\w]+\[[\w\-]+\]\[[\w\-]*?\]$/|!ARGS_NAMES:/^[\w]+\[[\w\-]+\]\[[\w\-]+\]\[[\w\-]*?\]$/|ARGS|XML:/* "@rx ((?:(?:[!-\+\-:->@\[\]\^`\{-~]|\x{c2}\x{b4}|\x{e2}\x80[\x98\x99])[^!-\+\-:->@\[\]\^`\{-~]*?){6})" \
    "id:942431,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (6)',\
    logdata:'Matched Data: %{TX.1} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/3',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'WARNING',\
    setvar:'tx.inbound_anomaly_score_pl3=+%{tx.warning_anomaly_score}',\
    setvar:'tx.sql_injection_score=+%{tx.warning_anomaly_score}'"
```

## Rule `942460` — Meta-Character Anomaly Detection Alert - Repetitive Non-Word Characters

**Family:** Character anomaly / meta-character detection

**Paranoia level:** `3`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `ARGS`  
**Transformations:** `none`  
**Severity:** `WARNING`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.warning_anomaly_score}; tx.inbound_anomaly_score_pl3=+%{tx.warning_anomaly_score}`  

**Rule-generation use:** Repetitive non-word meta-character anomaly detector. Useful for heavily obfuscated probes.

**Source context and comments:**

```text
[ Repetitive Non-Word Characters ]

This rule attempts to identify when multiple (4 or more) non-word characters
are repeated in sequence.

The pattern may occur in some normal texts, e.g. "foo...." will match.

If your traffic contains languages that include accented characters, such as French,
Spanish, or German, be aware that you may encounter more false positives than
usual. In this case, you may consider increasing the consecutive occurrence limit
to 5 instead of 4.

This will help avoid common triggers such as "test=+à+", which is frequent in French.

All languages that use characters without a valid representation outside of UTF-8
(i.e., relying solely on multi-byte sequences such as %E6%84%9B (Japanese))
are incompatible with this rule.
In such cases, the rule should be globally disabled.
```

**Source `SecRule` block:**

```apache
SecRule ARGS "@rx \W{4}" \
    "id:942460,\
    phase:2,\
    block,\
    capture,\
    t:none,\
    msg:'Meta-Character Anomaly Detection Alert - Repetitive Non-Word Characters',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/3',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'WARNING',\
    setvar:'tx.sql_injection_score=+%{tx.warning_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl3=+%{tx.warning_anomaly_score}'"
```

## Rule `942511` — SQLi bypass attempt by ticks detected

**Family:** General SQLi pattern

**Paranoia level:** `3`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** PL3 stricter tick SQLi bypass detector.

**Source context and comments:**

```text
-=[ Detect SQLi bypass: quotes ]=-

Quotes and backticks can be used to bypass SQLi detection.

Example:
GET http://localhost/test.php?id=9999%20or+{`if`(2=(select+2+from+wp_users+where+user_login='admin'))}

The minimum text between the ticks or backticks must be 2 (if, for example) and a maximum of 29.
29 is a compromise: The lower this number (29), the lower the probability of FP and the higher the probability of false negatives.
In tests we got a minimum number of FP with {2,29}.

Base64 encoding detection:
(?:[A-Za-z0-9+/]{4})+ #match any number of 4-letter blocks of the base64 char set
(?:[A-Za-z0-9+/]{2}== #match 2-letter block of the base64 char set followed by "==", together forming a 4-letter block
|                     # or
[A-Za-z0-9+/]{3}=     #match 3-letter block of the base64 char set followed by "=", together forming a 4-letter block
)?

The minimal string that triggers this regexp is: 'if'

The rule 942510 is similar to this rule, but triggers on backticks
(`if`). That rule runs in paranoia level 2 or higher since the risk of
false positives in natural text is still present but lower than this
rule.

Regular expression generated from regex-assembly/942511.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942511
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx '(?:[\s\x0b\(\)\+\-0-9<=@-Z_a-\{\}]{2,29}|(?:[\+/-9A-Za-z]{4})+(?:(?:[\+/-9A-Za-z]{2}=|[\+/-9A-Za-z]{3})=)?)'" \
    "id:942511,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQLi bypass attempt by ticks detected',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/3',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}'"
```

## Rule `942530` — SQLi query termination detected

**Family:** Authentication bypass / query termination

**Paranoia level:** `3`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `CRITICAL`  
**Actions:** `block, capture`  
**Score updates:** `tx.sql_injection_score=+%{tx.critical_anomaly_score}; tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}`  

**Rule-generation use:** Query termination pattern for '; style payloads.

**Source context and comments:**

```text
Detects ';
' Single quote. Used to delineate a query with an unmatched quote.
; Terminate a query. A prematurely terminated query creates an error.
Explanation source:
https://hwang.cisdept.cpp.edu/swanew/Text/SQL-Injection.htm

Bug Bounty example: email=admin@juice-sh.op';&password=foo
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx ';" \
    "id:942530,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQLi query termination detected',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/3',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}'"
```

## Rule `942017` — Paranoia-level gate / skip marker

**Family:** Paranoia-level gate / skip marker

**Paranoia level:** `control/gate`  
**Phase:** `1`  
**Operator:** `@lt`  
**Target:** `TX:DETECTION_PARANOIA_LEVEL`  
**Transformations:** `-`  
**Actions:** `pass, nolog`  

**Rule-generation use:** Use this rule when the observed payload matches the message, family, target, and pattern shown below. Scope to the vulnerable parameter or path when possible to reduce false positives.

**Source `SecRule` block:**

```apache
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 4" "id:942017,phase:1,pass,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.27.0-dev',skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI"
```

## Rule `942018` — Paranoia-level gate / skip marker

**Family:** Paranoia-level gate / skip marker

**Paranoia level:** `control/gate`  
**Phase:** `2`  
**Operator:** `@lt`  
**Target:** `TX:DETECTION_PARANOIA_LEVEL`  
**Transformations:** `-`  
**Actions:** `pass, nolog`  

**Rule-generation use:** Use this rule when the observed payload matches the message, family, target, and pattern shown below. Scope to the vulnerable parameter or path when possible to reduce false positives.

**Source `SecRule` block:**

```apache
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 4" "id:942018,phase:2,pass,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.27.0-dev',skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI"
```

## Rule `942421` — Restricted SQL Character Anomaly Detection (cookies): # of special characters exceeded (3)

**Family:** Character anomaly / meta-character detection

**Paranoia level:** `4`  
**Phase:** `1`  
**Operator:** `@rx`  
**Target:** `REQUEST_COOKIES|REQUEST_COOKIES_NAMES`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `WARNING`  
**Actions:** `block, capture`  
**Score updates:** `tx.inbound_anomaly_score_pl4=+%{tx.warning_anomaly_score}; tx.sql_injection_score=+%{tx.warning_anomaly_score}`  

**Rule-generation use:** Use this rule when the observed payload matches the message, family, target, and pattern shown below. Scope to the vulnerable parameter or path when possible to reduce false positives.

**Source context and comments:**

```text
-= Paranoia Level 4 =- (apply only when tx.detection_paranoia_level is sufficiently high: 4 or higher)


[ SQL Injection Character Anomaly Usage ]

This is a stricter sibling of rule 942420.

Regular expression generated from regex-assembly/942421.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942421
```

**Source `SecRule` block:**

```apache
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES "@rx ((?:(?:[!-\+\-:->@\[\]\^`\{-~]|\x{c2}\x{b4}|\x{e2}\x80[\x98\x99])[^!-\+\-:->@\[\]\^`\{-~]*?){3})" \
    "id:942421,\
    phase:1,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Restricted SQL Character Anomaly Detection (cookies): # of special characters exceeded (3)',\
    logdata:'Matched Data: %{TX.1} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/4',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'WARNING',\
    setvar:'tx.inbound_anomaly_score_pl4=+%{tx.warning_anomaly_score}',\
    setvar:'tx.sql_injection_score=+%{tx.warning_anomaly_score}'"
```

## Rule `942432` — Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (2)

**Family:** Character anomaly / meta-character detection

**Paranoia level:** `4`  
**Phase:** `2`  
**Operator:** `@rx`  
**Target:** `ARGS_NAMES|ARGS|XML:/*`  
**Transformations:** `none, urlDecodeUni`  
**Severity:** `WARNING`  
**Actions:** `block, capture`  
**Score updates:** `tx.inbound_anomaly_score_pl4=+%{tx.warning_anomaly_score}; tx.sql_injection_score=+%{tx.warning_anomaly_score}`  

**Rule-generation use:** Use this rule when the observed payload matches the message, family, target, and pattern shown below. Scope to the vulnerable parameter or path when possible to reduce false positives.

**Source context and comments:**

```text
This is a stricter sibling of rule 942430.

This rule is also triggered by the following exploit(s):
[ SAP CRM Java vulnerability CVE-2018-2380 - Exploit tested: https://www.exploit-db.com/exploits/44292 ]

Regular expression generated from regex-assembly/942432.ra.
To update the regular expression run the following shell script
(consult https://coreruleset.org/docs/development/regex_assembly/ for details):
crs-toolchain regex update 942432
```

**Source `SecRule` block:**

```apache
SecRule ARGS_NAMES|ARGS|XML:/* "@rx ((?:(?:[!-\+\-:->@\[\]\^`\{-~]|\x{c2}\x{b4}|\x{e2}\x80[\x98\x99])[^!-\+\-:->@\[\]\^`\{-~]*?){2})" \
    "id:942432,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (2)',\
    logdata:'Matched Data: %{TX.1} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/4',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-SQLI',\
    tag:'capec/1000/152/248/66',\
    ver:'OWASP_CRS/4.27.0-dev',\
    severity:'WARNING',\
    setvar:'tx.inbound_anomaly_score_pl4=+%{tx.warning_anomaly_score}',\
    setvar:'tx.sql_injection_score=+%{tx.warning_anomaly_score}'"
```

---

# 11. Rule Generation Output Template

When this document is retrieved, generate output in this structure:

```markdown
## Rule Objective

- Attack type: SQL Injection / SQLi
- Payload location:
- Observed bypass technique:
- Enforcement goal:

## Selected CRS References

- Rule IDs:
- Why these references apply:

## Proposed ModSecurity Rule

```apache
SecRule ...
```

## Transformations Used

- `t:none`:
- `t:urlDecodeUni`:
- `t:utf8toUnicode`:
- `t:replaceComments`:
- `t:removeCommentsChar`:
- `t:removeWhitespace`:
- `t:removeNulls`:

## Why the Rule Matches the Bypass

Explain how target, operator, regex/phrase, and transformations match the observed payload.

## False Positives and Tuning Notes

Explain affected parameters, cookies, headers, paths, and suggested exclusions or path scoping.

## Test Cases

Positive tests:
- payload:
- expected match:

Negative tests:
- benign input:
- expected no match:
```

---

# 12. Final SQLi Rule Generation Checklist

- [ ] Confirm `attack_type` is `SQLI` or normalized to `SQLI` before retrieval.
- [ ] Select targets based on actual payload location: `ARGS`, `ARGS_NAMES`, `REQUEST_COOKIES`, `REQUEST_HEADERS`, `REQUEST_FILENAME`, or `XML:/*`.
- [ ] Prefer `@detectSQLi` for broad unknown SQLi payloads.
- [ ] Prefer targeted `@rx` for known payload families such as `union select`, `sleep()`, JSON SQL syntax, inline comments, or auth bypass.
- [ ] Always start custom ModSecurity rules with `t:none`.
- [ ] Use `t:urlDecodeUni` for encoded payloads.
- [ ] Use `t:utf8toUnicode` and `t:removeNulls` when following libinjection CRS patterns.
- [ ] Use `t:replaceComments` or comment-focused rules when payloads use SQL comments.
- [ ] Use `t:removeWhitespace` for JSON SQL syntax in the style of CRS `942550`.
- [ ] Use CRS anomaly scoring if integrating with CRS.
- [ ] Use standalone `deny,status:403` only for immediate-block custom rules outside anomaly scoring.
- [ ] Include `msg`, `tag:'attack-sqli'`, `severity`, and logging actions.
- [ ] Add path or parameter scope for noisy PL2/PL3/PL4 rules.
- [ ] Add negative tests for benign SQL documentation, search strings, encoded data, and developer fields.
- [ ] For CRS contribution, update regex assembly sources instead of editing assembled regex directly.

---

# 13. Source Links Found in the Original Document

The original document includes these links. They are retained here because they help explain SQLi rule intent, evasion, regex assembly, and DBMS-specific syntax.

- http://websec.ca/kb/sql_injection
- http://websec.wordpress.com/2010/12/04/sqli-filter-evasion-cheat-sheet-mysql/
- http://ferruh.mavituna.com/sql-injection-cheatsheet-oku/
- https://github.com/sqlmapproject/sqlmap
- https://github.com/libinjection/libinjection
- https://coreruleset.org/docs/development/regex_assembly/
- https://raw.githubusercontent.com/PHPIDS/PHPIDS/master/lib/IDS/default_filter.xml
- https://www.exploringbinary.com/php-hangs-on-numeric-value-2-2250738585072011e-308/
- https://dev.mysql.com/doc/refman/5.7/en/sql-syntax-data-definition.html
- https://docs.oracle.com/search/?q=alter&size=60&category=database
- https://www.postgresql.org/search/?u=%2Fdocs&q=alter
- https://learn.microsoft.com/en-us/sql/t-sql/statements/statements?view=sql-server-ver16
- https://www.ibm.com/docs/en/search/alter?scope=SSEPGG_9.5.0
- https://dev.mysql.com/doc/refman/8.0/en/comments.html
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md#scientific-notation
- https://claroty.com/team82/research/js-on-security-off-abusing-json-based-sql-to-bypass-waf
- https://www.exploit-db.com/exploits/44292
- https://hwang.cisdept.cpp.edu/swanew/Text/SQL-Injection.htm


---

# 14. Compact Rule Family Summary for Reranking

This section repeats high-value semantic keywords in dense form so embedding retrieval and cross-encoder reranking can match short payload-driven queries.

```text
SQLI SQL injection ModSecurity CRS REQUEST-942 SecRule @detectSQLi @rx ARGS ARGS_NAMES REQUEST_COOKIES REQUEST_COOKIES_NAMES REQUEST_HEADERS User-Agent Referer REQUEST_FILENAME REQUEST_BASENAME XML t:none t:utf8toUnicode t:urlDecodeUni t:replaceComments t:removeCommentsChar t:removeWhitespace t:removeNulls block capture multiMatch chain anomaly score tx.sql_injection_score tx.inbound_anomaly_score_pl1 tx.inbound_anomaly_score_pl2 tx.inbound_anomaly_score_pl3 tx.inbound_anomaly_score_pl4 union select from information_schema sleep benchmark pg_sleep waitfor delay boolean tautology 1=1 1!=2 SQL operators regexp rlike like collate is null in all authentication bypass quote semicolon split query MySQL inline comment /*! */ /*+ */ JSON-based SQL injection json_extract @> <@ -> ->> MongoDB $where $ne $regex stored procedure create function xp_cmdshell load_file outfile dumpfile group_concat scientific notation hex binary special character anomaly
```
