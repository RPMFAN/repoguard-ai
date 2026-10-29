# RepoGuard AI — automated scan report
- **Target:** `OWASP/NodeGoat @ c5cb68a`
- **Scanned at (UTC):** `2026-10-29T17:19:54.651Z`
- **Files scanned:** 49 · **Leads:** 9 (High 7, Medium 2, Low 0)

> Automated pattern matches. Each item is a lead to be confirmed by manual review; false positives are expected.

| Rule | Severity | Location | Category | Matched code | Suggested fix |
| :--- | :---: | :--- | :--- | :--- | :--- |
| RG-SEC-001 | HIGH | `app/routes/contributions.js:32` | Code injection | `const preTax = eval(req.body.preTax);` | Remove eval/new Function; parse input explicitly (e.g. JSON.parse, parseInt) and validate it. |
| RG-SEC-001 | HIGH | `app/routes/contributions.js:33` | Code injection | `const afterTax = eval(req.body.afterTax);` | Remove eval/new Function; parse input explicitly (e.g. JSON.parse, parseInt) and validate it. |
| RG-SEC-001 | HIGH | `app/routes/contributions.js:34` | Code injection | `const roth = eval(req.body.roth);` | Remove eval/new Function; parse input explicitly (e.g. JSON.parse, parseInt) and validate it. |
| RG-SEC-003 | HIGH | `config/env/all.js:8` | Hard-coded secret | `cookieSecret: "session_cookie_secret_key_here",` | Move secrets to environment variables or a secret manager and rotate the exposed value. |
| RG-SEC-003 | HIGH | `config/env/development.js:6` | Hard-coded secret | `zapApiKey: "v9dn0balpqas1pcc281tn5ood1",` | Move secrets to environment variables or a secret manager and rotate the exposed value. |
| RG-SEC-003 | HIGH | `config/env/test.js:6` | Hard-coded secret | `zapApiKey: "v9dn0balpqas1pcc281tn5ood1",` | Move secrets to environment variables or a secret manager and rotate the exposed value. |
| RG-SEC-003 | HIGH | `test/security/profile-test.js:37` | Hard-coded secret | `var sutUserPassword = "User1_123";` | Move secrets to environment variables or a secret manager and rotate the exposed value. |
| RG-SEC-005 | MEDIUM | `app/data/allocations-dao.js:73` | Database injection | `return {$where: 'this.userId == ${parsedUserId} && this.stocks > ${parsedThreshold}'};` | Use parameterized queries / query builders and never pass user input into $where. |
| RG-SEC-005 | MEDIUM | `app/data/allocations-dao.js:78` | Database injection | `$where: 'this.userId == ${parsedUserId} && this.stocks > '${threshold}''` | Use parameterized queries / query builders and never pass user input into $where. |
