---
okf_version: "0.2"
---
# Start here

* [Secure Coding Policy](/policy.md) - How to read the rules: keywords, severities, precedence and exceptions.
* [Agent Conduct](/agent-conduct.md) - Rules for the coding agent's own behavior. Always load.
* [Verification Gates](/verification.md) - Commands that must pass before a commit or PR, and the security report.
* [Exception Register](/exceptions.md) - The only valid source of approved exceptions.

# Rules by topic

* [Input Validation](/input-validation.md) - Validate every trust-boundary input with strict Pydantic models.
* [Injection Prevention](/injection.md) - SQL, OS command, PowerShell, template, dynamic code and deserialization.
* [Output Encoding and XSS](/output-encoding-xss.md) - Rendering untrusted data in React, Markdown, URLs and redirects.
* [Authentication and Sessions](/authentication.md) - Passwords, session cookies, tokens, brute force, secret comparison.
* [Authorization](/authorization.md) - Deny by default, permission on every route and service, role isolation, mass assignment, negative tests.
* [Secrets Management](/secrets.md) - Keeping credentials out of code, logs, the web bundle and prompts.
* [Cryptography](/cryptography.md) - Randomness, approved algorithms, TLS verification, data at rest.
* [Dependencies and Supply Chain](/dependencies.md) - Adding, pinning and auditing Python and npm packages; CI pipeline integrity.
* [Errors and Logging](/errors-and-logging.md) - Failing closed, safe error responses, the audit log and security events.
* [Outbound Requests (SSRF)](/outbound-requests.md) - Server-side requests to URLs influenced by input (integrations).
* [Files and Paths](/files-and-paths.md) - Path traversal, uploads, spreadsheets (zip and XML) and attachments.
* [HTTP and Configuration](/http-and-config.md) - Headers, CORS, CSRF, limits and secure production defaults.
* [LLM Features](/llm-features.md) - Product features that call Claude (policy assistant, questionnaire drafting).
