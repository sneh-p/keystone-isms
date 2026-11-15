# Keystone ISMS

An information security management system for a single organisation, built around a
common control library mapped to several frameworks.

> Status: early development. See the roadmap below.

## Frameworks

| Framework | What ships in this repo |
|---|---|
| NIST CSF 2.0 | Full text (US government work, public domain) |
| ISO/IEC 27001:2022 | Clause and Annex A identifiers with short titles in our own words. Import official text from your licensed copy. |
| SOC 2 Trust Services Criteria | Criteria identifiers with own-words summaries. Import official text from your licensed copy. |
| CIS Controls v8.1 | Safeguard identifiers with own-words titles. Import official text from your licensed copy. |

Crosswalks between frameworks are original work and a starting point: verify them against the source documents.

## Roadmap

- [x] Phase 0: project structure
- [ ] Phase 1: core platform (database, accounts and roles, audit log, attachments, organisation profile and ISMS scope)
- [ ] Phase 2: framework library and crosswalks
- [ ] Phase 3: asset inventory and risk register (qualitative and FAIR)
- [ ] Phase 4: control implementation, Statement of Applicability, evidence
- [ ] Phase 5: third-party risk management
- [ ] Phase 6: vendor exposure map (Entra ID third-party apps; PowerShell collector + importer)
- [ ] Phase 7: policy management
- [ ] Phase 8: incidents, nonconformities and corrective actions
- [ ] Phase 9: internal audits and management review
- [ ] Phase 10: dashboards and reports
- [ ] Phase 11: documentation and packaging

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[test]"
.venv/bin/python -m pytest tests/ -v
```

Never commit real organisational data. `output/`, `data/`, `*.db` and `.env` are git-ignored.
