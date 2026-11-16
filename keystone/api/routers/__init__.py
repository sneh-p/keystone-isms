from . import admin, ai, answers, auth, compliance, dashboard, exposure, integrations, operations, org, policies, risk, people, tprm, trust, work

ROUTERS = [auth.router, admin.router, org.router, compliance.router, risk.router, tprm.router, exposure.router, policies.router, operations.router, dashboard.router, work.router, people.router, trust.router, integrations.router, ai.router, answers.router]
