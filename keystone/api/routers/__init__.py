from . import admin, ai, answers, asm, auth, collab, compliance, dashboard, exposure, integrations, notifications, operations, org, policies, risk, people, tprm, trust, vendor_portal, work, system, tickets

ROUTERS = [auth.router, admin.router, org.router, compliance.router, risk.router, tprm.router, exposure.router, policies.router, operations.router, dashboard.router, work.router, people.router, trust.router, integrations.router, ai.router, answers.router, notifications.router, vendor_portal.router, collab.router, asm.router, system.router, tickets.router]
