from . import admin, auth, compliance, dashboard, exposure, operations, org, policies, risk, tprm

ROUTERS = [auth.router, admin.router, org.router, compliance.router, risk.router, tprm.router, exposure.router, policies.router, operations.router, dashboard.router]
