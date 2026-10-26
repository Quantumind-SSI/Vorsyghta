# Role-Based Access Mapping

## Roles
- viewer
- analyst
- pilot_sponsor
- admin

## Persistence
Roles are stored in `vorsyghta.db.models.auth.UserRecord.role` and persisted to PostgreSQL.
Onboarding profile step calls `POST /api/auth/update-role` which updates `UserRecord.role` and commits transaction.

## Frontend Enforcement
- `requireSession` fetches fresh user via `fetchCurrentUser` on every request.
- Dashboard `frontend/src/app/app/page.tsx` renders role-specific sections:
  - viewer: Health, Stats, read-only.
  - analyst: Health, Stats, Activity, Analyst Workspace.
  - pilot_sponsor: Health, Stats, Activity, Sponsor summary.
  - admin: All above + Administration panel.

## Backend Enforcement
- RBAC enum defined in `vorsyghta/security/rbac.py` Role.
- `ROLE_HIERARCHY` defines ordering.
- JWT token payload includes role, refreshed on login.
- `update-role` endpoint validates role enum and updates DB.
- Future hardening: add `RequireRole` dependency to sensitive endpoints.

## Restart Persistence
Database is PostgreSQL in Docker volume `postgres_data`. Roles survive container restarts.
