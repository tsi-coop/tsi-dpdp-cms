-- 20_roles.sql
-- Roles and permissions (v0.6). Permissions are "resource:level" strings (level read < write < manage;
-- "*" = everything, "*:read" = read everything). See util/AccessMap.java for what each function needs.
--
-- Built-in (system) roles have fiduciary_id NULL. The application reads this table (cached for 60 s)
-- and falls back to the same defaults compiled into util/RolePermissions.java if a row is missing or
-- the table cannot be read. ADMIN is always "*" in the application regardless of this table, so
-- editing it cannot lock the platform administrator out.
-- Safe to re-run: existing rows are left as they are.

CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(20) NOT NULL,
    fiduciary_id UUID REFERENCES fiduciaries(id),   -- NULL = built-in role available to every fiduciary
    description TEXT,
    permissions TEXT[] NOT NULL DEFAULT '{}',
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- One role name per scope (NULL fiduciary counts as one scope)
CREATE UNIQUE INDEX IF NOT EXISTS idx_roles_name_scope
    ON roles (upper(name), COALESCE(fiduciary_id, '00000000-0000-0000-0000-000000000000'::uuid));

INSERT INTO roles (name, description, permissions, is_system) VALUES
 ('ADMIN',    'Platform administrator', ARRAY['*'], TRUE),
 ('DPO',      'Data Protection Officer for one fiduciary',
              ARRAY['users:manage','fiduciaries:read','apps:read','policies:write','ropa:write','consents:write',
                    'purges:manage','grievances:manage','breaches:write','settings:write','webhooks:manage',
                    'audit:read','certificates:write','dashboard:read','jobs:write','rights:manage','purposes:manage'], TRUE),
 ('OPERATOR', 'Delegated closure work for one fiduciary',
              ARRAY['users:read','fiduciaries:read','apps:read','policies:read','ropa:read','breaches:read',
                    'purges:write','grievances:write','jobs:write','settings:read','certificates:read',
                    'audit:read','dashboard:read','rights:write','purposes:read'], TRUE),
 ('AUDITOR',  'Read-only access, including audit logs', ARRAY['*:read'], TRUE)
ON CONFLICT DO NOTHING;
