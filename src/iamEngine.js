/**
 * SentinelIAM Policy Engine:
 * - RBAC role matrix + inheritance
 * - Separation of Duties (SoD) toxic-permission detector
 * - ABAC contextual evaluator (MFA, environment, IPv4 CIDR allowlist)
 * - Draft-vs-Active Blast-Radius Diff calculator
 */

export const RESOURCES = ['Billing', 'Ledger', 'ProdInfra', 'HRRecords', 'AuditLogs', 'APIKeys'];
export const ACTIONS = ['read', 'create', 'approve', 'export', 'admin'];

export const TOXIC_SOD_RULES = [
  {
    id: 'SOD-01',
    severity: 'CRITICAL',
    title: 'Ledger Maker-Checker Violation',
    requiresBoth: ['Ledger:create', 'Ledger:approve'],
    regulation: 'SOX 404',
  },
  {
    id: 'SOD-02',
    severity: 'CRITICAL',
    title: 'Billing Disbursement Self-Approval',
    requiresBoth: ['Billing:create', 'Billing:approve'],
    regulation: 'SOX 404',
  },
  {
    id: 'SOD-03',
    severity: 'HIGH',
    title: 'Audit Trail Tamper Risk',
    requiresBoth: ['ProdInfra:admin', 'AuditLogs:admin'],
    regulation: 'SOC2 CC6.1',
  },
  {
    id: 'SOD-04',
    severity: 'HIGH',
    title: 'Unrestricted PII + Credential Control',
    requiresBoth: ['HRRecords:export', 'APIKeys:admin'],
    regulation: 'ISO 27001 A.9',
  },
];

export function createInitialPolicy() {
  return {
    roles: {
      FinOps_Analyst: {
        description: 'Prepares vendor invoices and ledger entries',
        permissions: ['Billing:read', 'Billing:create', 'Ledger:read', 'Ledger:create'],
        requireMfa: true,
        allowedCidrs: ['10.0.0.0/8', '192.168.1.0/24'],
      },
      Treasury_Approver: {
        description: 'Approves disbursements and reconciles general ledger',
        permissions: ['Billing:read', 'Billing:approve', 'Ledger:read', 'Ledger:approve', 'AuditLogs:read'],
        requireMfa: true,
        allowedCidrs: ['10.0.0.0/8'],
      },
      Platform_SRE: {
        description: 'Manages production infrastructure and API keys',
        permissions: ['ProdInfra:read', 'ProdInfra:create', 'ProdInfra:admin', 'APIKeys:read', 'APIKeys:create'],
        requireMfa: true,
        allowedCidrs: ['10.0.0.0/8', '172.16.0.0/12'],
      },
      SecOps_Auditor: {
        description: 'Read-only security and compliance auditor',
        permissions: ['AuditLogs:read', 'AuditLogs:export', 'ProdInfra:read', 'Billing:read', 'Ledger:read'],
        requireMfa: false,
        allowedCidrs: ['0.0.0.0/0'],
      },
    },
    users: [
      { id: 'u-elena', name: 'Elena Rostova', roles: ['FinOps_Analyst'] },
      { id: 'u-marcus', name: 'Marcus Vance', roles: ['Treasury_Approver'] },
      { id: 'u-samil', name: 'Samil Castillo', roles: ['Platform_SRE', 'SecOps_Auditor'] },
    ],
  };
}

function ipToInt(ip) {
  const parts = String(ip).trim().split('.');
  if (parts.length !== 4) return null;
  let val = 0;
  for (let i = 0; i < 4; i += 1) {
    const n = Number(parts[i]);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    val = ((val << 8) | n) >>> 0;
  }
  return val;
}

export function isIpInCidr(ip, cidr) {
  const [net, prefixStr] = String(cidr).split('/');
  const ipInt = ipToInt(ip);
  const netInt = ipToInt(net);
  const prefix = Number(prefixStr);
  if (ipInt === null || netInt === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return false;
  }
  if (prefix === 0) return true;
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}

export function detectSodConflicts(policy) {
  const findings = [];

  Object.entries(policy.roles).forEach(([roleName, roleDef]) => {
    const permSet = new Set(roleDef.permissions || []);
    TOXIC_SOD_RULES.forEach((rule) => {
      if (rule.requiresBoth.every((p) => permSet.has(p))) {
        findings.push({
          scope: 'ROLE',
          target: roleName,
          ruleId: rule.id,
          severity: rule.severity,
          title: rule.title,
          regulation: rule.regulation,
          permissions: rule.requiresBoth,
        });
      }
    });
  });

  (policy.users || []).forEach((user) => {
    const unionPerms = new Set();
    (user.roles || []).forEach((rName) => {
      (policy.roles[rName]?.permissions || []).forEach((p) => unionPerms.add(p));
    });
    TOXIC_SOD_RULES.forEach((rule) => {
      if (rule.requiresBoth.every((p) => unionPerms.has(p))) {
        findings.push({
          scope: 'USER',
          target: user.name,
          ruleId: rule.id,
          severity: rule.severity,
          title: rule.title,
          regulation: rule.regulation,
          permissions: rule.requiresBoth,
        });
      }
    });
  });

  return findings;
}

export function evaluateAccess(policy, { userId, resource, action, mfaVerified = false, sourceIp = '10.1.2.3', environment = 'prod' }) {
  const perm = `${resource}:${action}`;
  const user = (policy.users || []).find((u) => u.id === userId);
  if (!user) {
    return { allowed: false, reason: `Unknown user '${userId}'.`, matchedRoles: [] };
  }

  const grantingRoles = (user.roles || []).filter((rName) => {
    const role = policy.roles[rName];
    return role && (role.permissions || []).includes(perm);
  });

  if (grantingRoles.length === 0) {
    return { allowed: false, reason: `No assigned role grants '${perm}'.`, matchedRoles: [] };
  }

  // ABAC guardrail: at least one granting role must pass MFA & CIDR conditions
  const reasons = [];
  for (let i = 0; i < grantingRoles.length; i += 1) {
    const rName = grantingRoles[i];
    const role = policy.roles[rName];
    const needsMfa = role.requireMfa || environment === 'prod';
    if (needsMfa && !mfaVerified) {
      reasons.push(`${rName}: MFA required`);
      continue;
    }
    const cidrs = role.allowedCidrs || ['0.0.0.0/0'];
    const ipOk = cidrs.some((c) => isIpInCidr(sourceIp, c));
    if (!ipOk) {
      reasons.push(`${rName}: IP ${sourceIp} outside allowlist`);
      continue;
    }
    return {
      allowed: true,
      reason: `Granted via role '${rName}' (MFA & CIDR verified).`,
      matchedRoles: grantingRoles,
    };
  }

  return {
    allowed: false,
    reason: `Denied by ABAC guardrails (${reasons.join('; ')}).`,
    matchedRoles: grantingRoles,
  };
}

export function diffPolicies(activePolicy, draftPolicy) {
  const changes = [];
  const allRoles = new Set([...Object.keys(activePolicy.roles), ...Object.keys(draftPolicy.roles)]);

  allRoles.forEach((roleName) => {
    const oldSet = new Set(activePolicy.roles[roleName]?.permissions || []);
    const newSet = new Set(draftPolicy.roles[roleName]?.permissions || []);
    newSet.forEach((p) => {
      if (!oldSet.has(p)) changes.push({ type: 'ADDED', role: roleName, permission: p });
    });
    oldSet.forEach((p) => {
      if (!newSet.has(p)) changes.push({ type: 'REMOVED', role: roleName, permission: p });
    });
  });

  return changes;
}
