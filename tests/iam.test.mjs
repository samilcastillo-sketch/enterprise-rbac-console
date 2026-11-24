import test from 'node:test';
import assert from 'node:assert/strict';

import {
  createInitialPolicy,
  detectSodConflicts,
  diffPolicies,
  evaluateAccess,
  isIpInCidr,
} from '../src/iamEngine.js';

test('initial baseline policy has zero SoD conflicts', () => {
  const policy = createInitialPolicy();
  const conflicts = detectSodConflicts(policy);
  assert.equal(conflicts.length, 0);
});

test('detects toxic Separation of Duties conflicts in roles and users', () => {
  const policy = createInitialPolicy();
  policy.roles.FinOps_Analyst.permissions.push('Ledger:approve');
  const conflicts = detectSodConflicts(policy);
  assert.ok(conflicts.some((c) => c.ruleId === 'SOD-01' && c.scope === 'ROLE'));
  assert.ok(conflicts.some((c) => c.ruleId === 'SOD-01' && c.scope === 'USER'));
});

test('evaluates RBAC + ABAC (MFA & CIDR allowlist) accurately', () => {
  const policy = createInitialPolicy();
  const allowed = evaluateAccess(policy, {
    userId: 'u-elena',
    resource: 'Ledger',
    action: 'create',
    mfaVerified: true,
    sourceIp: '10.42.0.15',
    environment: 'prod',
  });
  assert.equal(allowed.allowed, true);

  const deniedNoMfa = evaluateAccess(policy, {
    userId: 'u-elena',
    resource: 'Ledger',
    action: 'create',
    mfaVerified: false,
    sourceIp: '10.42.0.15',
    environment: 'prod',
  });
  assert.equal(deniedNoMfa.allowed, false);

  const deniedIp = evaluateAccess(policy, {
    userId: 'u-elena',
    resource: 'Ledger',
    action: 'create',
    mfaVerified: true,
    sourceIp: '8.8.8.8',
    environment: 'prod',
  });
  assert.equal(deniedIp.allowed, false);
  assert.equal(isIpInCidr('192.168.1.55', '192.168.1.0/24'), true);
});

test('calculates draft vs active blast-radius policy diff', () => {
  const active = createInitialPolicy();
  const draft = structuredClone(active);
  draft.roles.SecOps_Auditor.permissions.push('APIKeys:read');
  draft.roles.SecOps_Auditor.permissions = draft.roles.SecOps_Auditor.permissions.filter((p) => p !== 'Billing:read');

  const diff = diffPolicies(active, draft);
  assert.deepEqual(diff, [
    { type: 'ADDED', role: 'SecOps_Auditor', permission: 'APIKeys:read' },
    { type: 'REMOVED', role: 'SecOps_Auditor', permission: 'Billing:read' },
  ]);
});
