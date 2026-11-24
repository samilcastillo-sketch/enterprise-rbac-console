import {
  ACTIONS,
  RESOURCES,
  createInitialPolicy,
  detectSodConflicts,
  diffPolicies,
  evaluateAccess,
} from './iamEngine.js';

let activePolicy = createInitialPolicy();
let draftPolicy = structuredClone(activePolicy);
let selectedRole = Object.keys(draftPolicy.roles)[0];

const roleSelect = document.getElementById('roleSelect');
const mfaToggle = document.getElementById('mfaToggle');
const matrixTable = document.getElementById('matrixTable');
const sodCount = document.getElementById('sodCount');
const sodList = document.getElementById('sodList');
const diffCount = document.getElementById('diffCount');
const diffList = document.getElementById('diffList');
const publishBtn = document.getElementById('publishBtn');

const simUser = document.getElementById('simUser');
const simResource = document.getElementById('simResource');
const simAction = document.getElementById('simAction');
const evalResult = document.getElementById('evalResult');

function initSelects() {
  roleSelect.innerHTML = Object.keys(draftPolicy.roles).map((r) => `<option value="${r}">${r}</option>`).join('');
  roleSelect.value = selectedRole;
  simUser.innerHTML = draftPolicy.users.map((u) => `<option value="${u.id}">${u.name} (${u.roles.join(', ')})</option>`).join('');
  simResource.innerHTML = RESOURCES.map((r) => `<option value="${r}">${r}</option>`).join('');
  simAction.innerHTML = ACTIONS.map((a) => `<option value="${a}">${a}</option>`).join('');
}

function renderMatrix() {
  const role = draftPolicy.roles[selectedRole];
  mfaToggle.checked = Boolean(role.requireMfa);
  const permSet = new Set(role.permissions);

  const head = `<thead><tr><th>Resource</th>${ACTIONS.map((a) => `<th>${a}</th>`).join('')}</tr></thead>`;
  const rows = RESOURCES.map((res) => {
    const cells = ACTIONS.map((act) => {
      const key = `${res}:${act}`;
      const checked = permSet.has(key) ? 'checked' : '';
      return `<td><input type="checkbox" data-perm="${key}" ${checked} aria-label="${selectedRole} ${key}" /></td>`;
    }).join('');
    return `<tr><td>${res}</td>${cells}</tr>`;
  }).join('');

  matrixTable.innerHTML = `${head}<tbody>${rows}</tbody>`;
  matrixTable.querySelectorAll('input[type="checkbox"]').forEach((cb) => {
    cb.addEventListener('change', () => {
      const perm = cb.getAttribute('data-perm');
      if (cb.checked && !role.permissions.includes(perm)) role.permissions.push(perm);
      if (!cb.checked) role.permissions = role.permissions.filter((p) => p !== perm);
      renderGovernance();
    });
  });
}

function renderGovernance() {
  const conflicts = detectSodConflicts(draftPolicy);
  sodCount.textContent = String(conflicts.length);
  sodList.innerHTML = conflicts.length
    ? conflicts.map((c) => `<div class="alert-card"><strong>[${c.severity}] ${c.title}</strong><div>${c.scope}: ${c.target} (${c.regulation})</div></div>`).join('')
    : '<div style="color:var(--ok);font-size:0.8rem;">0 SoD compliance conflicts detected.</div>';

  const diffs = diffPolicies(activePolicy, draftPolicy);
  diffCount.textContent = String(diffs.length);
  publishBtn.disabled = diffs.length === 0;
  diffList.innerHTML = diffs.length
    ? diffs.map((d) => `<div class="${d.type === 'ADDED' ? 'diff-add' : 'diff-rem'}"><strong>${d.type}</strong> ${d.role} → ${d.permission}</div>`).join('')
    : '<div style="color:var(--muted);font-size:0.8rem;">No pending draft changes.</div>';
}

roleSelect.addEventListener('change', () => {
  selectedRole = roleSelect.value;
  renderMatrix();
});

mfaToggle.addEventListener('change', () => {
  draftPolicy.roles[selectedRole].requireMfa = mfaToggle.checked;
});

publishBtn.addEventListener('click', () => {
  activePolicy = structuredClone(draftPolicy);
  renderGovernance();
});

document.getElementById('resetBtn').addEventListener('click', () => {
  draftPolicy = structuredClone(activePolicy);
  renderMatrix();
  renderGovernance();
});

document.getElementById('evalBtn').addEventListener('click', () => {
  const decision = evaluateAccess(draftPolicy, {
    userId: simUser.value,
    resource: simResource.value,
    action: simAction.value,
    sourceIp: document.getElementById('simIp').value,
    environment: document.getElementById('simEnv').value,
    mfaVerified: document.getElementById('simMfa').checked,
  });
  evalResult.className = `eval-box ${decision.allowed ? 'allow' : 'deny'}`;
  evalResult.innerHTML = `<strong>${decision.allowed ? 'ALLOW' : 'DENY'}</strong>: ${decision.reason}`;
});

document.getElementById('exportBtn').addEventListener('click', () => {
  const blob = new Blob([JSON.stringify(draftPolicy, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'sentinel-iam-policy.json';
  a.click();
  URL.revokeObjectURL(url);
});

initSelects();
renderMatrix();
renderGovernance();
