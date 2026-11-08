# Windows VM Testing Procedure — Privileged Defensive Actions

> **Status: NOT EXECUTED.**
> The privileged tests in this document have **not** been run against a real
> Windows host. Every automated test in `tests/` uses injected runners and fake
> elevation adapters. This procedure exists so a human can validate the helper
> safely, later, on a disposable VM and record real evidence.
>
> **Do not run these tests on your daily-use machine.** Use a disposable
> Windows virtual machine with a snapshot that can be restored.

---

## 1. What is being validated

The defensive-action subsystem has two halves:

| Half | Runs as | Touches the system | Tested so far |
| --- | --- | --- | --- |
| Flask app, policy, approvals, audit, rollback | Normal user | User-owned files only | Automated unit/integration tests |
| One-shot elevated helper (`defense/windows/elevated.py`) | Administrator via UAC | Windows Firewall | **Not tested on real Windows** |

The elevated helper is **disabled by default** and must stay disabled unless a
genuinely administrator-protected installation is verified. A repository
checkout is explicitly **not** trusted.

The helper only accepts a fixed allowlist of actions:

- `create_firewall_block_rule`
- `remove_cyberguard_firewall_rule`

Everything else is rejected before any Windows command runs.

---

## 2. Safety rules for the tester

1. Use a **disposable VM**, never the host or a work laptop.
2. Take a snapshot before installing anything.
3. Do not test on a domain-joined machine that you do not own.
4. Do not enable `CYBERGUARD_DEFENSE_ELEVATION` on a production workstation.
5. Do not run the Flask app as administrator. Only the one-shot helper should
   ever be elevated.
6. Keep Windows Defender, antivirus and the Windows Firewall **enabled**.
7. Restore the snapshot after testing, whether tests pass or fail.
8. Record commands, output and screenshots. Do not fabricate results.

---

## 3. Required VM configuration

| Item | Value |
| --- | --- |
| Hypervisor | Hyper-V, VMware Workstation/Player, or VirtualBox |
| Guest OS | Windows 10/11 x64 (matching the target deployment) |
| RAM | 4 GB minimum, 8 GB recommended |
| Disk | 40 GB dynamic disk |
| Network | NAT or host-only; no bridged network needed |
| Account | Local administrator account available for UAC tests |
| Second account | Standard (non-admin) account for denial tests |
| Snapshot | Clean snapshot named `pre-cyberguard-tests` |

Optional but useful:

- A second snapshot after Python and dependencies are installed.
- A shared folder or clipboard for copying evidence out.

---

## 4. Prepare the VM

1. Boot the clean snapshot.
2. Install Python 3.14 x64 (or the version recorded in `README.md`).
3. Copy or clone the repository into a **non-administrator-protected** path,
   for example `C:\Users\tester\CyberSecurity-AI`.
4. Create and activate a virtual environment:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt -r rag\requirements.txt -r requirements-dev.txt
   ```

5. Confirm the app starts **without elevation**:

   ```powershell
   $env:CYBERGUARD_DEFENSE_ELEVATION = "0"
   python app.py
   ```

   Expected: the app binds to `127.0.0.1`, the dashboard loads, and
   `GET /api/defense/status` reports `elevation.enabled = false`.

6. Run the automated suite to confirm the baseline in the VM:

   ```powershell
   python -m pytest -q
   ```

   Expected: all tests pass; UAC and firewall commands are still mocked.

7. Shut down and take a snapshot named `post-install`.

---

## 5. Test cases

Each test lists setup, action, expected result and evidence to collect.
Use the snapshot `post-install` as the starting point.

### T1 — Elevation stays disabled by default

**Setup:** `CYBERGUARD_DEFENSE_ELEVATION` is unset or `0`.
**Action:** Preview and approve a firewall block rule, then execute it.
**Expected:**

- Preview and approval succeed (they are local bookkeeping).
- Execution returns `elevation_disabled`.
- No firewall rule is created.
- No UAC prompt appears.

**Evidence:** API response, `Get-NetFirewallRule -DisplayName 'CyberGuard-*'`
(before/after), audit event.

---

### T2 — Enabled but untrusted helper is refused

**Setup:** `CYBERGUARD_DEFENSE_ELEVATION=1`, but
`CYBERGUARD_DEFENSE_HELPER_ROOT` points at the repository checkout.
**Action:** Execute an approved action.
**Expected:**

- Execution returns `helper_untrusted` (or an equivalent fail-closed error).
- No UAC prompt appears.
- No firewall rule is created.

**Evidence:** API response, audit event, helper-root path.

---

### T3 — Trusted helper ACL verification

**Setup (on the disposable VM only):**

1. Create an administrator-only directory, for example
   `C:\ProgramData\CyberGuardHelper`.
2. Copy the interpreter and the helper files into it.
3. Remove inherited permissions and grant access only to
   `Administrators` and `SYSTEM`.
4. Set `CYBERGUARD_DEFENSE_HELPER_ROOT` to that directory.

**Action:** Start the app as a normal user and call
`GET /api/defense/status`.

**Expected:**

- Status reports the helper as configured **and trusted** only when the root,
  the absolute `sys.executable` and `defense\windows\elevated.py` all pass the
  admin-only ACL check.
- If the non-elevated app cannot read the ACL, status must report
  `trusted = false` and keep elevation unusable. This is a safe failure and
  must be documented, not worked around.

**Evidence:** ACL output (`icacls`), status JSON, screenshots.

> Practical note: a non-elevated process may lack `READ_CONTROL` on an
> admin-only directory. If verification fails for that reason, the correct
> result is **elevation stays disabled**. Do not loosen the ACL just to make
> the check pass.

---

### T4 — UAC approval

**Setup:** T3 completed; elevation enabled.
**Action:** Preview → approve → execute a block rule for a harmless test
address such as `203.0.113.7` on TCP port 443, profile `private`.

**Expected:**

- One UAC prompt appears.
- After approval, the helper runs once and exits.
- The backend verifies the exact rule (name, direction, action, protocol,
  ports, profile, remote address).
- Result status is `success` with `verified = true`.
- The audit log records the action without the approval token.

**Evidence:** UAC screenshot, execution result JSON, `Get-NetFirewallRule`
output, audit event.

---

### T5 — UAC cancellation

**Action:** Start the same flow, then cancel the UAC prompt.
**Expected:**

- The action is reported as cancelled / not executed.
- No firewall rule exists.
- The approval is single-use and cannot be replayed.

**Evidence:** API response, rule query, audit event.

---

### T6 — UAC denial (standard user)

**Setup:** Run the app as a standard user while the helper requires
administrator credentials.
**Action:** Enter a standard-user credential or cancel the credential prompt.
**Expected:**

- Execution fails closed (`uac_cancelled`, `uac_denied` or equivalent).
- No rule is created.
- No automatic retry occurs.

**Evidence:** API response, audit event.

---

### T7 — Firewall rule creation and removal

**Setup:** Elevation enabled and trusted.
**Action:**

1. Create a CyberGuard block rule.
2. Confirm it with `Get-NetFirewallRule` and
   `Get-NetFirewallAddressFilter`.
3. Prepare a rollback (inverse remove action).
4. Approve and execute the rollback.

**Expected:**

- Creation verifies the exact properties.
- Removal only succeeds for a `CyberGuard-` prefixed rule recorded in the
  ownership registry.
- Removal verifies the rule is gone.
- Audit records both executions.

**Evidence:** Rule output before/after, two execution results, audit events.

---

### T8 — Ownership validation

**Action:** Attempt to remove a rule that is not registered as CyberGuard-owned,
or a rule whose name does not start with `CyberGuard-`.

**Expected:** Rejected by policy before any command runs. No state changes.

**Evidence:** API error and audit event.

---

### T9 — Firewall output parsing (localised Windows)

**Setup:** A Windows installation with a non-English display language, if
available.
**Action:** Request `get_firewall_status`.

**Expected:**

- If the output cannot be parsed, `parsed = false`, profiles are empty and the
  raw text is returned.
- The dashboard shows the raw text and does not guess ON/OFF.
- No state changes.

**Evidence:** Raw output, API response, screenshot.

---

### T10 — Timeout and partial execution

**Setup:** Use a test-only injection or a deliberately slow wrapper to force a
timeout. Do **not** modify the real helper for production.
**Action:** Execute an approved action that exceeds the timeout.

**Expected:**

- Result is `execution_unknown`, never `success`.
- The action is not retried automatically.
- The audit log records the unknown outcome.
- The tester reconciles the real firewall state manually.

**Evidence:** Result JSON, audit event, manual firewall query.

---

### T11 — Replay protection

**Action:** Capture an approval token (in a test harness only) and try to use
it twice, or re-use an old request file.

**Expected:**

- The second use is rejected.
- A persistent `consumed/<nonce>.used` marker exists for the first use.
- No second firewall change occurs.

**Evidence:** API responses, `consumed` directory listing, audit events.

---

### T12 — Multi-process concurrency

**Action:** Start two app processes or send two execute requests concurrently
for the same action id.

**Expected:**

- At most one execution succeeds.
- The other fails closed (already consumed / unknown action).
- No duplicate rule is created.

**Evidence:** Both responses, rule count, audit events.

---

### T13 — Symlink, junction and reparse-point handling

**Setup:** Replace a request/result path component with a junction or symlink
in a disposable copy of the data directory.
**Action:** Preview/execute.

**Expected:**

- The helper refuses reparse points and hardlinks.
- No file is written outside the expected directory.
- The failure is audited.

**Evidence:** `dir /AL` or `fsutil reparsepoint query`, API response.

---

### T14 — Secret-key protection

**Setup:** Inspect the helper secret/key file ACL.
**Action:** Try to read the key as a standard user; then run with a key that is
not exactly 32 bytes.

**Expected:**

- A standard user cannot read the key.
- A malformed existing key is rejected and **not** silently regenerated.
- A missing key is generated once with a restricted ACL.

**Evidence:** `icacls` output, error responses, audit event.

---

## 6. Cleanup and rollback

After every test session:

1. Stop the Flask app.
2. Remove any `CyberGuard-` test rules that were created:

   ```powershell
   Get-NetFirewallRule -DisplayName 'CyberGuard-*' |
       Remove-NetFirewallRule
   ```

   (Only do this in the disposable VM. This command is intentionally **not**
   part of CyberGuard.)
3. Confirm no test rules remain.
4. Delete the test helper root and any temporary data directory.
5. Restore the VM snapshot `pre-cyberguard-tests` (or `post-install`).
6. Verify the host firewall was never touched.

---

## 7. Evidence checklist

Collect and store outside the repository:

- [ ] VM configuration and Windows build.
- [ ] Snapshot names and timestamps.
- [ ] `icacls` output for the helper root, interpreter, helper file and key.
- [ ] `GET /api/defense/status` JSON before and after each scenario.
- [ ] Preview, approval and execution responses (tokens redacted).
- [ ] `Get-NetFirewallRule` output before/after.
- [ ] Audit-log excerpts.
- [ ] Screenshots of UAC approve, cancel and deny.
- [ ] Any timeout/unknown result and the manual reconciliation.
- [ ] Confirmation that the host machine was not modified.

Do not commit captured evidence that contains usernames, hostnames, SIDs,
tokens or other machine-specific data.

---

## 8. Pass criteria

The privileged helper may be considered **safe to enable on a real machine**
only when all of the following are true:

- T1–T14 pass on a clean VM.
- The helper root, interpreter and helper script are independently verified as
  administrator-only.
- The secret key is exactly 32 bytes and unreadable by standard users.
- Request/result files are protected and reparse-point-safe.
- Timeout and concurrency cases never report `success`.
- No firewall change occurs without a separate human approval.
- No privilege escalation path is found from the non-elevated app.

Until then, keep `CYBERGUARD_DEFENSE_ELEVATION` unset and treat the helper as
**not production-approved**.
