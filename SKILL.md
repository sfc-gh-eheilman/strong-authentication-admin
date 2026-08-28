---
name: strong-authentication-admin
description: "Assess, fix, notify, enforce, and disable password-only authentication in your own Snowflake account ahead of Snowflake's strong authentication (MFA) deprecation. Use when: checking MFA readiness, finding password-only users, removing passwords from SSO users, converting service accounts to key pair auth, applying an authentication policy to require MFA, or disabling non-compliant users. Triggers: strong authentication, password-only deprecation, MFA readiness, who is not MFA enrolled, password only users, enforce MFA, strong auth admin. NOT for generic authentication policy management unrelated to the MFA deprecation (see manage-authentication-policy for that)."
---

# Strong Authentication Admin

Runs entirely against `SNOWFLAKE.ACCOUNT_USAGE` and `INFORMATION_SCHEMA` in **your own account** — no external dependencies, no data leaves your account.

> *This skill helps you evaluate your account against Snowflake's recommended strong authentication practices and take corrective action. It is not a comprehensive security audit. You are responsible for securing your own Snowflake account and determining your compliance requirements.*

**Requires:** `ACCOUNTADMIN` or `SECURITYADMIN` role.

---

## Safety Model — Read This First

This skill can modify live users in your Snowflake account: removing passwords, converting service account types, applying authentication policies, and disabling users.

**Every mutating action in every mode follows the same pattern:**
1. Run a **preview** query showing exactly which users/objects will be affected
2. Show the user that list as a table
3. Get **explicit confirmation** — never infer approval from an ambiguous reply
4. Execute changes **one row at a time**, reporting success/failure for each, so the user can stop mid-way
5. Print a final summary

**Never** run a bulk multi-user `ALTER` inside a single Snowflake Scripting block. Loop through rows yourself, one SQL statement per user, so every action is visible and interruptible.

---

## Step 0: Break-Glass Access (Mandatory Before Enforce)

Before offering **Enforce** mode, confirm the user has backup access to their own account.

**Ask:**
```
Before we touch anything, let's make sure you can't lock yourself out.
Do you already have a backup MFA method (a second passkey/device) or
one-time passcodes generated for your own admin account?
```

**If no:** Offer to generate one-time passcodes for their own user now:
```sql
-- Generates 5 one-time passcodes. Store these in a password manager or vault.
-- Each is single-use; regenerating invalidates all previous ones.
ALTER USER <their_own_username> ADD MFA METHOD OTP COUNT = 5;
```

Only proceed to Enforce mode once break-glass access is confirmed.

---

## Mode Menu

**Ask the user** (via a real choice, not assumed):
```
What would you like to do?

1. Assess    — Find out who is at risk (read-only, safe to run anytime)
2. Fix       — Remove passwords from SSO users, convert service accounts to key pair auth
3. Notify    — Email/prompt affected human users to enroll in MFA
4. Enforce   — Apply an authentication policy requiring MFA (requires Step 0 first)
5. Disable   — Disable users who still haven't complied after their deadline
```

Route based on selection:
- **1 → Load** `assess/SKILL.md`
- **2 → Load** `fix/SKILL.md`
- **3 → Load** `notify/SKILL.md`
- **4 → Confirm Step 0 is done, then Load** `enforce/SKILL.md`
- **5 → Load** `disable/SKILL.md`

If the user needs recovery help (a user got locked out) or wants to look up an exact auth-factor value, **load** `reference/emergency-and-values.md` directly — this can be loaded from any mode at any time.

**Recommended order for a first run:** Assess → Fix → Notify → (wait for the deadline you set) → Enforce → Disable. Don't skip straight to Enforce or Disable without running Assess first.

## Stopping Points

- After Step 0 (if user says no to break-glass): generate OTPs before continuing to Enforce
- After the mode menu: route only on an explicit numbered/named selection
- Every mutating statement inside every sub-skill has its own confirmation gate — see that file

## Output

Chat tables and per-user progress reporting. This skill does not generate PDF/DOCX files.
