# Strong Authentication Admin

A [Cortex Code](https://docs.snowflake.com/en/user-guide/cortex-code/cortex-code) skill that helps Snowflake account admins get ahead of Snowflake's **strong authentication (MFA) deprecation** — finding, fixing, notifying, enforcing, and (if needed) disabling password-only users, directly from a chat session in your own account.

Runs entirely against `SNOWFLAKE.ACCOUNT_USAGE` and `INFORMATION_SCHEMA`. No external services, no data leaves your account, no dependency on any other Snowflake customer's data.

> This skill helps you evaluate your account against Snowflake's recommended strong authentication practices and take corrective action. It is **not** a comprehensive security audit. You are responsible for securing your own Snowflake account and determining your compliance requirements.

---

## Why this exists

Snowflake is deprecating single-factor password sign-ins. Once that rollout reaches your account, any user or service account still authenticating with a bare username and password will simply stop being able to log in — no grace period at the point of cutover.

This skill answers the questions every admin ends up asking:

- **How big is this problem for me?** (a handful of users, or hundreds?)
- **Which specific users/service accounts are affected?**
- **How do I fix the easy ones** — users with SSO who still have a leftover password, or service accounts that already have a key pair configured but haven't switched over?
- **How do I notify the people who need to act**, and **enforce it** once they've had time to comply?
- **What do I do if someone gets locked out** in the process?

---

## Requirements

- `ACCOUNTADMIN` or `SECURITYADMIN` role in the target Snowflake account
- [Cortex Code](https://docs.snowflake.com/en/user-guide/cortex-code/cortex-code) (CoCo) — desktop or CLI

No Python, no external packages, no notification integration required for the core workflow (one optional mode uses `SYSTEM$SEND_EMAIL`, which needs a notification integration already configured — the skill will tell you if you don't have one).

---

## Installation

Copy this repository into your Cortex Code skills directory:

```bash
git clone https://github.com/sfc-gh-eheilman/strong-authentication-admin.git \
  ~/.snowflake/cortex/skills/strong-authentication-admin
```

Or download and unzip this repo directly into `~/.snowflake/cortex/skills/strong-authentication-admin/`.

Restart Cortex Code (or start a new session) so it picks up the new skill.

---

## Usage

Connect Cortex Code to the Snowflake account you want to assess, then either:

- Type `/strong-authentication-admin`, or
- Just ask naturally — e.g. *"help me check my account's MFA readiness"* or *"who's still using password-only auth?"*

You'll be walked through a mode menu:

| Mode | What it does | Mutates data? |
|------|-------------|:---:|
| **Assess** | Read-only report of every user's authentication status | No |
| **Fix** | Removes leftover passwords from SSO users; converts service accounts to key pair auth | Yes |
| **Notify** | Emails or prompts affected human users to enroll in MFA | Yes (sends email / triggers enrollment) |
| **Enforce** | Applies an authentication policy requiring MFA account-wide or for a pilot user | Yes |
| **Disable** | Disables users who still haven't complied after a deadline you set | Yes |

**Recommended order for a first run:** Assess → Fix → Notify → *(wait for your own deadline)* → Enforce → Disable.

There's also a standing **Emergency** reference (lockout recovery steps + validated Snowflake auth-value tables) that can be loaded from any mode at any time if something goes sideways mid-run.

---

## Safety model

This skill can modify live users in your account, so every mutating mode follows the same pattern:

1. **Preview** — a read-only query shows exactly which users/objects will be affected before anything changes
2. **Confirm** — you get an explicit yes/no (or, for the highest-risk actions, a typed exact-count confirmation) before any change is made
3. **One row at a time** — changes are applied to one user per statement with per-user success/failure reporting, not as a single opaque bulk operation, so you can stop mid-way if something looks wrong
4. **Summary** — a final report of what actually happened

**Enforce mode** additionally requires confirming you have break-glass access (a backup MFA method or generated one-time passcodes) to your own admin account *before* it will apply an account-wide policy — so you can't lock yourself out while locking everyone else in.

**Disable mode** requires typing the exact number of affected users back (e.g. `DISABLE 7 USERS`) rather than a generic "yes," and will never disable a service account — those get redirected to Fix mode instead, since disabling a service account can break production pipelines with no warning.

---

## Repository structure

```
strong-authentication-admin/
├── SKILL.md                          # Entry point: safety model, break-glass step, mode menu
├── assess/SKILL.md                   # Read-only exposure assessment queries
├── fix/SKILL.md                      # SSO password removal + service account conversion
├── notify/SKILL.md                   # Email template + MFA enrollment triggers
├── enforce/SKILL.md                  # Authentication policy creation and rollout
├── disable/SKILL.md                  # Non-compliant user disable flow
└── reference/emergency-and-values.md # Lockout recovery + validated Snowflake auth value tables
```

Every SQL statement in this skill has been validated against a live Snowflake account, including known gotchas (e.g. correct `LOGIN_HISTORY` enum values, the `INFORMATION_SCHEMA.LOGIN_HISTORY()` 7-day retention boundary, and the database/schema context required for authentication policy objects).

---

## What this skill does *not* do

- It does not generate PDF/DOCX reports — output is chat tables only
- It does not call out to any service outside your own Snowflake account
- It does not replace `manage-authentication-policy` for general-purpose authentication policy work unrelated to the password-only deprecation
- It is not a substitute for reading [Snowflake's official guidance](https://docs.snowflake.com/en/user-guide/security-mfa) on the deprecation timeline for your account

---

## License

MIT — see [LICENSE](LICENSE).

## Feedback / Issues

Open an issue on this repository, or reach out to the maintainer directly.
