---
name: strong-authentication-admin-enforce
description: "Apply an authentication policy requiring MFA. Highest-risk mode — requires break-glass confirmation first."
parent_skill: strong-authentication-admin
---

# Enforce Mode

**When to load:** From `strong-authentication-admin` Step "Mode Menu", option 4 — only after confirming Step 0 (break-glass access) in the router skill.

**⚠️ MANDATORY CHECKPOINT:** Before anything else in this mode, confirm break-glass access was set up. If you routed here without that confirmation, stop and go back to the router's Step 0 first.

An authentication policy is the actual enforcement mechanism — Assess/Fix/Notify alone can only monitor and ask nicely. Once applied, non-compliant users cannot log in until they enroll.

---

## Step 1: Choose a Policy Variant

> **Prerequisite:** Authentication policies are schema-level objects. If the session has no database/schema in context, `CREATE AUTHENTICATION POLICY` will fail with `"This session does not have a current database"`. Ask the user which database/schema to create the policy in (or offer to use their personal `USER$<name>` database), and run `USE DATABASE <db>; USE SCHEMA <schema>;` first if needed.

**Ask the user:**
```
Which policy do you want?

1. Require MFA for password users only — SSO users are exempt
   (most common starting point)
2. Require MFA for password AND SSO users
   (stricter — hardens SSO logins too)
3. Restrict which MFA methods are allowed
   (e.g. passkey/authenticator app only, no Duo)
```

## Step 2: Preview the Policy Definition (does not apply anything yet)

Show the user the exact SQL before running it. Substitute a policy name they choose (or default to `require_mfa_policy`).

**Option 1 — password users only:**
```sql
CREATE AUTHENTICATION POLICY <policy_name>
  MFA_ENROLLMENT = 'REQUIRED'
  CLIENT_TYPES = ('SNOWFLAKE_UI', 'DRIVERS', 'SNOWFLAKE_CLI', 'SNOWSQL')
  MFA_POLICY = ( ENFORCE_MFA_ON_EXTERNAL_AUTHENTICATION = 'NONE' )
  COMMENT = 'Require MFA enrollment for password users';
```

**Option 2 — password and SSO users:**
```sql
CREATE AUTHENTICATION POLICY <policy_name>
  MFA_ENROLLMENT = 'REQUIRED'
  CLIENT_TYPES = ('SNOWFLAKE_UI', 'DRIVERS', 'SNOWFLAKE_CLI', 'SNOWSQL')
  MFA_POLICY = ( ENFORCE_MFA_ON_EXTERNAL_AUTHENTICATION = 'ALL' )
  COMMENT = 'Require MFA for all human users including SSO';
```

**Option 3 — restrict methods:**
```sql
CREATE AUTHENTICATION POLICY <policy_name>
  MFA_ENROLLMENT = 'REQUIRED'
  CLIENT_TYPES = ('SNOWFLAKE_UI', 'DRIVERS')
  MFA_POLICY = ( ALLOWED_METHODS = ('PASSKEY', 'TOTP') )   -- ask which methods they want to allow
  COMMENT = 'Restricted MFA methods';
```

> **Constraints to check before running:**
> - `MFA_ENROLLMENT = 'REQUIRED'` requires `SNOWFLAKE_UI` in `CLIENT_TYPES` — that's the only place users can enroll.
> - Omitting `DRIVERS` from `CLIENT_TYPES` will break automated ingestion/pipelines.

**⚠️ CONFIRM:** Show the exact statement and get explicit approval before running `CREATE AUTHENTICATION POLICY`. This alone doesn't apply the policy yet — it just defines it.

## Step 3: Choose Scope — Pilot First, Recommended

**Strongly recommend piloting on a single test user before account-wide rollout.** Ask:

```
I recommend testing this on one user first before applying it account-wide.
Do you have a test/pilot user, or should we apply this to your own admin
account first (since you have break-glass access)?
```

**Apply to one user:**
```sql
ALTER USER "<pilot_username>" SET AUTHENTICATION POLICY <policy_name>;
```

Ask the user to test logging in as that user and confirm MFA is being requested correctly before proceeding to account-wide rollout.

**⚠️ STOP — do not proceed to account-wide until the pilot is confirmed working.**

## Step 4: Account-Wide Rollout (only after pilot confirmed)

```sql
ALTER ACCOUNT SET AUTHENTICATION POLICY <policy_name>;
```

Or scoped to service users only:
```sql
ALTER ACCOUNT SET AUTHENTICATION POLICY <policy_name> FOR ALL SERVICE USERS;
```

**⚠️ CONFIRM again before this specific statement** — this is account-wide and affects every user immediately.

## Step 5: Verify

```sql
SELECT * FROM TABLE(
  <a_database>.INFORMATION_SCHEMA.POLICY_REFERENCES(
    REF_ENTITY_DOMAIN => 'ACCOUNT', REF_ENTITY_NAME => '<account_name>'
  )
);
```

## Optional: Block Passwords Entirely for Service Accounts

```sql
CREATE AUTHENTICATION POLICY service_no_password_policy
  AUTHENTICATION_METHODS = ('KEYPAIR', 'OAUTH', 'WORKLOAD_IDENTITY', 'PROGRAMMATIC_ACCESS_TOKEN')
  COMMENT = 'Service accounts cannot use passwords';

ALTER ACCOUNT SET AUTHENTICATION POLICY service_no_password_policy FOR ALL SERVICE USERS;
```

Same confirm-before-run rule applies.

---

## Next

**Ask:**
```
Enforce mode complete. Would you like to move to Disable mode to remove
access for anyone who still hasn't complied?
```
