---
name: strong-authentication-admin-fix
description: "Remove passwords from SSO users and convert service accounts to key pair auth, one user at a time with confirmation."
parent_skill: strong-authentication-admin
---

# Fix Mode

**When to load:** From `strong-authentication-admin` Step "Mode Menu", option 2, or after Assess mode.

Two independent fixes in this mode. Run either or both.

---

## Fix 2a: Remove Passwords from SSO/Federated Users

Users who log in via SSO but still have a Snowflake password set can have that password removed safely — they'll keep using SSO with no disruption. This is usually the fastest way to shrink the at-risk list.

### Step 1 — Preview

```sql
SELECT
    name,
    login_name,
    email,
    has_mfa,
    has_rsa_public_key,
    last_success_login
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
WHERE deleted_on IS NULL
  AND disabled = FALSE
  AND has_password = TRUE
  AND ext_authn_uid IS NOT NULL        -- federated auth configured
ORDER BY last_success_login DESC NULLS LAST;
```

**Cross-check** that these users are actually logging in via SSO before touching anything:
```sql
SELECT DISTINCT user_name, first_authentication_factor, MAX(event_timestamp) AS last_sso_login
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE event_timestamp >= DATEADD('day', -90, CURRENT_TIMESTAMP)
  AND is_success = 'YES'
  AND first_authentication_factor IN ('SAML2_ASSERTION', 'ID_TOKEN', 'OAUTH_ACCESS_TOKEN')
GROUP BY user_name, first_authentication_factor
ORDER BY user_name;
```

**Only proceed with users that appear on BOTH lists.** A user on the first list but not the second has never actually used SSO in the last 90 days — removing their password could lock them out. Flag any mismatch to the user and exclude it from the confirmed list.

### Step 2 — Confirm

**Show** the confirmed list (intersection of both queries) as a table. **Ask:**
```
I found N users with a leftover password who are confirmed to be using SSO.
Removing their passwords will not affect their SSO login. Proceed with all N?
(yes / no / let me pick specific users)
```

Do not proceed without an explicit "yes" or an explicit subset selection.

### Step 3 — Execute (one user at a time)

For each confirmed user, run individually and report the result before moving to the next:
```sql
ALTER USER "<username>" UNSET PASSWORD;
```

After each statement, confirm success and move to the next. If one fails, stop and report which user failed and why — do not silently continue.

### Step 4 — Summary

Report: "Removed passwords from X of N users. [List any skipped/failed users and why]."

---

## Fix 2b: Convert Service Accounts to `TYPE = SERVICE`

`TYPE = SERVICE` users **cannot have a password at all** — Snowflake blocks the property. This is the permanent fix for service accounts. `LEGACY_SERVICE` is being deprecated, so `SERVICE` is the recommended destination.

### Step 1 — Preview

```sql
SELECT
    u.name,
    u.type,
    u.has_password,
    u.has_rsa_public_key,
    u.last_success_login,
    COUNT(h.event_timestamp) AS pw_logins_l90d
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS u
LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY h
    ON h.user_name = u.name
   AND h.event_timestamp >= DATEADD('day', -90, CURRENT_TIMESTAMP)
   AND h.is_success = 'YES'
   AND h.first_authentication_factor = 'PASSWORD'
WHERE u.deleted_on IS NULL
  AND u.disabled = FALSE
  AND u.type IN ('LEGACY_SERVICE', 'SERVICE')
  AND u.has_password = TRUE
GROUP BY u.name, u.type, u.has_password, u.has_rsa_public_key, u.last_success_login
ORDER BY pw_logins_l90d DESC;
```

### Step 2 — Explain the sequence, per account

**This cannot be fully automated** — it requires the customer to update their application's connection string between steps 2 and 4. Walk through this **one account at a time**, waiting for the user to confirm each step before advancing:

1. **They generate a key pair** (outside Snowflake, in their shell):
   ```bash
   openssl genrsa 2048 | openssl pkcs8 -topk8 -inform PEM -out rsa_key.p8 -nocrypt
   openssl rsa -in rsa_key.p8 -pubout -out rsa_key.pub
   ```
2. **You register the public key** (they paste the key body, without header/footer lines):
   ```sql
   ALTER USER "<svc_user>" SET RSA_PUBLIC_KEY = '<public_key_body>';
   ```
3. **⚠️ STOP — wait for the user.** They must update the application's connection string to `authenticator=snowflake_jwt` with the private key, and confirm it connects successfully. Do not proceed until they say it's working.
4. **You verify** key pair logins are appearing:
   ```sql
   SELECT event_timestamp, first_authentication_factor, is_success
   FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
   WHERE user_name = '<svc_user>'
     AND event_timestamp >= DATEADD('hour', -24, CURRENT_TIMESTAMP)
   ORDER BY event_timestamp DESC;
   ```
5. **Only once confirmed**, convert the type — this permanently blocks password auth for this user:
   ```sql
   ALTER USER "<svc_user>" SET TYPE = SERVICE;
   ```

> Converting to `TYPE = SERVICE` also blocks `RESET PASSWORD` and `DISABLE_MFA` for that user. Converting back to `PERSON` restores previously stored password properties.

### Summary

After each account is converted, report progress. When all confirmed accounts are done, summarize: "Converted X of N service accounts to TYPE=SERVICE."

---

## Next

**Ask:**
```
Fix mode complete. Would you like to move to Notify mode to reach out to
remaining human users, or stop here?
```
If yes → **Load** `../notify/SKILL.md`.
