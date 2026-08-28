---
name: strong-authentication-admin-assess
description: "Read-only exposure assessment for strong authentication / MFA readiness."
parent_skill: strong-authentication-admin
---

# Assess Mode

**When to load:** From `strong-authentication-admin` Step "Mode Menu", option 1.

Every query here is `SELECT` only. Nothing is modified. Safe to run repeatedly.

> **Data notes:** `ACCOUNT_USAGE` views have up to a 90-minute lag and retain 365 days. `INFORMATION_SCHEMA.LOGIN_HISTORY()` has no lag but only covers the last 7 days — use `-6 days` in the window, not `-7`, to avoid a retention-boundary error.

---

## Query 1 — Full User Status Report *(run this first)*

One row per user with a plain-English `status` column.

```sql
WITH recent_pw_logins AS (
    SELECT
        user_name,
        COUNT(*)                AS password_only_logins,
        MAX(event_timestamp)    AS last_pw_only_login
    FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
    WHERE event_timestamp >= DATEADD('day', -90, CURRENT_TIMESTAMP)
      AND is_success = 'YES'
      AND first_authentication_factor = 'PASSWORD'
      AND second_authentication_factor IS NULL
    GROUP BY user_name
)
SELECT
    u.name                                              AS user_name,
    u.login_name,
    u.email,
    u.type                                              AS user_type,
    u.disabled,
    u.has_password,
    u.has_mfa,                                          -- TRUE = enrolled in any MFA method
    u.has_rsa_public_key,                               -- TRUE = key pair auth configured
    u.has_pat,
    u.has_workload_identity,
    u.ext_authn_uid IS NOT NULL                         AS has_federated_auth,
    u.last_success_login,
    COALESCE(pw.password_only_logins, 0)                AS password_only_logins_l90d,
    TO_CHAR(pw.last_pw_only_login, 'YYYY-MM-DD')        AS last_pw_only_login,
    CASE
        WHEN u.disabled = TRUE                          THEN 'Disabled'
        WHEN u.type IN ('SERVICE', 'SERVICE_AGENT')     THEN 'Service user — password not allowed, safe'
        WHEN u.has_password = FALSE                     THEN 'No password — safe'
        WHEN u.has_mfa = TRUE                           THEN 'MFA enrolled — safe'
        WHEN u.has_rsa_public_key = TRUE
             AND COALESCE(pw.password_only_logins,0) = 0 THEN 'Key pair in use — remove password'
        WHEN pw.password_only_logins > 0                THEN 'Password-only — NEEDS ACTION'
        WHEN u.last_success_login < DATEADD('day', -90, CURRENT_TIMESTAMP)
             OR u.last_success_login IS NULL            THEN 'Inactive — review for disable'
        ELSE 'Has password, no recent login — review'
    END                                                 AS status
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS u
LEFT JOIN recent_pw_logins pw ON pw.user_name = u.name
WHERE u.deleted_on IS NULL
ORDER BY password_only_logins_l90d DESC, u.name;
```

**Present a summary count by status** after running this (e.g. "12 users need action, 3 are key-pair-ready, 340 are already safe").

---

## Query 2 — Easiest Wins (key pair already configured, still using password)

These need only a connection-string update, no new key generation.

```sql
SELECT
    u.name,
    u.type,
    u.has_rsa_public_key,
    COUNT(h.event_timestamp)    AS password_logins_l90d,
    MAX(h.event_timestamp)      AS last_password_login
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS u
JOIN SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY h
    ON h.user_name = u.name
   AND h.event_timestamp >= DATEADD('day', -90, CURRENT_TIMESTAMP)
   AND h.is_success = 'YES'
   AND h.first_authentication_factor = 'PASSWORD'
   AND h.second_authentication_factor IS NULL
WHERE u.deleted_on IS NULL
  AND u.disabled = FALSE
  AND u.has_rsa_public_key = TRUE
  AND u.has_password = TRUE
GROUP BY u.name, u.type, u.has_rsa_public_key
ORDER BY password_logins_l90d DESC;
```

---

## Query 3 — Executive Summary by Authentication Method

```sql
SELECT
    CASE
        WHEN second_authentication_factor IS NOT NULL                   THEN 'MFA (password + second factor)'
        WHEN first_authentication_factor = 'PASSWORD'
             AND second_authentication_factor IS NULL                    THEN 'Password-only (NO MFA)'
        WHEN first_authentication_factor = 'RSA_KEYPAIR'                THEN 'Key pair auth'
        WHEN first_authentication_factor = 'SAML2_ASSERTION'            THEN 'SSO / SAML'
        WHEN first_authentication_factor = 'OAUTH_ACCESS_TOKEN'         THEN 'OAuth'
        WHEN first_authentication_factor = 'PROGRAMMATIC_ACCESS_TOKEN'  THEN 'PAT'
        WHEN first_authentication_factor = 'WORKLOAD_IDENTITY'          THEN 'Workload identity federation'
        WHEN first_authentication_factor = 'ID_TOKEN'                   THEN 'Cached SSO ID token'
        WHEN first_authentication_factor = 'WEB_SESSION'                THEN 'Existing web session'
        ELSE COALESCE(first_authentication_factor, 'UNKNOWN')
    END                             AS auth_method,
    COUNT(DISTINCT user_name)       AS distinct_users,
    COUNT(*)                        AS total_logins
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE event_timestamp >= DATEADD('day', -90, CURRENT_TIMESTAMP)
  AND is_success = 'YES'
GROUP BY 1
ORDER BY total_logins DESC;
```

---

## Query 4 — Near Real-Time (Last 6 Days, No Data Lag)

```sql
-- Requires a database in context (any database) or you'll get
-- "Invalid identifier INFORMATION_SCHEMA.LOGIN_HISTORY". Run USE DATABASE first if needed.
SELECT
    user_name,
    first_authentication_factor,
    second_authentication_factor,
    event_timestamp,
    client_ip,
    reported_client_type
FROM TABLE(INFORMATION_SCHEMA.LOGIN_HISTORY(
    DATEADD('day', -6, CURRENT_TIMESTAMP),
    CURRENT_TIMESTAMP
))
WHERE first_authentication_factor = 'PASSWORD'
  AND second_authentication_factor IS NULL
  AND is_success = 'YES'
ORDER BY event_timestamp DESC;
```

---

## After Running These

Summarize findings for the user: total users, how many need action, how many are "easiest wins," and how many are already safe.

**Ask:**
```
Based on this, would you like to move to Fix mode to start remediating,
or stop here for now?
```

If yes → **Load** `../fix/SKILL.md`.
