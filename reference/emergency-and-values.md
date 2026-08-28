---
name: strong-authentication-admin-reference
description: "Lockout recovery procedures and validated authentication factor value tables."
parent_skill: strong-authentication-admin
---

# Emergency Recovery & Reference Values

**When to load:** From any mode, at any time — when a user is locked out, or when you need to double-check an exact enum value rather than guessing.

---

## Emergency: A User Got Locked Out

### Human user can't log in

**1. Check why:**
```sql
SELECT event_timestamp, user_name, is_success, error_code, error_message,
       first_authentication_factor, second_authentication_factor, reported_client_type
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE user_name = '<username>'
ORDER BY event_timestamp DESC
LIMIT 10;
```

**2. Temporarily bypass MFA** to get them working immediately:
```sql
ALTER USER <username> SET MINS_TO_BYPASS_MFA = 30;
```

**3. Have them enroll during that window:**
```sql
ALTER USER <username> ENROLL MFA;
```

**4. If they lost their MFA device** — clear methods and force re-enrollment:
```sql
ALTER USER <username> SET DISABLE_MFA = TRUE;
ALTER USER <username> ENROLL MFA;
```

**5. If the account was disabled:**
```sql
ALTER USER <username> SET DISABLED = FALSE;
```

### Service account connection is failing

**1. Check the error:**
```sql
SELECT event_timestamp, user_name, error_code, error_message,
       first_authentication_factor, reported_client_type, reported_client_version
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE user_name = '<svc_user>'
ORDER BY event_timestamp DESC
LIMIT 10;
```

**2. Fastest fix — key pair auth:**
```bash
openssl genrsa 2048 | openssl pkcs8 -topk8 -inform PEM -out rsa_key.p8 -nocrypt
openssl rsa -in rsa_key.p8 -pubout -out rsa_key.pub
```
```sql
ALTER USER <svc_user> SET RSA_PUBLIC_KEY = '<contents_of_rsa_key.pub>';
```
Then the customer updates their application to `authenticator=snowflake_jwt` with the private key path.

### The admin is locked out of their own account

1. Use a stored one-time passcode (OTP) if generated earlier — see the router `SKILL.md` Step 0
2. Ask another `ACCOUNTADMIN` to run: `ALTER USER <you> SET MINS_TO_BYPASS_MFA = 30;`
3. If no other admin can help: contact Snowflake Support — https://community.snowflake.com/s/article/How-to-Submit-a-Support-Case

---

## Reference: Validated Authentication Factor Values

These are actual observed values — do not substitute plausible-sounding alternatives.

### FIRST_AUTHENTICATION_FACTOR

| Value | Description |
|-------|-------------|
| `PASSWORD` | Username + password |
| `RSA_KEYPAIR` | Key pair (JWT) |
| `SAML2_ASSERTION` | SAML SSO |
| `OAUTH_ACCESS_TOKEN` | OAuth |
| `PROGRAMMATIC_ACCESS_TOKEN` | PAT |
| `WORKLOAD_IDENTITY` | Workload identity federation |
| `ID_TOKEN` | Cached SSO token |
| `WEB_SESSION` | Existing browser session |

### SECOND_AUTHENTICATION_FACTOR

| Value | Description |
|-------|-------------|
| `NULL` | No MFA |
| `PASSKEY` | Passkey (WebAuthn) |
| `TOTP` | Authenticator app |
| `DUO_PUSH` | Duo push notification |
| `MFA_PROMPT` | Generic MFA challenge (seen on some client types) |
| `MFA_TOKEN` | Cached MFA token (requires `ALLOW_CLIENT_MFA_CACHING`) |

Any non-NULL value here means MFA was satisfied, regardless of which literal appears. Use `SHOW MFA METHODS FOR USER <name>;` to see exactly which methods a user has enrolled, independent of login history.

### USERS.TYPE values

| Value | Password allowed? |
|-------|-------------------|
| `PERSON` (or NULL) | Yes — must enroll MFA |
| `SERVICE` | **No** — blocked by Snowflake |
| `SERVICE_AGENT` | **No** |
| `LEGACY_SERVICE` | Yes — being deprecated, migrate to `SERVICE` |
| `SNOWFLAKE_SERVICE` | N/A — Snowflake-internal |

### Known gotchas

- `INFORMATION_SCHEMA.LOGIN_HISTORY()` retention is exactly 7 days; use `-6 days` in `DATEADD` to avoid a boundary error, and ensure a database is in context.
- `EXT_AUTHN_DUO` only flags Duo — use `HAS_MFA` for a complete MFA check.
- `type != 'SERVICE'` does not exclude `LEGACY_SERVICE`/`SNOWFLAKE_SERVICE`; use `(type = 'PERSON' OR type IS NULL)` to select humans.
- There is no `GENERATE_SCOPED_ACCESS_TOKEN` function — use `MINS_TO_BYPASS_MFA` for temporary access.

---

## See Also

- [Planning for the deprecation of single-factor password sign-ins](https://docs.snowflake.com/en/user-guide/security-mfa)
- [Authentication policies](https://docs.snowflake.com/en/user-guide/authentication-policies)
- [ALTER USER](https://docs.snowflake.com/en/sql-reference/sql/alter-user)
- [Key pair authentication](https://docs.snowflake.com/en/user-guide/key-pair-auth)
- [LOGIN_HISTORY view](https://docs.snowflake.com/en/sql-reference/account-usage/login_history)
