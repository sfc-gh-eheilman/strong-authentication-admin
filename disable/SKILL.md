---
name: strong-authentication-admin-disable
description: "Disable users who have not complied after their notification deadline. Highest-risk mode — requires a typed exact-count confirmation."
parent_skill: strong-authentication-admin
---

# Disable Mode

**When to load:** From `strong-authentication-admin` Step "Mode Menu", option 5 — normally only after Notify mode has run and the customer's own deadline has passed.

This is the highest-risk mode in this skill. It locks users out. Use the strictest confirmation pattern here.

**Never bulk-disable service accounts.** If any of the accounts found below are `SERVICE` or `LEGACY_SERVICE` type, stop and redirect to `../fix/SKILL.md` Fix 2b instead — migrate them, don't disable them. Disabling a service account breaks production pipelines immediately with no warning.

---

## Step 1 — Ask for the notification date

```
What date did you send your MFA enrollment notification to users?
(This is the cutoff — we'll only flag users who logged in with
password-only AFTER this date, meaning they saw the notice and didn't act.)
```

## Step 2 — Preview

```sql
SELECT DISTINCT
    h.user_name,
    u.email,
    u.type                              AS user_type,
    u.has_mfa,
    COUNT(*)                            AS pw_only_logins_since_notification,
    MAX(h.event_timestamp)              AS last_pw_only_login
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY h
JOIN SNOWFLAKE.ACCOUNT_USAGE.USERS u ON u.name = h.user_name
WHERE h.event_timestamp >= '<notification_date>'::TIMESTAMP
  AND h.is_success = 'YES'
  AND h.first_authentication_factor = 'PASSWORD'
  AND h.second_authentication_factor IS NULL
  AND u.deleted_on IS NULL
  AND u.disabled = FALSE
GROUP BY h.user_name, u.email, u.type, u.has_mfa
ORDER BY last_pw_only_login DESC;
```

**Check the `user_type` column in the results.** Split the list:
- **Human users (`PERSON` or blank type):** candidates for disabling in this mode
- **`SERVICE` / `LEGACY_SERVICE` / `SERVICE_AGENT`:** exclude from this mode entirely, flag to the user, and point them at Fix mode instead

Present only the human-user subset as the candidate list going forward.

## Step 3 — Typed Confirmation (not just "yes")

Count the human-user candidates (call this count **N**). **Ask:**

```
I found N human users who have logged in password-only since <date> and
still have no MFA enrolled. Disabling them will lock them out immediately
until an admin re-enables them.

To confirm, type exactly: DISABLE N USERS

(substituting the actual number for N — e.g. "DISABLE 7 USERS")
```

**Do not proceed unless the user's reply matches the exact count shown.** If they type a different number, or "yes," or anything else, stop and ask again — this is intentional friction for a destructive action. If the count doesn't match, it's also a signal the list may have changed since they last looked; re-run the preview query before asking again.

## Step 4 — Execute (one user at a time)

For each confirmed human-user candidate:
```sql
ALTER USER "<username>" SET DISABLED = TRUE;
```

Report success/failure per user as you go.

## Step 5 — Summary and Re-Enable Path

Report: "Disabled X of N users."

Remind the user how to reverse this per-user once someone enrolls in MFA:
```sql
ALTER USER "<username>" SET DISABLED = FALSE;
```

---

## Next

This is typically the last mode in a full run. **Ask:**
```
Would you like to re-run Assess mode now to see the updated state of your
account, or are you done for this session?
```
If yes → **Load** `../assess/SKILL.md`.
