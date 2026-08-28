---
name: strong-authentication-admin-notify
description: "Email template and MFA enrollment trigger for password-only human users."
parent_skill: strong-authentication-admin
---

# Notify Mode

**When to load:** From `strong-authentication-admin` Step "Mode Menu", option 3, or after Fix mode.

Two options here: trigger Snowflake's built-in enrollment email, or send a custom email via a notification integration. Ask the user which they'd prefer.

---

## Option A: Trigger Snowflake's Built-In Enrollment Prompt (recommended, simpler)

Snowflake emails the user a direct enrollment link. No notification integration required.

### Step 1 — Preview

```sql
SELECT DISTINCT u.name, u.email, u.last_success_login
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS u
INNER JOIN (
    SELECT DISTINCT user_name
    FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
    WHERE event_timestamp >= DATEADD('day', -90, CURRENT_TIMESTAMP)
      AND is_success = 'YES'
      AND first_authentication_factor = 'PASSWORD'
      AND second_authentication_factor IS NULL
) pw ON pw.user_name = u.name
WHERE u.deleted_on IS NULL
  AND u.disabled = FALSE
  AND u.has_mfa = FALSE
  AND (u.type = 'PERSON' OR u.type IS NULL)   -- human users only
ORDER BY u.name;
```

Flag any rows with a `NULL` email — Snowflake will return a URL you'll need to hand-deliver instead of emailing automatically. Show these separately.

### Step 2 — Confirm

```
I found N human users who are password-only and not yet MFA-enrolled.
Trigger Snowflake's enrollment email for all of them?
(yes / no / let me pick specific users)
```

### Step 3 — Execute (one user at a time)

```sql
ALTER USER "<username>" ENROLL MFA;
```

For users with no verified email, this returns a URL instead of sending mail — capture and relay that URL to the user for manual delivery.

### Step 4 — Summary

"Enrollment prompts sent to X of N users. Y users had no email on file — here are their enrollment URLs to send manually: [...]"

---

## Option B: Custom Email via Notification Integration

Use this if the customer wants a fully custom message (deadline date, company-specific instructions) rather than Snowflake's default enrollment email.

### Prerequisite check

```sql
SHOW INTEGRATIONS;
-- Look for TYPE = NOTIFICATION, ENABLED = true
```

If none exists, stop and direct the user to set one up first: https://docs.snowflake.com/en/user-guide/notifications/email-stored-proc — do not attempt to create a notification integration on their behalf without their explicit input on mail settings.

### Email template (give this to the user to review/customize, do not send until approved)

---
**Subject:** Action required — Update your Snowflake login before [DATE]

Hi [First Name],

We're making a required security update to how you log in to Snowflake. Starting **[DATE]**, Snowflake will no longer accept logins using only a username and password. You'll need to set up a second verification step, called MFA.

**If you already use single sign-on** to reach Snowflake, you're all set — no action needed.

**If you log in with a Snowflake username and password**, here's what to do before [DATE]:
1. Sign in to Snowsight
2. Click your name in the bottom-left corner, then **Settings**
3. Click **Authentication**, then enroll an MFA method
4. Choose one: **Passkey** (recommended), **Authenticator app**, or **Duo**

Takes about 2 minutes. Questions? Contact [admin email].

Thank you,
[Your name]
---

### Execute — ask for the integration name and deadline date, then loop one user at a time

For each user found in the Option A preview query (with a non-null email):
```sql
CALL SYSTEM$SEND_EMAIL(
    '<notification_integration>',
    '<user_email>',
    'Action Required: Update Your Snowflake Login Before <deadline_date>',
    '<the customized email body, with <user_name> substituted in>'
);
```

Report success/failure per user, then a final summary.

---

## Next

**Ask:**
```
Notify mode complete. Once your deadline has passed, come back and run
Enforce mode to require MFA going forward, or Disable mode to remove
access for anyone who still hasn't complied.
```
