# PB-01 Password guessing and account takeover

## When to use
Many failed logins for one account (brute force) or for many accounts (password spraying), especially when followed by a successful login, a login without MFA, or traffic from Tor or anonymizing services.

## Investigation
Check the source IP reputation. Check whether the successful login completed MFA. Check the user's usual locations and devices. Look for new mailbox rules, MFA changes or password resets after the login.

## Response
Severity is high if a login succeeded after the failures, critical if the account is privileged. Disable active sessions, force a password reset, re-register MFA and block the source IP. Notify the user through a separate channel.
