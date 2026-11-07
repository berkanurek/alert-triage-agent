# PB-02 Phishing email

## When to use
Emails that imitate a trusted brand, use a newly registered or look-alike (typosquatting) domain, or ask users to log in or open attachments.

## Investigation
Check the sender domain reputation and registration age. Find all recipients and who clicked the link or opened the attachment. Check whether any clicking user entered credentials or logged in from a new location afterwards.

## Response
Severity is high if any user clicked, medium if nobody clicked. Remove the email from all mailboxes, block the domain and URL, reset passwords of users who clicked, and check their accounts for suspicious activity.
