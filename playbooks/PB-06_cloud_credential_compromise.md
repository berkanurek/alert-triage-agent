# PB-06 Cloud access key or service account compromise

## When to use
New access keys or tokens for service accounts, especially when used soon after creation from unknown networks, or mass listing and downloading of storage buckets.

## Investigation
Check whether an approved change ticket covers the key creation. Check where the service account is normally used from. Check the reputation of the source IP and which data was accessed.

## Response
Severity is critical when an unapproved key accessed storage from an external network. Disable the key immediately, rotate all credentials of the service account, review what was downloaded and assess regulatory reporting duties.
