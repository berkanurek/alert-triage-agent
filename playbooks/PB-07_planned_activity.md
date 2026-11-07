# PB-07 Approved security testing and planned activity

## When to use
Alerts from vulnerability scanners, antivirus tests with the EICAR test file, penetration tests or maintenance work.

## Investigation
Find an approved change ticket that names the host, IP or user. Check that the activity happened inside the approved time window and came from the approved source.

## Response
If the change ticket matches the source and the time window, close the alert as a false positive with severity low and reference the ticket ID. If anything does not match, treat the activity as real and escalate.
