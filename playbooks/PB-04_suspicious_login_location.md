# PB-04 Impossible travel and unusual login location

## When to use
Logins from two distant locations in a time that makes physical travel impossible, or a login from a country the user never used before.

## Investigation
Check whether the second IP belongs to a company-approved VPN or proxy. Check the user's history with that VPN. Check whether MFA was completed and whether the device is known.

## Response
If the IP is an approved VPN that the user uses regularly and MFA was completed, close the alert as a false positive with severity low. Otherwise treat it as possible account takeover and follow PB-01.
