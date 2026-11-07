# Privacy and data flow

- **URL:** local parsing is performed first. Query values are excluded from saved reports; saved URL reports retain the hostname. If URLhaus and/or Google Web Risk is configured and the user opts in, the complete URL path and query (fragment excluded) are sent to each configured provider. Token-like query keys and private IP literals are skipped. Message text and bulk inputs are never sent to these providers.
- **Message:** processed in memory. The returned report can include extracted URLs and phone-like text for the current view; the persisted history removes those extracted values and does not store the original message.
- **QR:** decoded in the browser. QR payload is shown before analysis. UPI fields may be saved in local report history; treat that history as sensitive.
- **File:** bytes are processed in memory and not saved. The report retains a hash, file size/type, and generic `Uploaded file` label; filename is not retained in history.
- **History:** reports are stored in the local SQLite database, up to 500 per account. The database is not encrypted at rest. Authenticated users can view/delete their reports or clear their own history. Account deletion removes that account's reports and sessions. Pre-migration orphan records remain inaccessible.
- Usernames, password hashes, session digests, and CSRF tokens are stored by the service. Passwords are not stored as plain text. No email address is required; password reset and account recovery are not implemented.
- No analytics are included. URLhaus and Web Risk calls occur only when configured and explicitly opted into for that URL scan.

Do not treat this local preview as a production identity service. It lacks email verification, password reset, MFA, account recovery, and independent security review.
