# Fleet transition

Prepare War Elephant on a connected workstation. Import the cyber.mil ZIP files the ship is authorized to hold and the current inventory workbook. Record the displayed SHA-256. That value is an integrity check, not proof of publisher authenticity. Confirm both the previous and newest imported baseline remain selectable. Build the frontend and the offline wheel basket, then copy the directory to read-only media.

In the enclave, create the operator and a separate vault passphrase. Enter a discovery credential and a remediation credential with different scope. Approve a short-lived scope that lists exact addresses, excluded hosts, ports, and an expiration. Run directory query only after `FLEETGUARD_ENABLE_LIVE_LDAP` is set and the controller certificate validates. Treat TCP timeouts as inconclusive.

Reconcile spreadsheet, directory, and probe rows without collapsing them on IP. Confirm identities and baselines before assessment. Manual rules stay in the outstanding-work export. For the one implemented change, approve the exact proposal hash, execute, and verify. Roll back only with a second approval, and stop if the file changed in between.

Export the inventory, findings, executions, and audit checkpoint before leaving the enclave. The sync inbox may store those records later. It will not apply approvals or repeat changes. A local administrator can still rewrite the database and recompute the hash chain until an external signer is configured.
