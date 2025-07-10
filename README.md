# Fraud Detection SQL Demo

This repository contains a simple SQL script that demonstrates how a real-time fraud detection rules engine can be implemented using database triggers and stored procedures.

The script creates the following objects:

- `Users`, `Accounts` and `Transactions` tables representing a minimal banking schema.
- `Fraud_Alerts` table where all detected suspicious activity is logged.
- `CheckForSuspiciousActivity` stored procedure implementing three fraud rules:
  1. More than two transfers over $5000 within one hour.
  2. Transactions from different countries less than 30 minutes apart.
  3. A new device used between midnight and 6 AM.
- A trigger that executes this procedure after each insert into `Transactions`.
- Sample inserts that simulate streaming transactions and populate the alerts table.

To try the demo in PostgreSQL, run:

```bash
psql -f sql/fraud_detection.sql
```

After executing the script, query `Fraud_Alerts` to see which transactions triggered rules.
