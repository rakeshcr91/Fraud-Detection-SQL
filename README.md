# Fraud Detection SQL Demo

This repository contains an extended SQL script that demonstrates a real-time fraud detection rules engine using database triggers and stored procedures. The script now includes a large amount of sample data (over 1000 lines) so that you can test rule detection at scale.

The script creates the following objects:

- `Users`, `Accounts` and `Transactions` tables representing a minimal banking schema.
- `Fraud_Alerts` table where suspicious activity is logged.
- `Logins` table for login events and `Login_Alerts` for suspicious logins.
- `CheckForSuspiciousActivity` stored procedure implementing transaction rules.
- `CheckLoginActivity` stored procedure implementing login rules.
- Triggers that execute the procedures after each insert.
- Sample data for hundreds of users, accounts, transactions and login events.

To try the demo in PostgreSQL, run:

```bash
psql -f sql/fraud_detection.sql
```

After executing the script, query `Fraud_Alerts` and `Login_Alerts` to see which events triggered rules.
