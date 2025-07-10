-- SQL script for real-time fraud detection

-- Create base tables
CREATE TABLE IF NOT EXISTS Users (
    user_id     SERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    email       TEXT NOT NULL UNIQUE,
    country     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS Accounts (
    account_id  SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES Users(user_id),
    balance     NUMERIC(12,2) DEFAULT 0,
    device_id   TEXT
);

CREATE TABLE IF NOT EXISTS Transactions (
    txn_id       SERIAL PRIMARY KEY,
    account_id   INTEGER NOT NULL REFERENCES Accounts(account_id),
    amount       NUMERIC(12,2) NOT NULL,
    txn_type     TEXT NOT NULL,
    country      TEXT NOT NULL,
    device_id    TEXT,
    txn_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Table to record suspicious activity
CREATE TABLE IF NOT EXISTS Fraud_Alerts (
    alert_id       SERIAL PRIMARY KEY,
    user_id        INTEGER NOT NULL REFERENCES Users(user_id),
    reason         TEXT NOT NULL,
    alert_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Stored procedure to check for suspicious activity
CREATE OR REPLACE FUNCTION CheckForSuspiciousActivity() RETURNS TRIGGER AS $$
BEGIN
    -- Rule 1: More than two transfers > $5000 within one hour
    IF (TG_OP = 'INSERT') THEN
        -- Count large transfers in the past hour for the same account
        IF NEW.txn_type = 'transfer' AND NEW.amount > 5000 THEN
            PERFORM 1 FROM Transactions
            WHERE account_id = NEW.account_id
              AND txn_type = 'transfer'
              AND amount > 5000
              AND txn_timestamp >= NEW.txn_timestamp - INTERVAL '1 hour';

            IF FOUND THEN
                -- Count again to see if there are already at least two others
                IF (
                    SELECT COUNT(*) FROM Transactions
                    WHERE account_id = NEW.account_id
                      AND txn_type = 'transfer'
                      AND amount > 5000
                      AND txn_timestamp >= NEW.txn_timestamp - INTERVAL '1 hour'
                ) >= 2 THEN
                    INSERT INTO Fraud_Alerts(user_id, reason, alert_timestamp)
                    SELECT a.user_id,
                           'More than two large transfers within an hour',
                           NEW.txn_timestamp
                    FROM Accounts a WHERE a.account_id = NEW.account_id;
                END IF;
            END IF;
        END IF;

        -- Rule 2: Transactions from different countries within 30 minutes
        PERFORM 1 FROM Transactions t
        JOIN Accounts a ON a.account_id = t.account_id
        JOIN Accounts a2 ON a2.account_id = NEW.account_id
        WHERE a.user_id = a2.user_id
          AND t.country <> NEW.country
          AND t.txn_timestamp >= NEW.txn_timestamp - INTERVAL '30 minutes'
          AND t.txn_timestamp <= NEW.txn_timestamp + INTERVAL '30 minutes'
          LIMIT 1;
        IF FOUND THEN
            INSERT INTO Fraud_Alerts(user_id, reason, alert_timestamp)
            SELECT a2.user_id,
                   'Transactions from different countries within 30 minutes',
                   NEW.txn_timestamp
            FROM Accounts a2 WHERE a2.account_id = NEW.account_id;
        END IF;

        -- Rule 3: New device used after midnight
        IF NEW.device_id IS NOT NULL AND EXTRACT(HOUR FROM NEW.txn_timestamp) >= 0 AND EXTRACT(HOUR FROM NEW.txn_timestamp) < 6 THEN
            PERFORM 1 FROM Transactions t
            WHERE t.account_id = NEW.account_id
              AND t.device_id = NEW.device_id
              LIMIT 1;
            IF NOT FOUND THEN
                INSERT INTO Fraud_Alerts(user_id, reason, alert_timestamp)
                SELECT a.user_id,
                       'New device used after midnight',
                       NEW.txn_timestamp
                FROM Accounts a WHERE a.account_id = NEW.account_id;
            END IF;
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to call the procedure on new transactions
DROP TRIGGER IF EXISTS trg_check_suspicious ON Transactions;
CREATE TRIGGER trg_check_suspicious
AFTER INSERT ON Transactions
FOR EACH ROW
EXECUTE FUNCTION CheckForSuspiciousActivity();

-- Sample data to simulate streaming events
INSERT INTO Users(name, email, country) VALUES
('Alice', 'alice@example.com', 'US'),
('Bob', 'bob@example.com', 'US');

INSERT INTO Accounts(user_id, balance, device_id) VALUES
(1, 10000, 'device_a1'),
(2, 5000, 'device_b1');

-- Simulate transactions
INSERT INTO Transactions(account_id, amount, txn_type, country, device_id, txn_timestamp)
VALUES
-- Large transfers for rule 1
(1, 6000, 'transfer', 'US', 'device_a1', '2025-07-10 08:00:00'),
(1, 7000, 'transfer', 'US', 'device_a1', '2025-07-10 08:30:00'),
(1, 8000, 'transfer', 'US', 'device_a1', '2025-07-10 08:45:00'),

-- Different countries for rule 2
(2, 100, 'purchase', 'US', 'device_b1', '2025-07-10 09:00:00'),
(2, 50, 'purchase', 'CA', 'device_b1', '2025-07-10 09:25:00'),

-- New device after midnight for rule 3
(1, 20, 'purchase', 'US', 'device_a2', '2025-07-11 01:15:00');

-- View fraud alerts
SELECT * FROM Fraud_Alerts;
