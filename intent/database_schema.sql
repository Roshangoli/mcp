-- Database schema addition for Tenant-Scoped Intent Certificates (Layer 0)
-- This table will be added to database.py in the init_database() method

-- Intent certificates table
-- Stores short-lived (5 min) certificates binding user intent to authorized operations
CREATE TABLE IF NOT EXISTS intent_certificates (
    certificate_id TEXT PRIMARY KEY,        -- UUID v4 string
    customer_id INTEGER NOT NULL,           -- FK to customers(customer_id)
    intent_classes TEXT NOT NULL,           -- JSON array: ["search", "order", "track", "export"]
    item_bounds TEXT,                       -- JSON array: ["laptop", "keyboard"] (can be NULL)
    spend_limit REAL,                       -- Dollar amount for place_order (can be NULL)
    tenant_scope TEXT NOT NULL,             -- "ALL" or comma-separated company IDs "1,3,5"
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,          -- created_at + 5 minutes
    signature TEXT NOT NULL,                -- HMAC-SHA256 signature (hex-encoded)
    is_active INTEGER DEFAULT 1,            -- 1 = active, 0 = revoked/used (for future use)
    is_completed INTEGER DEFAULT 0,         -- 1 = primary action completed (place_order), 0 = not completed
    call_count INTEGER DEFAULT 0,           -- Number of times this certificate has been used
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

-- Index for fast lookup by customer_id and active status
CREATE INDEX IF NOT EXISTS idx_intent_certificates_customer
ON intent_certificates(customer_id, is_active);

-- Index for fast cleanup of expired certificates
CREATE INDEX IF NOT EXISTS idx_intent_certificates_expiry
ON intent_certificates(is_active, expires_at);

-- Modification to existing orders table
-- Add certificate_id as optional foreign key to track cumulative spending
-- This ALTER TABLE should be added to database.py after the CREATE TABLE orders statement
-- ALTER TABLE orders ADD COLUMN certificate_id TEXT REFERENCES intent_certificates(certificate_id);
-- Note: In practice, this will be added in the init_database() method with IF NOT EXISTS checks

-- Notes:
-- 1. JSON storage: SQLite 3.38+ has native JSON support, but we use TEXT with JSON
--    serialization for broader compatibility. Parse with json.loads() in Python.
-- 2. Cleanup: Expired certificates (expires_at < now) should be periodically cleaned
--    up, similar to how rate_limit_log cleanup works in security.py line 184.
-- 3. is_active field: Reserved for future use (certificate revocation). For now,
--    always 1. Could be set to 0 to revoke a certificate before it expires.
-- 4. is_completed field: Set to 1 when place_order succeeds. Subsequent calls with
--    that certificate_id get CertificateExpiredError if is_completed = 1.
-- 5. call_count field: Incremented on every successful before_tool_call() execution.
--    If call_count exceeds 20: raise IntentDriftWarning and log it.
-- 6. certificate_id in orders: Links orders to the certificate that authorized them,
--    enabling cumulative spend limit tracking across multiple orders.
