
CREATE TABLE IF NOT EXISTS certificates (
    nickname VARCHAR(255) PRIMARY KEY,
    cert_pem TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_certificates_nickname ON certificates(nickname);
