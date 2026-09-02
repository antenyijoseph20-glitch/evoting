-- Database Schema for E-Voting Core Server

CREATE TABLE IF NOT EXISTS issued_signatures (
    id SERIAL PRIMARY KEY,
    vin VARCHAR(19) UNIQUE NOT NULL,
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ballot_box (
    id SERIAL PRIMARY KEY,
    candidate VARCHAR(50) NOT NULL,
    nonce VARCHAR(64) UNIQUE NOT NULL,
    signature NUMERIC NOT NULL UNIQUE,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ballot_nonce ON ballot_box(nonce);
CREATE INDEX IF NOT EXISTS idx_issued_vin ON issued_signatures(vin);