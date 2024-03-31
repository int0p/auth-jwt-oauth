-- Add up migration script here
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

DROP TABLE IF EXISTS "users";

CREATE TABLE
    "users" (
        id UUID NOT NULL PRIMARY KEY DEFAULT (uuid_generate_v4()),
        name VARCHAR(100) NOT NULL,
        email VARCHAR(255) NOT NULL ,
        photo VARCHAR NOT NULL DEFAULT 'default.png',
        verified BOOLEAN NOT NULL DEFAULT FALSE,
        provider VARCHAR(50) NOT NULL DEFAULT 'local',
        password VARCHAR(100),
        role VARCHAR(50) NOT NULL DEFAULT 'user',
        created_at TIMESTAMP
        WITH
            TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP
        WITH
            TIME ZONE DEFAULT NOW()
    );

ALTER TABLE "users"
ADD CONSTRAINT password_required CHECK ((provider != 'google') OR (password IS NOT NULL));

ALTER TABLE "users"
ADD CONSTRAINT email_provider_unique UNIQUE (email, provider);

CREATE INDEX users_email_idx ON users (email);