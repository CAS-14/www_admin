CREATE TABLE access(
    address TEXT NOT NULL,
    real_address TEXT,
    time INTEGER NOT NULL,
    method TEXT,
    path TEXT,
    status INTEGER NOT NULL,
    response_length INTEGER,
    referer TEXT,
    user_agent TEXT
);