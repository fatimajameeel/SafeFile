-- Drop tables if they exist (useful during development)
DROP TABLE IF EXISTS system_log;
DROP TABLE IF EXISTS file;
DROP TABLE IF EXISTS scan;
DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS role;

--------------------------------------------------
-- ROLE TABLE
--------------------------------------------------
CREATE TABLE role (
    role_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    role_name   TEXT NOT NULL UNIQUE,
    description TEXT
);

--------------------------------------------------
-- USER TABLE
--------------------------------------------------
CREATE TABLE user (
    user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email         TEXT UNIQUE,
    role_id       INTEGER NOT NULL,
    FOREIGN KEY (role_id) REFERENCES role(role_id)
);

--------------------------------------------------
-- SCAN TABLE
--------------------------------------------------
CREATE TABLE scan (
    scan_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    scan_type  TEXT NOT NULL,                -- single_file / folder
    timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user(user_id)
);

--------------------------------------------------
-- FILE TABLE (FULLY MATCHES ERD)
--------------------------------------------------
CREATE TABLE file (
    file_id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id              INTEGER NOT NULL,
    file_name            TEXT NOT NULL,
    file_size            INTEGER,
    timestamp            DATETIME DEFAULT CURRENT_TIMESTAMP,

    -- Detection & analysis results
    file_type_detected   TEXT,
    entropy_value        REAL,
    yara_hits            TEXT,
    file_hash            TEXT,
    vt_report_json       TEXT,
    vt_malicious_count   INTEGER,
    vt_total_engines     INTEGER,

    ml_verdict           TEXT,
    final_verdict        TEXT,
    risk_score           REAL,
    malware_type         TEXT,
    is_pe                INTEGER,            -- 0 = false, 1 = true

    -- Analyst interaction
    analyst_note         TEXT,
    analyst_note_at      DATETIME,

    -- Full structured analysis snapshot
    analysis_json        TEXT,

    FOREIGN KEY (scan_id) REFERENCES scan(scan_id)
);

--------------------------------------------------
-- SYSTEM LOG TABLE
--------------------------------------------------
CREATE TABLE system_log (
    log_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER,
    scan_id       INTEGER,
    file_id       INTEGER,
    event_type    TEXT NOT NULL,
    event_detail  TEXT,
    severity      TEXT,                      -- INFO / WARNING / ERROR
    timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user(user_id),
    FOREIGN KEY (scan_id) REFERENCES scan(scan_id),
    FOREIGN KEY (file_id) REFERENCES file(file_id)
);
