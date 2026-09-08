-- ===================================================================
-- Honeypot-Based Attack Monitoring and Security Analysis System
-- SQLite Database Schema Definition (schema.sql)
-- ===================================================================

-- Enable Foreign Key Constraints
PRAGMA foreign_keys = ON;

-- -------------------------------------------------------------------
-- Table 1: users
-- Stores authenticated administrators with secure password hashes
-- -------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -------------------------------------------------------------------
-- Table 2: events
-- Stores normalized honeypot telemetry and classified attack events
-- -------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    source_port INTEGER,
    destination_port INTEGER,
    protocol TEXT NOT NULL DEFAULT 'ssh',
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'LOW' CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    username TEXT,
    command TEXT,
    raw_log TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Optimized Indexes for Fast Filter, Search & Timeline Analytics
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);

-- -------------------------------------------------------------------
-- Table 3: system_logs
-- Stores internal application logs, auth audits, and error telemetry
-- -------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS system_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    level TEXT NOT NULL DEFAULT 'INFO' CHECK (level IN ('INFO', 'WARNING', 'ERROR', 'SECURITY')),
    message TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_system_logs_level ON system_logs(level);
CREATE INDEX IF NOT EXISTS idx_system_logs_timestamp ON system_logs(timestamp);
