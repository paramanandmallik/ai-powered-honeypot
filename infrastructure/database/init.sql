-- AI Honeypot Intelligence Database Schema
-- PostgreSQL initialization script

-- Create database extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create schemas
CREATE SCHEMA IF NOT EXISTS honeypot;
CREATE SCHEMA IF NOT EXISTS intelligence;
CREATE SCHEMA IF NOT EXISTS security;
CREATE SCHEMA IF NOT EXISTS audit;

-- Set search path
SET search_path TO honeypot, intelligence, security, audit, public;

-- ============================================================================
-- HONEYPOT SCHEMA TABLES
-- ============================================================================

-- Honeypot sessions table
CREATE TABLE IF NOT EXISTS honeypot.sessions (
    session_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    honeypot_type VARCHAR(50) NOT NULL,
    honeypot_id VARCHAR(100) NOT NULL,
    attacker_ip INET NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    end_time TIMESTAMP WITH TIME ZONE,
    session_duration INTEGER, -- in seconds
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    s3_location TEXT,
    archived BOOLEAN DEFAULT FALSE,
    archived_date TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Honeypot interactions table
CREATE TABLE IF NOT EXISTS honeypot.interactions (
    interaction_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL REFERENCES honeypot.sessions(session_id) ON DELETE CASCADE,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    interaction_type VARCHAR(50) NOT NULL,
    command TEXT,
    response TEXT,
    synthetic_data_used JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Synthetic data table
CREATE TABLE IF NOT EXISTS honeypot.synthetic_data (
    data_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    data_type VARCHAR(50) NOT NULL,
    synthetic_flag BOOLEAN NOT NULL DEFAULT TRUE,
    fingerprint VARCHAR(64) NOT NULL UNIQUE,
    content_hash VARCHAR(64) NOT NULL,
    s3_location TEXT,
    usage_count INTEGER DEFAULT 0,
    last_accessed TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- INTELLIGENCE SCHEMA TABLES
-- ============================================================================

-- Intelligence reports table
CREATE TABLE IF NOT EXISTS intelligence.reports (
    report_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID REFERENCES honeypot.sessions(session_id) ON DELETE SET NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    mitre_techniques JSONB,
    iocs JSONB,
    confidence_score DECIMAL(3,2) CHECK (confidence_score >= 0 AND confidence_score <= 1),
    threat_assessment TEXT,
    raw_data TEXT,
    attacker_ip INET,
    honeypot_type VARCHAR(50),
    session_duration INTEGER,
    commands_executed JSONB,
    files_accessed JSONB,
    network_connections JSONB,
    synthetic_data_accessed JSONB,
    processed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- External intelligence table
CREATE TABLE IF NOT EXISTS intelligence.external_intelligence (
    intelligence_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source VARCHAR(100) NOT NULL,
    intelligence_type VARCHAR(50) NOT NULL,
    data JSONB NOT NULL,
    confidence_score DECIMAL(3,2) CHECK (confidence_score >= 0 AND confidence_score <= 1),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    metadata JSONB,
    processed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- IOCs (Indicators of Compromise) table
CREATE TABLE IF NOT EXISTS intelligence.iocs (
    ioc_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ioc_type VARCHAR(50) NOT NULL,
    ioc_value TEXT NOT NULL,
    confidence VARCHAR(20) NOT NULL,
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    source_reports UUID[] DEFAULT '{}',
    threat_level VARCHAR(20),
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(ioc_type, ioc_value)
);

-- MITRE ATT&CK techniques table
CREATE TABLE IF NOT EXISTS intelligence.mitre_techniques (
    technique_id VARCHAR(10) PRIMARY KEY,
    technique_name VARCHAR(200) NOT NULL,
    tactic VARCHAR(100) NOT NULL,
    description TEXT,
    first_observed TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_observed TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    observation_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- SECURITY SCHEMA TABLES
-- ============================================================================

-- Security events table
CREATE TABLE IF NOT EXISTS security.events (
    event_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    event_data JSONB,
    processed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    status VARCHAR(20) DEFAULT 'open',
    response_actions JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Security incidents table
CREATE TABLE IF NOT EXISTS security.incidents (
    incident_id VARCHAR(50) PRIMARY KEY,
    event_id UUID REFERENCES security.events(event_id) ON DELETE SET NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'open',
    title VARCHAR(200),
    description TEXT,
    event_data JSONB,
    actions_taken JSONB,
    assigned_to VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    resolved_at TIMESTAMP WITH TIME ZONE
);

-- Real data detection table
CREATE TABLE IF NOT EXISTS security.real_data_detections (
    detection_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID REFERENCES honeypot.sessions(session_id) ON DELETE CASCADE,
    data_type VARCHAR(50) NOT NULL,
    confidence_score DECIMAL(3,2) NOT NULL,
    data_sample TEXT, -- Encrypted sample for analysis
    quarantine_location TEXT,
    status VARCHAR(20) DEFAULT 'quarantined',
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    resolved_at TIMESTAMP WITH TIME ZONE
);

-- ============================================================================
-- AUDIT SCHEMA TABLES
-- ============================================================================

-- Audit log table
CREATE TABLE IF NOT EXISTS audit.logs (
    log_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    user_id VARCHAR(100),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(100),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    error_message TEXT
);

-- System metrics table
CREATE TABLE IF NOT EXISTS audit.system_metrics (
    metric_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(10,2) NOT NULL,
    metric_unit VARCHAR(20),
    tags JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Honeypot sessions indexes
CREATE INDEX IF NOT EXISTS idx_sessions_attacker_ip ON honeypot.sessions(attacker_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_start_time ON honeypot.sessions(start_time);
CREATE INDEX IF NOT EXISTS idx_sessions_honeypot_type ON honeypot.sessions(honeypot_type);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON honeypot.sessions(status);

-- Honeypot interactions indexes
CREATE INDEX IF NOT EXISTS idx_interactions_session_id ON honeypot.interactions(session_id);
CREATE INDEX IF NOT EXISTS idx_interactions_timestamp ON honeypot.interactions(timestamp);
CREATE INDEX IF NOT EXISTS idx_interactions_type ON honeypot.interactions(interaction_type);

-- Synthetic data indexes
CREATE INDEX IF NOT EXISTS idx_synthetic_data_type ON honeypot.synthetic_data(data_type);
CREATE INDEX IF NOT EXISTS idx_synthetic_data_last_accessed ON honeypot.synthetic_data(last_accessed);
CREATE INDEX IF NOT EXISTS idx_synthetic_data_usage_count ON honeypot.synthetic_data(usage_count);

-- Intelligence reports indexes
CREATE INDEX IF NOT EXISTS idx_reports_timestamp ON intelligence.reports(timestamp);
CREATE INDEX IF NOT EXISTS idx_reports_confidence ON intelligence.reports(confidence_score);
CREATE INDEX IF NOT EXISTS idx_reports_attacker_ip ON intelligence.reports(attacker_ip);
CREATE INDEX IF NOT EXISTS idx_reports_session_id ON intelligence.reports(session_id);

-- IOCs indexes
CREATE INDEX IF NOT EXISTS idx_iocs_type ON intelligence.iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON intelligence.iocs(ioc_value);
CREATE INDEX IF NOT EXISTS idx_iocs_first_seen ON intelligence.iocs(first_seen);
CREATE INDEX IF NOT EXISTS idx_iocs_status ON intelligence.iocs(status);

-- Security events indexes
CREATE INDEX IF NOT EXISTS idx_security_events_type ON security.events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security.events(severity);
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security.events(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_events_status ON security.events(status);

-- Audit logs indexes
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit.logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit.logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit.logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_success ON audit.logs(success);

-- ============================================================================
-- FUNCTIONS AND TRIGGERS
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers for updated_at columns
CREATE TRIGGER update_sessions_updated_at BEFORE UPDATE ON honeypot.sessions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_synthetic_data_updated_at BEFORE UPDATE ON honeypot.synthetic_data
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_iocs_updated_at BEFORE UPDATE ON intelligence.iocs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_mitre_techniques_updated_at BEFORE UPDATE ON intelligence.mitre_techniques
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_incidents_updated_at BEFORE UPDATE ON security.incidents
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to automatically update IOC statistics
CREATE OR REPLACE FUNCTION update_ioc_stats()
RETURNS TRIGGER AS $$
BEGIN
    -- Update IOC last_seen timestamp and increment observation count
    INSERT INTO intelligence.iocs (ioc_type, ioc_value, confidence, first_seen, last_seen)
    SELECT 
        (jsonb_array_elements(NEW.iocs)->>'type')::VARCHAR(50),
        (jsonb_array_elements(NEW.iocs)->>'value')::TEXT,
        (jsonb_array_elements(NEW.iocs)->>'confidence')::VARCHAR(20),
        NEW.timestamp,
        NEW.timestamp
    FROM (SELECT NEW.iocs) AS t
    WHERE NEW.iocs IS NOT NULL
    ON CONFLICT (ioc_type, ioc_value) 
    DO UPDATE SET 
        last_seen = NEW.timestamp,
        source_reports = array_append(intelligence.iocs.source_reports, NEW.report_id),
        updated_at = NOW();
    
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to update IOC stats when intelligence reports are inserted
CREATE TRIGGER update_ioc_stats_trigger AFTER INSERT ON intelligence.reports
    FOR EACH ROW EXECUTE FUNCTION update_ioc_stats();

-- Function to update MITRE technique statistics
CREATE OR REPLACE FUNCTION update_mitre_stats()
RETURNS TRIGGER AS $$
BEGIN
    -- Update MITRE technique observation statistics
    INSERT INTO intelligence.mitre_techniques (technique_id, technique_name, tactic, first_observed, last_observed, observation_count)
    SELECT 
        (jsonb_array_elements(NEW.mitre_techniques)->>'technique_id')::VARCHAR(10),
        (jsonb_array_elements(NEW.mitre_techniques)->>'name')::VARCHAR(200),
        (jsonb_array_elements(NEW.mitre_techniques)->>'tactic')::VARCHAR(100),
        NEW.timestamp,
        NEW.timestamp,
        1
    FROM (SELECT NEW.mitre_techniques) AS t
    WHERE NEW.mitre_techniques IS NOT NULL
    ON CONFLICT (technique_id) 
    DO UPDATE SET 
        last_observed = NEW.timestamp,
        observation_count = intelligence.mitre_techniques.observation_count + 1,
        updated_at = NOW();
    
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to update MITRE stats when intelligence reports are inserted
CREATE TRIGGER update_mitre_stats_trigger AFTER INSERT ON intelligence.reports
    FOR EACH ROW EXECUTE FUNCTION update_mitre_stats();

-- ============================================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================================

-- View for active sessions with basic statistics
CREATE OR REPLACE VIEW honeypot.active_sessions AS
SELECT 
    s.session_id,
    s.honeypot_type,
    s.attacker_ip,
    s.start_time,
    EXTRACT(EPOCH FROM (NOW() - s.start_time))::INTEGER AS duration_seconds,
    COUNT(i.interaction_id) AS interaction_count,
    MAX(i.timestamp) AS last_interaction
FROM honeypot.sessions s
LEFT JOIN honeypot.interactions i ON s.session_id = i.session_id
WHERE s.status = 'active'
GROUP BY s.session_id, s.honeypot_type, s.attacker_ip, s.start_time;

-- View for recent high-confidence intelligence
CREATE OR REPLACE VIEW intelligence.recent_high_confidence AS
SELECT 
    r.report_id,
    r.timestamp,
    r.confidence_score,
    r.attacker_ip,
    r.honeypot_type,
    jsonb_array_length(COALESCE(r.mitre_techniques, '[]'::jsonb)) AS mitre_technique_count,
    jsonb_array_length(COALESCE(r.iocs, '[]'::jsonb)) AS ioc_count
FROM intelligence.reports r
WHERE r.confidence_score >= 0.7
    AND r.timestamp >= NOW() - INTERVAL '7 days'
ORDER BY r.timestamp DESC;

-- View for security incident summary
CREATE OR REPLACE VIEW security.incident_summary AS
SELECT 
    i.incident_id,
    i.severity,
    i.status,
    i.title,
    i.created_at,
    i.updated_at,
    e.event_type,
    e.timestamp AS event_timestamp
FROM security.incidents i
LEFT JOIN security.events e ON i.event_id = e.event_id
ORDER BY i.created_at DESC;

-- ============================================================================
-- INITIAL DATA
-- ============================================================================

-- Insert common MITRE ATT&CK techniques
INSERT INTO intelligence.mitre_techniques (technique_id, technique_name, tactic, description) VALUES
('T1003', 'OS Credential Dumping', 'Credential Access', 'Adversaries may attempt to dump credentials to obtain account login and credential material'),
('T1055', 'Process Injection', 'Defense Evasion', 'Adversaries may inject code into processes in order to evade process-based defenses'),
('T1059', 'Command and Scripting Interpreter', 'Execution', 'Adversaries may abuse command and script interpreters to execute commands'),
('T1078', 'Valid Accounts', 'Defense Evasion', 'Adversaries may obtain and abuse credentials of existing accounts'),
('T1082', 'System Information Discovery', 'Discovery', 'An adversary may attempt to get detailed information about the operating system'),
('T1083', 'File and Directory Discovery', 'Discovery', 'Adversaries may enumerate files and directories or may search in specific locations'),
('T1087', 'Account Discovery', 'Discovery', 'Adversaries may attempt to get a listing of accounts on a system or within an environment'),
('T1090', 'Proxy', 'Command and Control', 'Adversaries may use a connection proxy to direct network traffic'),
('T1105', 'Ingress Tool Transfer', 'Command and Control', 'Adversaries may transfer tools or other files from an external system'),
('T1110', 'Brute Force', 'Credential Access', 'Adversaries may use brute force techniques to gain access to accounts'),
('T1190', 'Exploit Public-Facing Application', 'Initial Access', 'Adversaries may attempt to take advantage of a weakness in an Internet-facing computer'),
('T1566', 'Phishing', 'Initial Access', 'Adversaries may send phishing messages to gain access to victim systems')
ON CONFLICT (technique_id) DO NOTHING;

-- Create database user for application (if not exists)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'honeypot_app') THEN
        CREATE ROLE honeypot_app WITH LOGIN PASSWORD 'change_me_in_production';
    END IF;
END
$$;

-- Grant permissions to application user
GRANT USAGE ON SCHEMA honeypot, intelligence, security, audit TO honeypot_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA honeypot, intelligence, security, audit TO honeypot_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA honeypot, intelligence, security, audit TO honeypot_app;

-- Grant permissions on views
GRANT SELECT ON honeypot.active_sessions TO honeypot_app;
GRANT SELECT ON intelligence.recent_high_confidence TO honeypot_app;
GRANT SELECT ON security.incident_summary TO honeypot_app;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA honeypot, intelligence, security, audit 
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO honeypot_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA honeypot, intelligence, security, audit 
    GRANT USAGE, SELECT ON SEQUENCES TO honeypot_app;

COMMIT;