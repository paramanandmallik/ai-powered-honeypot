-- AI Honeypot System Database Initialization

-- Create database schema
CREATE SCHEMA IF NOT EXISTS honeypot;

-- Set default schema
SET search_path TO honeypot;

-- Engagements table
CREATE TABLE IF NOT EXISTS engagements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id VARCHAR(255) UNIQUE NOT NULL,
    source_ip INET NOT NULL,
    target_honeypot VARCHAR(100) NOT NULL,
    threat_confidence DECIMAL(3,2) NOT NULL,
    engagement_decision VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Interactions table
CREATE TABLE IF NOT EXISTS interactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id UUID NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    interaction_type VARCHAR(50) NOT NULL,
    request_data JSONB NOT NULL,
    response_data JSONB NOT NULL,
    synthetic_data_used BOOLEAN DEFAULT false,
    real_data_detected BOOLEAN DEFAULT false,
    confidence_score DECIMAL(3,2),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Intelligence reports table
CREATE TABLE IF NOT EXISTS intelligence_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id UUID NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    mitre_techniques TEXT[],
    mitre_tactics TEXT[],
    tools_identified TEXT[],
    iocs_extracted JSONB,
    attack_patterns JSONB,
    confidence_score DECIMAL(3,2) NOT NULL,
    report_data JSONB NOT NULL,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Threat indicators table
CREATE TABLE IF NOT EXISTS threat_indicators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    indicator_type VARCHAR(50) NOT NULL,
    indicator_value TEXT NOT NULL,
    confidence DECIMAL(3,2) NOT NULL,
    source VARCHAR(100) NOT NULL,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    times_seen INTEGER DEFAULT 1,
    metadata JSONB
);

-- Agent metrics table
CREATE TABLE IF NOT EXISTS agent_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_name VARCHAR(50) NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(10,4) NOT NULL,
    labels JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- System events table
CREATE TABLE IF NOT EXISTS system_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(50) NOT NULL,
    event_source VARCHAR(50) NOT NULL,
    event_data JSONB NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'info',
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_engagements_session_id ON engagements(session_id);
CREATE INDEX IF NOT EXISTS idx_engagements_source_ip ON engagements(source_ip);
CREATE INDEX IF NOT EXISTS idx_engagements_status ON engagements(status);
CREATE INDEX IF NOT EXISTS idx_engagements_started_at ON engagements(started_at);

CREATE INDEX IF NOT EXISTS idx_interactions_engagement_id ON interactions(engagement_id);
CREATE INDEX IF NOT EXISTS idx_interactions_timestamp ON interactions(timestamp);
CREATE INDEX IF NOT EXISTS idx_interactions_type ON interactions(interaction_type);

CREATE INDEX IF NOT EXISTS idx_intelligence_engagement_id ON intelligence_reports(engagement_id);
CREATE INDEX IF NOT EXISTS idx_intelligence_generated_at ON intelligence_reports(generated_at);

CREATE INDEX IF NOT EXISTS idx_threat_indicators_type ON threat_indicators(indicator_type);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_value ON threat_indicators(indicator_value);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_confidence ON threat_indicators(confidence);

CREATE INDEX IF NOT EXISTS idx_agent_metrics_agent_name ON agent_metrics(agent_name);
CREATE INDEX IF NOT EXISTS idx_agent_metrics_timestamp ON agent_metrics(timestamp);

CREATE INDEX IF NOT EXISTS idx_system_events_type ON system_events(event_type);
CREATE INDEX IF NOT EXISTS idx_system_events_timestamp ON system_events(timestamp);

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger for engagements table
CREATE TRIGGER update_engagements_updated_at 
    BEFORE UPDATE ON engagements 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert sample data for development
INSERT INTO threat_indicators (indicator_type, indicator_value, confidence, source, metadata) VALUES
('ip', '192.168.1.100', 0.85, 'test_feed', '{"country": "US", "asn": "AS12345"}'),
('domain', 'malicious-domain.com', 0.92, 'test_feed', '{"category": "malware"}'),
('hash', 'a1b2c3d4e5f6', 0.78, 'test_feed', '{"file_type": "exe"}')
ON CONFLICT DO NOTHING;