# AI-Powered Honeypot System (AgentCore)

A comprehensive AI-powered honeypot system built with AWS AgentCore that provides intelligent threat detection, automated engagement, and real-time intelligence generation.

## 🎯 Overview

This system deploys multiple AI agents that work together to:
- **Detect** incoming threats and attacks
- **Coordinate** response strategies 
- **Engage** with attackers through realistic honeypots
- **Generate** actionable threat intelligence

## 🏗️ Architecture

The system consists of four main AI agents:
- **Detection Agent**: Monitors and identifies potential threats
- **Coordinator Agent**: Orchestrates system responses
- **Interaction Agent**: Manages honeypot engagements
- **Intelligence Agent**: Generates threat reports and IOCs

## 🚀 Features

### Real-time Dashboard
- Live threat monitoring and metrics
- Active engagement tracking
- Intelligence report generation
- System health monitoring
- Professional architecture diagrams

### AI Agent Capabilities
- Automated threat detection with confidence scoring
- Dynamic honeypot deployment and management
- Intelligent attacker engagement strategies
- MITRE ATT&CK framework mapping
- IOC extraction and threat intelligence generation

### Honeypot Infrastructure
- Web admin portal honeypots
- SSH service honeypots
- Database honeypots
- File share honeypots

## 🌐 Live Dashboard

Access the real-time dashboard at:
- **Primary**: https://srms4z2ke7.execute-api.us-east-1.amazonaws.com/prod/
- **Alternative**: https://srms4z2ke7.execute-api.us-east-1.amazonaws.com/

## 📊 Dashboard Features

- **System Status**: Real-time agent health monitoring
- **Live Metrics**: Threat counts, active engagements, intelligence reports
- **Threat Analysis**: Detailed threat detection with confidence scoring
- **Active Engagements**: Real-time honeypot interaction tracking
- **Intelligence Reports**: MITRE ATT&CK mapped threat intelligence
- **Architecture Overview**: Professional system architecture visualization

## 🛠️ Technology Stack

- **AWS AgentCore**: AI agent orchestration platform
- **AWS Lambda**: Serverless dashboard and API endpoints
- **AWS API Gateway**: RESTful API management
- **AWS S3 + CloudFront**: Static asset delivery
- **Python**: Core agent implementation
- **Docker**: Containerized deployment
- **HTML/CSS/JavaScript**: Interactive dashboard

## 📁 Project Structure

```
ai-honeypot-agentcore/
├── agents/                     # Core AI agent implementations
├── build/agentcore/           # AgentCore packaged agents
├── deployment/                # Deployment scripts and configurations
├── infrastructure/            # AWS infrastructure as code
├── tests/                     # Comprehensive testing suite
├── docs/                      # System documentation
├── lambda_function.py         # Dashboard Lambda function
├── docker-compose.yml         # Local development environment
└── README.md                  # This file
```

## 🚦 Quick Start

### Local Development
```bash
# Start the development environment
./start-dev-environment.sh

# Run local validation
python run_local_validation.py

# Test S3 image integration
python test_s3_image.py
```

### AWS Deployment
```bash
# Deploy infrastructure
cd infrastructure && python deploy_complete.py

# Update Lambda dashboard
./fix_api_gateway_comprehensive.sh
```

## 🔧 Configuration

Key configuration files:
- `config/integration_config.json` - System integration settings
- `deployment/agent-configs/` - Individual agent configurations
- `docker-compose.yml` - Local development setup

## 📈 Monitoring & Observability

The system includes comprehensive monitoring:
- Real-time dashboard with auto-refresh
- System health indicators
- Performance metrics
- Security compliance validation
- Automated testing frameworks

## 🔒 Security Features

- Contingent authorization integration
- Security compliance validation
- Penetration testing frameworks
- Threat intelligence generation
- IOC extraction and analysis

## 📚 Documentation

Comprehensive documentation available in `/docs/`:
- System Architecture Guide
- Agent Development Guide
- API Specifications
- Deployment & Maintenance Guide
- Troubleshooting Guide
- Security Testing Implementation

## 🧪 Testing

Multiple testing frameworks included:
- Unit and integration tests
- Security penetration testing
- Performance validation
- End-to-end system testing
- Automated test orchestration

## 🤝 Contributing

This is a research and development project for AI-powered cybersecurity systems. 

## 📄 License

This project is for research and educational purposes.

---

**Dashboard URL**: https://srms4z2ke7.execute-api.us-east-1.amazonaws.com/prod/

**Last Updated**: October 2025