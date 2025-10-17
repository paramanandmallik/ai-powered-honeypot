# AI-Powered Honeypot System - Architecture Diagrams

## System Overview Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           External Interfaces                                   │
├─────────────────┬─────────────────┬─────────────────┬─────────────────────────┤
│   Threat Feeds  │ Manual Triggers │ SIEM Integration│   Management Dashboard  │
│   (STIX/TAXII)  │   (SOC Team)    │   (Splunk/QRadar)│     (Web Interface)     │
└─────────┬───────┴─────────┬───────┴─────────┬───────┴─────────┬───────────────┘
          │                 │                 │                 │
          └─────────────────┼─────────────────┼─────────────────┘
                            │                 │
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        AgentCore Runtime Platform                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │
│  │ Detection   │  │ Coordinator │  │ Interaction │  │   Intelligence      │   │
│  │   Agent     │  │    Agent    │  │    Agent    │  │      Agent          │   │
│  │             │  │             │  │             │  │                     │   │
│  │ • Threat    │  │ • Honeypot  │  │ • Attacker  │  │ • Session Analysis  │   │
│  │   Analysis  │  │   Lifecycle │  │   Engagement│  │ • MITRE Mapping     │   │
│  │ • AI Models │  │ • Resource  │  │ • AI Personas│  │ • IOC Extraction    │   │
│  │ • Confidence│  │   Management│  │ • Synthetic │  │ • Report Generation │   │
│  │   Scoring   │  │ • Emergency │  │   Data Gen  │  │ • Trend Analysis    │   │
│  └─────────────┘  │   Shutdown  │  └─────────────┘  └─────────────────────┘   │
│                   └─────────────┘                                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                        AgentCore Runtime Services                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │
│  │ Message Bus │  │ Workflow    │  │ State Mgmt  │  │   Auto Scaling      │   │
│  │             │  │  Engine     │  │             │  │                     │   │
│  │ • Agent     │  │ • Process   │  │ • Agent     │  │ • Load Monitoring   │   │
│  │   Comm      │  │   Orchestr. │  │   Coord     │  │ • Instance Mgmt     │   │
│  │ • Event     │  │ • Workflow  │  │ • Session   │  │ • Resource Alloc    │   │
│  │   Routing   │  │   Triggers  │  │   State     │  │ • Performance Opt   │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           Honeypot Infrastructure                               │
├─────────────────┬─────────────────┬─────────────────┬─────────────────────────┤
│  Web Admin      │   SSH Server    │   Database      │    File Share           │
│   Portal        │   Honeypot      │   Honeypot      │    Honeypot             │
│                 │                 │                 │                         │
│ • Flask/FastAPI │ • Custom SSH    │ • MySQL Proxy   │ • SMB/FTP Server        │
│ • Fake Users    │ • Linux Sim     │ • Synthetic DB  │ • Fake Documents        │
│ • Auth System   │ • Command Sim   │ • Query Logging │ • Access Logging        │
│ • Session Mgmt  │ • File System   │ • Attack Detect │ • Metadata Tracking     │
└─────────────────┴─────────────────┴─────────────────┴─────────────────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            AWS Supporting Services                              │
├─────────────────┬─────────────────┬─────────────────┬─────────────────────────┤
│   S3 Storage    │   RDS Database  │   CloudWatch    │    VPC Network          │
│                 │                 │                 │                         │
│ • Session Logs  │ • Intelligence  │ • Metrics       │ • Network Isolation     │
│ • Transcripts   │ • Reports       │ • Alerts        │ • Security Groups       │
│ • Backups       │ • IOCs          │ • Dashboards    │ • Egress Filtering      │
│ • Archives      │ • Trends        │ • Monitoring    │ • Attack Detection      │
└─────────────────┴─────────────────┴─────────────────┴─────────────────────────┘
```