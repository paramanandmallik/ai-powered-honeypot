# Figma Architecture Diagram Specification
## AI-Powered Honeypot System on AgentCore Runtime

### Canvas Setup
- **Canvas Size**: 1920x1080px (16:9 ratio - perfect for LinkedIn/social media)
- **Background**: White (#FFFFFF)
- **Grid**: 8px grid system
- **Margins**: 80px on all sides

### Typography System
- **Title Font**: Inter Bold, 32px, #232F3E (AWS Dark Blue)
- **Section Headers**: Inter SemiBold, 20px, #232F3E
- **Component Labels**: Inter Medium, 16px, #232F3E
- **Details**: Inter Regular, 12px, #5A6C7D

### Color Palette
- **AWS Orange**: #FF9900 (primary accent)
- **AWS Dark Blue**: #232F3E (text and borders)
- **AWS Light Blue**: #4B9CD3 (secondary accent)
- **Light Gray**: #F8F9FA (component backgrounds)
- **Medium Gray**: #E9ECEF (borders)
- **Success Green**: #28A745 (status indicators)

### Component Specifications

#### 1. Title Section (Top)
**Position**: X: 80, Y: 40
**Size**: 1760x80px
```
Text: "AI-Powered Honeypot System"
Font: Inter Bold, 32px, #232F3E
Alignment: Center

Subtitle: "Built on Amazon AgentCore Runtime"
Font: Inter Medium, 18px, #5A6C7D
Position: Below title, center aligned
```

#### 2. External Interfaces Layer
**Position**: X: 80, Y: 140
**Size**: 1760x120px
**Background**: #F8F9FA with 2px border #E9ECEF

```
Section Header: "External Interfaces"
Font: Inter SemiBold, 20px, #232F3E
Position: Top-left of section

Components (5 boxes, evenly spaced):
1. SIEM Integration (X: 120, Y: 180)
2. Threat Feeds (X: 420, Y: 180)
3. Manual Triggers (X: 720, Y: 180)
4. Management Dashboard (X: 1020, Y: 180)
5. Monitoring & Alerts (X: 1320, Y: 180)

Each box:
- Size: 200x60px
- Background: White
- Border: 2px solid #E9ECEF
- Corner radius: 8px
- Icon: 24x24px AWS icon (top-center)
- Label: Inter Medium, 14px, #232F3E (center)
```

#### 3. AgentCore Runtime Platform (Main Section)
**Position**: X: 80, Y: 300
**Size**: 1760x400px
**Background**: Linear gradient from #4B9CD3 to #2E86AB
**Border**: 3px solid #FF9900

```
Section Header: "AgentCore Runtime Platform"
Font: Inter Bold, 24px, White
Position: Top-center of section

Sub-section 1: Core AI Agents
Position: X: 120, Y: 350
Size: 1680x160px
Background: rgba(255,255,255,0.9)
Border radius: 12px

4 Agent Boxes (evenly spaced):
1. Detection Agent (X: 160, Y: 370)
2. Coordinator Agent (X: 520, Y: 370)
3. Interaction Agent (X: 880, Y: 370)
4. Intelligence Agent (X: 1240, Y: 370)

Each Agent Box:
- Size: 280x120px
- Background: White
- Border: 2px solid #FF9900
- Corner radius: 12px
- Shadow: 0 4px 8px rgba(0,0,0,0.1)

Agent Box Content:
- Icon: 32x32px at top-left
- Title: Inter Bold, 16px, #232F3E
- Bullet points: Inter Regular, 11px, #5A6C7D
- 4-5 bullet points per agent

Sub-section 2: Runtime Services
Position: X: 120, Y: 530
Size: 1680x120px
Background: rgba(255,255,255,0.8)
Border radius: 8px

5 Service Boxes (evenly spaced):
1. Message Bus
2. Workflow Engine
3. State Management
4. Auto Scaling
5. Security & Monitoring

Each Service Box:
- Size: 280x80px
- Background: White
- Border: 1px solid #E9ECEF
- Corner radius: 8px
```

#### 4. Honeypot Infrastructure Layer
**Position**: X: 80, Y: 740
**Size**: 1760x140px
**Background**: #F8F9FA with 2px border #E9ECEF

```
Section Header: "Honeypot Infrastructure"
Font: Inter SemiBold, 20px, #232F3E

5 Honeypot Boxes (evenly spaced):
1. Web Admin Portal
2. SSH Honeypot
3. Database Honeypot
4. File Share Honeypot
5. Email Honeypot

Each Honeypot Box:
- Size: 280x80px
- Background: White
- Border: 2px solid #28A745
- Corner radius: 8px
- Icon: 24x24px service icon
- Title: Inter Medium, 14px, #232F3E
- Details: Inter Regular, 10px, #5A6C7D
```

#### 5. AWS Supporting Services Layer
**Position**: X: 80, Y: 920
**Size**: 1760x120px
**Background**: #232F3E (AWS Dark Blue)

```
Section Header: "AWS Supporting Services"
Font: Inter SemiBold, 20px, White

5 AWS Service Boxes (evenly spaced):
1. S3 Storage
2. RDS Database
3. CloudWatch
4. VPC Network
5. SNS Notifications

Each AWS Box:
- Size: 280x80px
- Background: #FF9900 (AWS Orange)
- Corner radius: 8px
- AWS Icon: 24x24px white icon
- Title: Inter Bold, 14px, White
- Details: Inter Regular, 10px, rgba(255,255,255,0.9)
```

### Connection Arrows
**Style**: 3px solid #FF9900
**Arrow heads**: Triangular, 12px
**Connections**:
1. External Interfaces → AgentCore Platform (center to center)
2. AgentCore Platform → Honeypot Infrastructure (center to center)
3. Honeypot Infrastructure → AWS Services (center to center)
4. Bidirectional arrows between AI Agents (dashed, 2px, #4B9CD3)

### AWS Icons to Use (from Figma Community)
- **AgentCore**: AWS Lambda + AWS Batch
- **Detection Agent**: AWS SageMaker
- **Coordinator**: AWS Step Functions
- **Interaction**: AWS Bedrock
- **Intelligence**: AWS Comprehend
- **Message Bus**: Amazon SQS
- **Workflow**: AWS Step Functions
- **State Management**: Amazon DynamoDB
- **Auto Scaling**: AWS Auto Scaling
- **Web Honeypot**: Amazon EC2
- **SSH Honeypot**: AWS Systems Manager
- **Database**: Amazon RDS
- **File Share**: Amazon EFS
- **Email**: Amazon SES
- **S3**: Amazon S3
- **CloudWatch**: Amazon CloudWatch
- **VPC**: Amazon VPC
- **SNS**: Amazon SNS

### Export Settings for Social Media
1. **LinkedIn Post**: 1200x675px, PNG, 300 DPI
2. **Twitter**: 1200x675px, PNG, 300 DPI
3. **High Resolution**: 1920x1080px, PNG, 300 DPI
4. **Print Quality**: 1920x1080px, PDF, 300 DPI

### Step-by-Step Creation Process
1. Create new Figma file: "AI-Honeypot-Architecture"
2. Set canvas to 1920x1080px
3. Import AWS Architecture Icons from Figma Community
4. Create background layers with specified colors
5. Add text elements with specified typography
6. Place AWS icons in designated positions
7. Add connection arrows between layers
8. Apply shadows and effects as specified
9. Export in multiple formats for social media

This specification provides exact positioning, colors, fonts, and styling for a professional architecture diagram that will look great on LinkedIn and other social platforms.