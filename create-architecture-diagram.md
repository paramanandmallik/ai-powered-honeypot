# Steps to Create Professional Architecture Diagram

## Option 1: Using Figma (Recommended for Social Media)

### Steps to Add Figma MCP Server to Kiro:

1. **Check Current MCP Configuration**
   ```bash
   # Check if Figma MCP is already configured
   cat ~/.kiro/settings/mcp.json
   # or
   cat .kiro/settings/mcp.json
   ```

2. **Add Figma MCP Server** (if not present)
   ```json
   {
     "mcpServers": {
       "figma": {
         "command": "uvx",
         "args": ["framelink-figma-mcp@latest"],
         "env": {
           "FIGMA_ACCESS_TOKEN": "your-figma-token"
         },
         "disabled": false,
         "autoApprove": ["get_figma_data", "download_figma_images"]
       }
     }
   }
   ```

3. **Get Figma Access Token**
   - Go to Figma → Settings → Account → Personal Access Tokens
   - Generate new token with file access permissions
   - Add token to MCP configuration

4. **Create Architecture Diagram in Figma**
   - Use AWS Architecture Icons library
   - Create professional layout with proper spacing
   - Export as high-resolution PNG/SVG

## Option 2: Using Draw.io/Diagrams.net MCP Server

### Steps to Add Draw.io MCP Server:

1. **Install Draw.io MCP Server**
   ```bash
   # This would need to be created or found
   uvx install mcp-drawio
   ```

2. **Add to MCP Configuration**
   ```json
   {
     "mcpServers": {
       "drawio": {
         "command": "uvx",
         "args": ["mcp-drawio@latest"],
         "disabled": false,
         "autoApprove": ["create_diagram", "export_diagram"]
       }
     }
   }
   ```

## Option 3: Manual Creation Guide

### Tools and Resources:
1. **AWS Architecture Icons**: https://aws.amazon.com/architecture/icons/
2. **Recommended Tools**:
   - Figma (Professional, collaborative)
   - Draw.io (Free, web-based)
   - Lucidchart (Professional)
   - Visio (Enterprise)

### Diagram Specifications for Social Media:
- **LinkedIn Post**: 1200x627px or 1080x1080px (square)
- **Twitter**: 1200x675px
- **General Social**: 1920x1080px (16:9)
- **Resolution**: 300 DPI for print quality
- **Format**: PNG with transparent background or white background

### Architecture Elements to Include:
1. **AgentCore Runtime Platform** (central focus)
2. **Four AI Agents** (Detection, Coordinator, Interaction, Intelligence)
3. **AWS Services** (S3, RDS, CloudWatch, VPC)
4. **Honeypot Infrastructure** (Web, SSH, Database, File Share)
5. **External Interfaces** (Threat Feeds, Management Dashboard)
6. **Data Flow Arrows** (showing communication paths)
7. **Security Boundaries** (VPC, network isolation)

## Current Status

Since the Figma MCP server requires proper authentication setup, I recommend:

1. **Immediate Solution**: I can create a detailed text-based diagram that you can use as a template
2. **Professional Solution**: Set up Figma MCP server with proper authentication
3. **Alternative**: Use the text diagram to create the visual in your preferred tool

Would you like me to:
- Create a detailed text-based architecture template?
- Help you set up the Figma MCP server?
- Generate the diagram specifications for manual creation?