# Project Context - AI-Powered Honeypot System

## CRITICAL: Service Being Used

**WE ARE BUILDING ON AMAZON BEDROCK AGENTCORE RUNTIME, NOT AMAZON BEDROCK**

- **Service**: Amazon Bedrock AgentCore Runtime
- **NOT**: Amazon Bedrock (the foundation model service)
- **AgentCore Runtime**: A separate service for deploying and managing AI agents
- **No Bedrock credentials needed**: AgentCore Runtime handles AI processing internally
- **No BedrockModel imports**: Use AgentCore's native capabilities

## Key Differences

### Amazon Bedrock AgentCore Runtime:
- Agent deployment and management platform
- Built-in AI processing capabilities
- Native messaging and workflow systems
- Automatic scaling and lifecycle management
- Uses `bedrock_agentcore.runtime` imports

### Amazon Bedrock (NOT what we're using):
- Foundation model service (Claude, Titan, etc.)
- Requires Bedrock credentials and model access
- Uses `boto3` and Bedrock API calls
- Direct model invocation

## Implementation Guidelines

1. **Use AgentCore SDK**: `from bedrock_agentcore.runtime import BedrockAgentCoreApp`
2. **No Bedrock imports**: Avoid `BedrockModel`, `boto3.client('bedrock')`
3. **Native AI processing**: Use AgentCore's built-in capabilities
4. **Agent deployment**: Deploy to AgentCore Runtime platform
5. **Messaging**: Use AgentCore's native messaging system

## Project Structure
- Building AI agents that run ON AgentCore Runtime
- Agents communicate through AgentCore messaging
- No direct Bedrock model calls needed
- Focus on agent logic and AgentCore integration