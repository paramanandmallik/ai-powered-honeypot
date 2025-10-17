---
inclusion: always
---

# AWS Documentation Validation Rules

## Core Principle
**ALWAYS validate against official AWS documentation before generating any AWS-related code.**

## Validation Requirements

### 1. AgentCore Runtime Implementation
- **MUST** follow the official AWS AgentCore Runtime patterns from `docs.aws.amazon.com/bedrock-agentcore/`
- **MUST** use the correct import: `from bedrock_agentcore import BedrockAgentCoreApp`
- **MUST** implement the `@app.entrypoint` decorator pattern
- **MUST** return JSON-serializable responses
- **MUST** handle the `payload` parameter correctly

### 2. Bedrock Integration
- **MUST** use proper Bedrock model IDs from official documentation
- **MUST** handle Bedrock authentication correctly
- **MUST** implement proper error handling for Bedrock API calls
- **MUST** use correct region configurations

### 3. Container Deployment
- **MUST** use ARM64 architecture for AgentCore Runtime
- **MUST** expose port 8080 for AgentCore Runtime
- **MUST** implement `/ping` endpoint for health checks
- **MUST** follow official Dockerfile patterns

### 4. SDK Usage
- **MUST** use official AWS SDKs and packages
- **MUST** follow semantic versioning for dependencies
- **MUST** implement proper credential handling

## Implementation Checklist

Before implementing any AWS service integration:

1. ✅ Check official AWS documentation
2. ✅ Verify SDK import patterns
3. ✅ Validate API call signatures
4. ✅ Confirm response formats
5. ✅ Test error handling scenarios
6. ✅ Verify authentication requirements

## Common Patterns to Follow

### AgentCore Runtime Entry Point
```python
from bedrock_agentcore import BedrockAgentCoreApp

app = BedrockAgentCoreApp()

@app.entrypoint
def invoke(payload):
    # Process payload
    return {"result": "response"}
```

### Bedrock Model Usage
```python
import boto3
client = boto3.client('bedrock-runtime', region_name='us-east-1')
```

### Error Handling
```python
try:
    # AWS API call
    pass
except ClientError as e:
    # Handle AWS-specific errors
    pass
```

## Validation Sources
- Primary: `docs.aws.amazon.com`
- Secondary: Official AWS GitHub repositories
- Tertiary: AWS SDK documentation

## Never Assume
- API signatures without checking documentation
- Default parameter values
- Error response formats
- Authentication requirements
- Regional availability