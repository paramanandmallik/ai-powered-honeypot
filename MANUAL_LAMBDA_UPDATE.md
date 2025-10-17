# Manual Lambda Function Update Instructions

## Problem
Getting 502 Bad Gateway error from API Gateway URL: https://srms4z2ke7.execute-api.us-east-1.amazonaws.com/prod/

## Solution
The Lambda function needs to be updated with working code. Since we can't deploy via CLI due to credentials, here's how to do it manually:

## Steps

### 1. Access AWS Lambda Console
1. Go to AWS Console → Lambda
2. Find function: `honeypot-dashboard-function`
3. Click on the function name

### 2. Update Function Code
1. In the Lambda function page, scroll down to "Code source"
2. Delete all existing code in the editor
3. Copy the entire contents of `lambda_function_fixed.py` from this directory
4. Paste it into the Lambda code editor
5. Make sure the file is named `lambda_function.py` (rename if needed)
6. Click "Deploy" button

### 3. Test the Function
1. Click "Test" button
2. Create a new test event with this JSON:
```json
{
  "httpMethod": "GET",
  "path": "/"
}
```
3. Run the test - should return status 200

### 4. Verify API Gateway
1. Visit: https://srms4z2ke7.execute-api.us-east-1.amazonaws.com/prod/
2. Should now show the working dashboard instead of 502 error

## What the Fixed Code Does
- Handles both GET and POST requests properly
- Returns proper HTTP responses with correct headers
- Includes error handling to prevent 502 errors
- Serves a beautiful dashboard HTML page
- Accepts data updates from detection agents

## Alternative: Use AWS CLI (if credentials work)
```bash
# Create deployment package
zip lambda_function.zip lambda_function_fixed.py

# Update function (rename file to lambda_function.py first)
aws lambda update-function-code \
    --function-name honeypot-dashboard-function \
    --zip-file fileb://lambda_function.zip \
    --region us-east-1
```

## Expected Result
After updating, the dashboard should load properly and show:
- AI-Powered Honeypot System title
- Live status indicator
- Statistics cards showing honeypot metrics
- Auto-refresh functionality

The 502 Bad Gateway error should be resolved.