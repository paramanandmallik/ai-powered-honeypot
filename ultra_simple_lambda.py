def lambda_handler(event, context):
    """Ultra simple Lambda function for troubleshooting"""
    
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'text/html'
        },
        'body': '''<!DOCTYPE html>
<html>
<head>
    <title>Test Dashboard</title>
</head>
<body>
    <h1>Lambda Function is Working!</h1>
    <p>If you see this, the Lambda function is running correctly.</p>
    <p>Timestamp: 2025-01-18</p>
</body>
</html>'''
    }