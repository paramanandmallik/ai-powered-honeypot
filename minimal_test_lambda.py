def lambda_handler(event, context):
    """Absolute minimal Lambda function for testing"""
    return {
        'statusCode': 200,
        'body': 'Hello from Lambda!'
    }