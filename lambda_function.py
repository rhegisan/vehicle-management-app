import json

def lambda_handler(event, context):
    # Log the incoming event (for debugging purposes)
    print("Received event:", json.dumps(event, indent=2))
    
    # Return a simple response
    response = {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda! Your request has been processed successfully.')
    }
    
    return response
