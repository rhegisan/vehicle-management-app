import boto3

class Config:
    SECRET_KEY = 'mysecretkey'
    DEBUG = True
    

# # AWS DynamoDB setup (Make sure you have AWS credentials set up, or you can set them in environment variables)
#     dynamodb = boto3.resource('dynamodb', region_name='us-east-1')  # Choose your region
#     users_table = dynamodb.Table('users')
#     vehicles_table = dynamodb.Table('vehicles')
#     vehicle_service_history = dynamodb.Table('vehicle_service_history')

#     # AWS S3 setup
#     S3_BUCKET_NAME = 'rhegi'  # Replace with your S3 bucket name
#     S3_REGION = 'us-east-1'  # Use your region
#     s3_client = boto3.client('s3', region_name=S3_REGION)

#     # AWS Clients
#     sqs_client = boto3.client('sqs', region_name='us-east-1')
#     sns_client = boto3.client('sns', region_name='us-east-1')
#     lambda_client = boto3.client('lambda', region_name='us-east-1')
#     sqs_queue_url='https://sqs.us-east-1.amazonaws.com/073995508140/appointmentQueue'
