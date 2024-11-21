import boto3
import json
from datetime import datetime

# Initialize the SNS client
sns_client = boto3.client('sns')

def lambda_handler(event, context):
    # Parse the incoming SNS message
    for record in event['Records']:
        sns_message = json.loads(record['Sns']['Message'])
        vehicle_number = sns_message['vehicle_number']
        maintenance_date_str = sns_message['maintenance_date']
        
        # Parse the maintenance date from the message
        maintenance_date = datetime.fromisoformat(maintenance_date_str)

        # Get today's date
        today = datetime.utcnow()

        # Calculate the date difference
        days_until_maintenance = (maintenance_date - today).days

        # If maintenance is within 5 days, send a follow-up SNS notification
        if days_until_maintenance <= 5:
            # Prepare the follow-up notification message
            message = {
                "vehicle_number": vehicle_number,
                "maintenance_date": maintenance_date.isoformat(),
                "days_until_maintenance": days_until_maintenance,
                "alert": "Maintenance is due within 5 days. Please schedule accordingly."
            }
            
            # Send a follow-up SNS notification (You can replace the ARN with your topic ARN)
            topic_arn = 'arn:aws:sns:us-east-1:073995508140:MaintenanceDueAlertTopic'  # Replace with your ARN
            response = sns_client.publish(
                TopicArn=topic_arn,
                Message=json.dumps(message),
                Subject="Vehicle Maintenance Due Alert"
            )

            print(f"Follow-up SNS notification sent for vehicle {vehicle_number}, response: {response}")

    return {
        'statusCode': 200,
        'body': json.dumps('Processed SNS message successfully')
    }
