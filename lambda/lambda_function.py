import boto3
import datetime

def lambda_handler(event, context):
    # Initialize DynamoDB resource
    dynamodb = boto3.resource('dynamodb')
    vehicles_table = dynamodb.Table('vehicles')

    # Initialize SNS client
    sns_client = boto3.client('sns')
    sns_topic_arn = 'arn:aws:sns:us-east-1:180026181162:MaintenanceDueTopic'

    # Get today's date
    today = datetime.datetime.now().date()

    try:
        # Scan the table to get all vehicles
        response = vehicles_table.scan()
        vehicles = response.get('Items', [])

        for vehicle in vehicles:
            # Extract required details
            maintenance_date_str = vehicle.get('maintenance_date')
            vehicle_number = vehicle.get('vehicle_number')
            username = vehicle.get('username')

            if not maintenance_date_str or not vehicle_number or not username:
                continue

            # Parse maintenance date
            maintenance_date = datetime.datetime.strptime(maintenance_date_str.split('T')[0], '%Y-%m-%d').date()

            # Calculate days difference
            days_diff = (today - maintenance_date).days

            # Determine message type based on days difference
            if -5 <= days_diff <= 0:  # 5 days before or on the due date
                alert_message = (
                    f"Reminder: Vehicle {vehicle_number} maintenance is in {-days_diff} days, "
                    f"due on {maintenance_date_str}." if days_diff < 0 else
                    f"Reminder: Vehicle {vehicle_number} maintenance is today, due on {maintenance_date_str}."
                )
            elif 0 < days_diff <= 5:  # 5 days after the due date
                alert_message = (
                    f"Reminder: Vehicle {vehicle_number} maintenance was due {days_diff} days ago, "
                    f"on {maintenance_date_str}."
                )
            else:
                # Outside the range (-5 to 5), no alert needed
                continue

            # Publish message to SNS
            sns_client.publish(
                TopicArn=sns_topic_arn,
                Message=alert_message,
                Subject=f"Maintenance Reminder for Vehicle {vehicle_number}",
                MessageAttributes={
                    "username": {
                        "DataType": "String",
                        "StringValue": username
                    }
                }
            )
    except Exception as e:
        raise e