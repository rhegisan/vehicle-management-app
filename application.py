from flask import Flask, render_template, request, redirect, url_for, flash, Response
import boto3
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.utils import secure_filename
from datetime import datetime
import bcrypt
import time
from botocore.exceptions import ClientError
import concurrent.futures
import json
import os
import zipfile
from decimal import Decimal
from vehicle_form_validator import FieldValidator
import logging
import watchtower

# Creating a application as function for wsgi to consider it as an entrypoint
def create_application():
    application = Flask(__name__)

    config = application.config.from_object('config.Config')

    # Configure logging to send logs to CloudWatch
    logger = logging.getLogger()
    # Configuring it to capture INFO, WARNING, ERROR and CRITICAL
    logger.setLevel(logging.INFO)

    # Create a CloudWatch log handler
    log_handler = watchtower.CloudWatchLogHandler(log_group='vehicles', stream_name='vehicles', boto3_client=boto3.client("logs", region_name="us-east-1"))

    # Add the handler to the logger
    logger.addHandler(log_handler)

    login_manager = LoginManager(application)
    # Redirects to the login page for unauthorized users
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access this page.'

    # Flask login manager to handle the login and to manage the session
    class User(UserMixin):
        def __init__(self, username, password=None, name=None, email=None, phone_number=None, role=None):
            self.id = username
            self.password = password
            self.name = name
            self.email = email
            self.phone_number = phone_number
            self.role = role # for checking whether it is admin or employee

        @staticmethod
        def get(username):
            response = users_table.get_item(Key={'username': username})
            if 'Item' in response:
                user_data = response['Item']
                return User(
                    username=user_data['username'], 
                    password=user_data['password'], 
                    role=user_data.get('role', 'employee')
                )
            return None
        def is_admin(self):
            return self.role == 'admin'
        
        @login_manager.user_loader
        def load_user(username):
            return User.get(username)


    # File Handling
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}

    # DynamoDB setup
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    users_table = dynamodb.Table('users')
    vehicles_table = dynamodb.Table('vehicles')
    vehicle_service_history = dynamodb.Table('vehicle_service_history')

    # S3 setup
    S3_BUCKET_NAME = 'rhegisan' 
    S3_REGION = 'us-east-1'
    s3_client = boto3.client('s3', region_name=S3_REGION)

    # SQS SETUP
    sqs_client = boto3.client('sqs', region_name='us-east-1')
    sqs_queue_url='https://sqs.us-east-1.amazonaws.com/180026181162/appointmentQueue'
    queue_name = 'appointmentQueue'

    # SNS SETUP
    sns_client = boto3.client('sns', region_name='us-east-1')
    sns_topic_name_maintenance = 'MaintenanceDueTopic'
    sns_topic_name_appointment = 'appointmentTopic'
    email_address = 'rhegisanjebas71@gmail.com'

    # CLOUDWATCH SETUP
    event_client = boto3.client('events', region_name='us-east-1')
    rule_name = 'DailyMaintenanceCheck'

    # LAMBDA SETUP
    lambda_client = boto3.client('lambda', region_name='us-east-1')
    lambda_arn = 'arn:aws:lambda:us-east-1:180026181162:function:VehicleMaintenanceLambda'


    # Check if file type is allowed
    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

    # Function to check if tables exist and create them if not
    def create_tables_if_not_exist():
        client = boto3.client('dynamodb', region_name='us-east-1')

        # Check if 'users' table exists
        try:
            client.describe_table(TableName='users')
            logger.info("Table 'users' already exists.")
        except client.exceptions.ResourceNotFoundException:
            logger.info("Table 'users' does not exist. Creating table...")
            client.create_table(
                TableName='users',
                KeySchema=[{'AttributeName': 'username', 'KeyType': 'HASH'}],  # Partition key
                AttributeDefinitions=[
                    {'AttributeName': 'username', 'AttributeType': 'S'}
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )

        try:
            client.describe_table(TableName='vehicles')
            logger.info("Table 'vehicles' already exists.")
        except client.exceptions.ResourceNotFoundException:
            logger.info("Table 'vehicles' does not exist. Creating table...")

            client.create_table(
                TableName='vehicles',
                KeySchema=[
                    {'AttributeName': 'vehicle_number', 'KeyType': 'HASH'},  # Partition key
                    {'AttributeName': 'username', 'KeyType': 'RANGE'}  # Sort key (username)
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'vehicle_number', 'AttributeType': 'S'},
                    {'AttributeName': 'username', 'AttributeType': 'S'},
                    {'AttributeName': 'maintenance_date', 'AttributeType': 'S'},
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                },
                GlobalSecondaryIndexes=[
                    {
                        'IndexName': 'username-index',  # GSI name for querying by username
                        'KeySchema': [
                            {'AttributeName': 'username', 'KeyType': 'HASH'}  # GSI partition key
                        ],
                        'Projection': {
                            'ProjectionType': 'ALL'  # Include all attributes in the GSI projection
                        },
                        'ProvisionedThroughput': {
                            'ReadCapacityUnits': 5,
                            'WriteCapacityUnits': 5
                        }
                    },
                    {
                        'IndexName': 'MaintenanceDateIndex',
                        'KeySchema': [
                            {
                                'AttributeName': 'maintenance_date',
                                'KeyType': 'HASH'  # maintenance_date the partition key for the GSI
                            },
                        ],
                        'Projection': {
                            'ProjectionType': 'ALL'  # Include all attributes in the projection
                        },
                        'ProvisionedThroughput': {
                            'ReadCapacityUnits': 5,
                            'WriteCapacityUnits': 5
                        }
                    }
                ]
            )
            # Check if 'vehicle_service_history' table exists
        try:
            client.describe_table(TableName='vehicle_service_history')
            logger.info("Table 'vehicle_service_history' already exists.")
        except client.exceptions.ResourceNotFoundException:
            logger.info("Table 'vehicle_service_history' does not exist. Creating table...")
            client.create_table(
                TableName='vehicle_service_history',
                KeySchema=[
                    {'AttributeName': 'vehicle_number', 'KeyType': 'HASH'}# Partition key
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'vehicle_number', 'AttributeType': 'S'}
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )
            
            client.get_waiter('table_exists').wait(TableName='users')
            logger.info("Table 'users' created successfully.")
            client.get_waiter('table_exists').wait(TableName='vehicles')
            logger.info("Table 'vehicles' created successfully.")
            client.get_waiter('table_exists').wait(TableName='vehicle_service_history')
            logger.info("Table 'vehicle_service_history' created successfully.")

    # Function to check that the S3 bucket exists, and create it if donnot exist
    def ensure_bucket_exists():
        try:
            s3_client.head_bucket(Bucket=S3_BUCKET_NAME)
            logger.info(f"Bucket {S3_BUCKET_NAME} already exists.")
        except s3_client.exceptions.ClientError:
            logger.info(f"Bucket {S3_BUCKET_NAME} does not exist. Creating bucket...")
            if S3_REGION == 'us-east-1':
                try:
                    s3_client.create_bucket(Bucket=S3_BUCKET_NAME)
                    logger.info(f"Bucket {S3_BUCKET_NAME} created successfully in {S3_REGION} region.")
                except ClientError as e:
                    logger.info(f"Error creating bucket: {e}")
                    retry_on_error()
            else:
                try:
                    s3_client.create_bucket(
                        Bucket=S3_BUCKET_NAME)
                    logger.info(f"Bucket {S3_BUCKET_NAME} created successfully in {S3_REGION} region.")
                except ClientError as e:
                    logger.info(f"Error creating bucket: {e}")
                    retry_on_error()

    def retry_on_error(max_retries=5, delay=2):
        attempts = 0
        while attempts < max_retries:
            time.sleep(delay)  # Delay before retry
            logger.info(f"Retrying in {delay} seconds...")
            attempts += 1
            try:
                ensure_bucket_exists()  # Try creating the bucket again
                break  # Exit the loop if successful
            except ClientError as e:
                if attempts == max_retries:
                    logger.info(f"Failed to create the bucket after {max_retries} attempts.")
                    break  # Exit the loop after max retries
                continue  # Retry on failure

    # Check whether sqs_queue exists if not then create
    def check_or_create_sqs_queue():
        try:
            # Trying to get the queue URL to check if the queue exists
            sqs_client.get_queue_url(QueueName=queue_name)
            logger.info(f"SQS Queue '{queue_name}' already exists.")
        except sqs_client.exceptions.QueueDoesNotExist:
            logger.info(f"SQS Queue '{queue_name}' does not exist. Creating it...")
            response = sqs_client.create_queue(QueueName=queue_name)
            queue_url = response['QueueUrl']
            
            # Poll to confirm that the queue has been created
            logger.info(f"Waiting for SQS Queue '{queue_name}' to be created...")
            confirm_creation = False
            retries = 0
            while retries < 5 and not confirm_creation:
                try:
                    sqs_client.get_queue_url(QueueName=queue_name)
                    logger.info(f"SQS Queue '{queue_name}' created successfully.")
                    confirm_creation = True
                except sqs_client.exceptions.QueueDoesNotExist:
                    time.sleep(2)  # Wait before retrying
                    retries += 1
                    if retries == 5:
                        logger.info("SQS Queue creation failed after 5 retries.")

    def check_or_create_sns_maintenanceDueTopic():
        try:
            # Try to get the topic's attributes to check if it exists
            sns_client.get_topic_attributes(TopicArn=f'arn:aws:sns:us-east-1:180026181162:{sns_topic_name_maintenance}')
            logger.info(f"SNS Topic '{sns_topic_name_maintenance}' already exists.")
        except sns_client.exceptions.NotFoundException:
            logger.info(f"SNS Topic '{sns_topic_name_maintenance}' does not exist. Creating it...")
            response = sns_client.create_topic(Name=sns_topic_name_maintenance)
            topic_arn = response['TopicArn']
            
            # Poll to confirm the SNS topic is created
            logger.info(f"Waiting for SNS Topic '{sns_topic_name_maintenance}' to be created...")
            confirm_creation = False
            retries = 0
            while retries < 5 and not confirm_creation:
                try:
                    sns_client.get_topic_attributes(TopicArn=topic_arn)
                    logger.info(f"SNS Topic '{sns_topic_name_maintenance}' created successfully.")
                    confirm_creation = True
                except sns_client.exceptions.NotFoundException:
                    time.sleep(2)  # Wait before retrying
                    retries += 1
                    if retries == 5:
                        logger.info("SNS Topic creation failed after 5 retries.")

    def check_or_create_sns_appointmentTopic():
        
        try:
            # Try to get the topic's attributes to check if it exists
            sns_client.get_topic_attributes(TopicArn=f'arn:aws:sns:us-east-1:180026181162:{sns_topic_name_appointment}')
            logger.info(f"SNS Topic '{sns_topic_name_appointment}' already exists.")
        except sns_client.exceptions.NotFoundException:
            logger.info(f"SNS Topic '{sns_topic_name_appointment}' does not exist. Creating it...")
            response = sns_client.create_topic(Name=sns_topic_name_appointment)
            topic_arn = response['TopicArn']
            
            # Poll to confirm the SNS topic is created
            logger.info(f"Waiting for SNS Topic '{sns_topic_name_appointment}' to be created...")
            confirm_creation = False
            retries = 0
            while retries < 5 and not confirm_creation:
                try:
                    sns_client.get_topic_attributes(TopicArn=topic_arn)
                    logger.info(f"SNS Topic '{sns_topic_name_appointment}' created successfully.")
                    confirm_creation = True
                except sns_client.exceptions.NotFoundException:
                    time.sleep(2)  # Wait before retrying
                    retries += 1
                    if retries == 5:
                        logger.info("SNS Topic creation failed after 5 retries.")

    def zip_lambda_function(source_dir, output_zip):
        # Zips the contents of a directory for Lambda deployment.
        with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(source_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, start=source_dir)
                    zipf.write(file_path, arcname)

    def check_or_create_lambda_function():
        function_name = 'VehicleMaintenanceLambda'
        try:
            # Check if the Lambda function exists
            lambda_client.get_function(FunctionName=function_name)
            logger.info(f"Lambda function '{function_name}' already exists.")
        except lambda_client.exceptions.ResourceNotFoundException:
            logger.info(f"Lambda function '{function_name}' does not exist. Creating it...")
            
            # Path to Lambda code
            source_dir = './lambda' 
            output_zip = 'lambda_function.zip'

            # Zip the Lambda function code
            zip_lambda_function(source_dir, output_zip)
            
            # Read zip file for Lambda function creation
            with open(output_zip, 'rb') as zip_file:
                zip_data = zip_file.read()

            # Create the Lambda function
            response = lambda_client.create_function(
                FunctionName=function_name,
                Runtime='python3.11',
                Role='arn:aws:iam::180026181162:role/LabRole',
                Handler='lambda_function.lambda_handler',
                Code={'ZipFile': zip_data},
                Timeout=30,
                MemorySize=128
            )
            logger.info(f"Lambda function '{function_name}' created. Waiting for confirmation...")

            # Poll to confirm that the Lambda function is created
            confirm_creation = False
            retries = 0
            while retries < 5 and not confirm_creation:
                try:
                    lambda_client.get_function(FunctionName=function_name)
                    logger.info(f"Lambda function '{function_name}' created successfully.")
                    confirm_creation = True
                except lambda_client.exceptions.ResourceNotFoundException:
                    time.sleep(2)  # Wait before retrying
                    retries += 1
                    if retries == 5:
                        logger.error("Lambda function creation failed after 5 retries.")
        else:
            # Update the existing Lambda function code
            logger.info(f"Updating code for Lambda function '{function_name}'...")
            
            # Path to Lambda code
            source_dir = './lambda'  # Replace with your Lambda code directory
            output_zip = 'lambda_function.zip'

            # Zip the Lambda function code
            zip_lambda_function(source_dir, output_zip)
            
            # Read zip file for updating the Lambda function code
            with open(output_zip, 'rb') as zip_file:
                zip_data = zip_file.read()
            
            response = lambda_client.update_function_code(
                FunctionName=function_name,
                ZipFile=zip_data
            )
            logger.info(f"Lambda function '{function_name}' code updated successfully.")

    # def subscribe_to_sns(topic_arn, lambda_function_arn, email_address):
    #     """
    #     Subscribes both the Lambda function and email address to the given SNS topic if they are not already subscribed.
    #     Uses retry logic for both Lambda function and email.
    #     """
    #     retries = 0

    #     # Retry loop for subscribing both Lambda and Email
    #     while retries < 5:
    #         try:
    #             # Check if Lambda is already subscribed
    #             lambda_subscribed = False
    #             subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=topic_arn)['Subscriptions']
    #             for subscription in subscriptions:
    #                 if subscription['Endpoint'] == lambda_function_arn:
    #                     lambda_subscribed = True
    #                     logger.info(f"Lambda function {lambda_function_arn} is already subscribed.")
    #                     break

    #             if not lambda_subscribed:
    #                 # If not subscribed, attempt to subscribe the Lambda function
    #                 sns_client.subscribe(
    #                     TopicArn=topic_arn,
    #                     Protocol='lambda',
    #                     Endpoint=lambda_function_arn
    #                 )
    #                 logger.info(f"Lambda function {lambda_function_arn} successfully subscribed to SNS topic.")

    #             # Check if Email is already subscribed
    #             email_subscribed = False
    #             for subscription in subscriptions:
    #                 if subscription['Endpoint'] == email_address:
    #                     email_subscribed = True
    #                     logger.info(f"Email address {email_address} is already subscribed.")
    #                     break

    #             if not email_subscribed:
    #                 # If not subscribed, attempt to subscribe the email address
    #                 sns_client.subscribe(
    #                     TopicArn=topic_arn,
    #                     Protocol='email',
    #                     Endpoint=email_address
    #                 )
    #                 logger.info(f"Email address {email_address} successfully subscribed to SNS topic.")

    #             # If both subscriptions are successful, break out of the retry loop
    #             break

    #         except Exception as e:
    #             retries += 1
    #             logger.info(f"Error subscribing Lambda or Email to SNS topic (Attempt {retries}): {e}")
    #             time.sleep(2)  # Retry after a brief pause

    #     if retries == 5:
    #         logger.info("Failed to subscribe Lambda function or Email address after 5 attempts.")

    def create_cloudwatch_rule():

        # Check if the rule already exists
        try:
            response = event_client.describe_rule(Name=rule_name)
            logger.info(f"CloudWatch rule '{rule_name}' already exists.")
            rule_arn = response['Arn']
            logger.info(f"Rule ARN: {rule_arn}")
        except event_client.exceptions.ResourceNotFoundException:
            # Rule doesn't exist, so we need to create it
            logger.info(f"CloudWatch rule '{rule_name}' does not exist. Creating it now.")
            
            # Create a CloudWatch Rule that triggers every 24 hours
            rule_response = event_client.put_rule(
                Name=rule_name,
                ScheduleExpression='rate(24 hours)',
                State='ENABLED',
            )
            
            rule_arn = rule_response['RuleArn']
            logger.info(f"CloudWatch rule created with ARN: {rule_arn}")
            
            # Attach Lambda function as target for CloudWatch rule
            event_client.put_targets(
                Rule=rule_name,
                Targets=[
                    {
                        'Id': '1',
                        'Arn': 'arn:aws:lambda:us-east-1:180026181162:function:VehicleMaintenanceLambda',
                    },
                ]
            )


    # Function to ensure that all the aws resources/services exist before running the application
    def setup_resources():

        # Using ThreadPoolExecutor for concurrent execution of AWS resource setup tasks
        # To ensure that different resources are checked or created in parallel to improve efficiency.
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            futures.append(executor.submit(check_or_create_lambda_function))
            futures.append(executor.submit(create_tables_if_not_exist)) 
            futures.append(executor.submit(ensure_bucket_exists))
            futures.append(executor.submit(check_or_create_sns_maintenanceDueTopic))
            futures.append(executor.submit(check_or_create_sns_appointmentTopic))
            futures.append(executor.submit(create_cloudwatch_rule))
            futures.append(executor.submit(check_or_create_sqs_queue))
            # futures.append(executor.submit(subscribe_to_sns, sns_topic_name_maintenance, lambda_arn, email_address))
            # Wait for all the tasks to complete (block execution until all tasks are done)
            for future in futures:
                future.result()

    # Call this function ensure that all the aws resources/services exist before running the application
    setup_resources()

    # Function to generate presigned URL for an image
    def generate_presigned_url(bucket_name, object_key, expiration=3600):
        try:
            response = s3_client.generate_presigned_url('get_object',
                                                        Params={'Bucket': bucket_name, 'Key': object_key},
                                                        ExpiresIn=expiration)
        except ClientError as e:
            logger.error(f"Error generating presigned URL: {e}")
            return None
        return response


    def send_sns_notification(topic_arn="arn:aws:sns:us-east-1:180026181162:appointmentTopic", message="", subject="Notification"):
        try:
            topic_arn = ''
            # Send the message to the SNS Topic
            response = sns_client.publish(
                TopicArn=topic_arn,
                Message=json.dumps(message),
                Subject=subject
            )
            
            logger.info(f"SNS notification sent, response: {response}")
        except Exception as e:
            logger.error(f"Error sending SNS notification: {e}")

    def delete_file_from_s3(filename):
        try:
            s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=filename)
            logger.info(f"Deleted {filename} from S3.")
        except Exception as e:
            logger.error(f"Error deleting file {filename} from S3: {e}")


    @application.route('/', methods=['GET', 'POST'])
    def landing_page():
        # Initialize form data and error messages
        error_messages = {}
        form_data = {
            'full_name': '',
            'vehicle_number': '',
            'vehicle_type': '',
            'vehicle_make': '',
            'vehicle_model': '',
            'maintenance_date': '',
            'email': '',
            'phone': ''
        }

        if request.method == 'POST':
            # Capture appointment details from the form
            name = form_data['full_name'] = request.form['full_name']
            form_data['vehicle_number'] = request.form['vehicle_number']
            form_data['vehicle_type'] = request.form['vehicle_type']
            form_data['vehicle_make'] = request.form['vehicle_make']
            form_data['vehicle_model'] = request.form['vehicle_model']
            form_data['maintenance_date'] = request.form['maintenance_date']
            form_data['email'] = request.form['email']
            form_data['phone'] = request.form['phone']

            # Validate Full Name
            if not FieldValidator.validate_full_name(form_data['full_name']):
                error_messages['full_name'] = 'Invalid full name. Name should be alphabetic and properly formatted. John Doe'

            # Validate Email
            if not FieldValidator.validate_email(form_data['email']):
                error_messages['email'] = 'Invalid email address. Email must be in format x@x.x'

            # Validate Phone Number
            if not FieldValidator.validate_phone_number(form_data['phone'], country_code='IE'):
                error_messages['phone'] = 'Invalid phone number format. Example: +353123456789 or 0123456789.'

            # Validate Vehicle Number
            if not FieldValidator.validate_vehicle_number(form_data['vehicle_number']):
                error_messages['vehicle_number'] = "Invalid vehicle number, the format must be XX-XX-1234 (e.g., AB-01-1234)"
            
            # Validate Vehicle Type
            if not FieldValidator.validate_vehicle_type(form_data['vehicle_type']):
                error_messages['vehicle_type'] = "Invalid vehicle type. Please choose a valid type. 'car', 'truck', 'motorcycle', 'bus', 'van', 'bike', 'cycle', 'train']"
            
            # Validate Vehicle Make
            if not FieldValidator.validate_vehicle_make(form_data['vehicle_make']):
                error_messages['vehicle_make'] = "Vehicle make must contain only alphabetic characters."
            
            # Validate Vehicle Model
            if not FieldValidator.validate_vehicle_model(form_data['vehicle_model']):
                error_messages['vehicle_model'] = "Vehicle model must be between 1 and 20 characters."

            # If there are validation errors, render the form again with the error messages
            if error_messages:
                return render_template('landing_page.html', error_messages=error_messages, form_data=form_data)

            # Create the appointment details message
            appointment_message = {
                'customer_fullname': form_data['full_name'],
                'vehicle_number': form_data['vehicle_number'],
                'vehicle_type': form_data['vehicle_type'],
                'vehicle_make': form_data['vehicle_make'],
                'vehicle_model': form_data['vehicle_model'],
                'maintenance_date': form_data['maintenance_date'],
                'customer_email': form_data['email'],
                'customer_phone': form_data['phone']
            }

            # Send appointment to SQS
            sqs_client.send_message(
                QueueUrl=sqs_queue_url,
                MessageBody=json.dumps(appointment_message)
            )

            logger.info(f"A new appointment data has been sent to SQS, customer name - {name}")

            # Send SNS notification (email to the company)
            sns_client.publish(
                TopicArn='arn:aws:sns:us-east-1:180026181162:appointmentTopic',
                Message=json.dumps(appointment_message),
                Subject="New Appointment Request"
            )

            logger.info(f"A new appointment data has been sent to SNS topic, customer name - {name}")

            # Flash success message and redirect to the same page
            flash('Appointment request submitted successfully! We will contact you soon.', 'success')
            return redirect(url_for('landing_page'))  # Redirect to the landing page (root route)

        # Render the form with any error messages or pre-filled data
        return render_template('landing_page.html', error_messages=error_messages, form_data=form_data)

    # To download the appointments from the queue in a txt file
    @application.route('/appointments', methods=['GET'])
    @login_required
    def appointments():
        try:
            # Fetch messages from SQS
            response = sqs_client.receive_message(
                QueueUrl=sqs_queue_url,
                MaxNumberOfMessages=10,  # Fetch up to 10 messages
                WaitTimeSeconds=10        # Enable long polling
            )

            appointments = []
            if 'Messages' in response:
                for message in response['Messages']:
                    body = json.loads(message['Body'])  # Parse JSON body
                    appointments.append(body)

                    # Optionally delete the message after fetching
                    sqs_client.delete_message(
                        QueueUrl=sqs_queue_url,
                        ReceiptHandle=message['ReceiptHandle']
                    )

            # Convert the appointments list to JSON format (pretty-printed)
            json_data = json.dumps(appointments, indent=2)

            # Create a response with the JSON data as a .txt file
            response = Response(json_data, mimetype='text/plain')
            response.headers['Content-Disposition'] = 'attachment; filename=appointments.txt'

            # Return the text file to the user
            return response

        except Exception as e:
            logger.error(f"Error downloading appointments: {e}")
            return "Failed to download appointments data."


    # Route for creating a new user which is accessible only to admin
    @application.route('/signup', methods=['GET', 'POST'])
    @login_required
    def signup():
        error_messages = {}

        # Checking the user
        # Only admin can view/edit the signup page
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('landing_page'))
        
        if request.method == 'POST':
            username = request.form['username']
            full_name = request.form['full_name']
            email = request.form['email']
            phone_number = request.form['phone_number']
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            role = request.form['role']

            # Validate Full Name
            if not FieldValidator.validate_full_name(full_name):
                error_messages['full_name'] = 'Invalid full name. Name should be alphabetic and properly formatted. John Doe'

            # Validate Email
            if not FieldValidator.validate_email(email):
                error_messages['email'] = 'Invalid email address. Email must be in format x@x.x'

            # Validate Phone Number
            if not FieldValidator.validate_phone_number(phone_number, country_code='IE'):
                error_messages['phone_number'] = 'Invalid phone number format. Example: +353123456789 or 0123456789.'

            # Validate Password
            if password != confirm_password:
                error_messages['confirm_password'] = 'Passwords do not match!'
            
            is_valid, message = FieldValidator.validate_password(password, confirm_password)
            if not is_valid:
                error_messages['password'] = message

            # If there are errors, render the form again
            if error_messages:
                return render_template('signup.html', error_messages=error_messages)

            # Proceed with the rest of the logic (e.g., creating user, saving to DB, etc.)
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            user_item = {
                'username': username,
                'password': boto3.dynamodb.types.Binary(hashed_password),
                'full_name': full_name,
                'email': email,
                'phone_number': phone_number,
                'role': role
            }

            # Store the user in DynamoDB
            users_table.put_item(Item=user_item)

            logger.info(f"Successfully Signed in {username}")
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))

        return render_template('signup.html', error_messages=error_messages)


    # Route for editing the profile #custom library used here
    @application.route('/edit_profile', methods=['GET', 'POST'])
    @login_required
    def edit_profile():
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('landing_page'))
        
        error_messages = {}  # Dictionary to hold error messages
        
        if request.method == 'POST':
            full_name = request.form['full_name']
            email = request.form['email']
            phone_number = request.form['phone_number']
            new_password = request.form['password']
            confirm_password = request.form['confirm_password']
            role = request.form['role']
            
            # Validate full name
            if not FieldValidator.validate_full_name(full_name):
                error_messages['full_name'] = 'Invalid full name. Name should only contain letters and spaces, and each part should start with a capital letter e.g., John Doe.'
            
            # Validate email
            if not FieldValidator.validate_email(email):
                error_messages['email'] = 'Invalid email address. Email must be in format x@x.x'

            # Validate phone number
            if not FieldValidator.validate_phone_number(phone_number, country_code='IE'):
                error_messages['phone_number'] = 'Invalid phone number format. Example: +353123456789 or 0123456789.'

            # Check if passwords match
            if new_password and new_password != confirm_password:
                error_messages['password'] = 'Passwords do not match!'

            # Check password strength if a new password is provided
            if new_password:
                is_valid, message = FieldValidator.validate_password(new_password, confirm_password)
                if not is_valid:
                    error_messages['password'] = message

            if error_messages:
                return render_template('edit_profile.html', 
                                    full_name=full_name, email=email, phone_number=phone_number, 
                                    role=role, error_messages=error_messages)
            
            # Hash the new password if provided
            if new_password:
                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            
            # Update the user's profile in DynamoDB
            update_expression = "SET full_name = :full_name, email = :email, phone_number = :phone_number, #role = :role"
            expression_values = {
                ':full_name': full_name,
                ':email': email,
                ':phone_number': phone_number,
                ':role': role
            }

            # If a new password is provided, update it as well
            if new_password:
                update_expression += ", password = :password"
                expression_values[':password'] = boto3.dynamodb.types.Binary(hashed_password)


            # Add expression attribute names for reserved words
            expression_attribute_names = {
                '#role': 'role'  # Mapping placeholder to the actual reserved keyword 'role'
        }
            
            try:
                # Perform the update in DynamoDB
                users_table.update_item(
                    Key={'username': current_user.id},
                    UpdateExpression=update_expression,
                    ExpressionAttributeValues=expression_values,
                    ExpressionAttributeNames=expression_attribute_names  # Add this mapping
                )
                logger.info(f"Profile updated for user {current_user.id} successfully!")
                flash('Profile updated successfully!', 'success')
                return redirect(url_for('home'))
            except Exception as e:
                logger.error(f"Error updating profile: {e}")
                flash('An error occurred while updating your profile.', 'danger')
                return redirect(url_for('edit_profile'))
        
        # Fetch the current user's information from DynamoDB
        try:
            user = users_table.get_item(Key={'username': current_user.id})['Item']
        except Exception as e:
            logger.error(f"Error fetching user data: {e}")
            flash('Error fetching your data. Please try again later.', 'danger')
            return redirect(url_for('home'))

        # Pass the current values of full_name, email, phone_number to the template
        return render_template('edit_profile.html', 
                           username=user['username'], 
                           full_name=user['full_name'], 
                           email=user['email'], 
                           phone_number=user['phone_number'],
                           role=user['role'],
                           error_messages={})


    # Login Route
    @application.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            # Retrieve user from the database
            user = User.get(username)
            if user and bcrypt.checkpw(password.encode('utf-8'), user.password.value):
                login_user(user)  # Pass the `User` object
                logger.info(f"{user} Successfully logged in")
                flash('Login successful!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid username or password', 'danger')

        return render_template('login.html')


    @application.route('/home', methods=['GET', 'POST'])
    @login_required
    def home():
        # Fetch vehicles linked to the current user
        response = vehicles_table.query(
            IndexName='username-index',  # Using the GSI on 'username'
            KeyConditionExpression=boto3.dynamodb.conditions.Key('username').eq(current_user.id)
        )

        vehicles = response.get('Items', [])

        # Generate presigned URL for each vehicle's bill image and add it to the vehicle dict
        for vehicle in vehicles:
            if vehicle.get('bill_image'):
                # Generate the presigned URL for the bill image (if it exists)
                vehicle['image_url'] = generate_presigned_url(S3_BUCKET_NAME, vehicle['bill_image'])

            # Add the link to the service history page for each vehicle
            vehicle['service_history_url'] = url_for('view_service_history', vehicle_number=vehicle['vehicle_number'])

        # Pass the vehicles (with image_url and service_history_url) to the template
        return render_template('home.html', vehicles=vehicles)


    # Logout Route
    @application.route('/logout')
    def logout():
        logout_user()
        flash('You have been logged out.', 'info')
        return redirect(url_for('login'))

    # Function to upload files to S3
    def upload_file_to_s3(file):
        # Uploading a single file to S3 and returns the file path.
        # Generate a secure filename
        filename = secure_filename(file.filename)

        # User-specific S3 path (create a path with the username)
        s3_user_folder = f'users/{current_user.id}/bills/{filename}'
        
        try:
            # Upload the file to S3
            s3_client.upload_fileobj(file, S3_BUCKET_NAME, s3_user_folder)
            logger.info(f"Successfully uploaded {filename} to S3 at {s3_user_folder}")
            return s3_user_folder
        except Exception as e:
            logger.error(f"Error uploading file to S3: {e}")
            return None

    # Vehicle Maintenance Route
    @application.route('/vehicle', methods=['GET', 'POST'])
    @login_required
    def vehicle():
        error_messages = {}
        if request.method == 'POST':
            vehicle_number = request.form['vehicle_number']
            vehicle_type = request.form['vehicle_type']
            vehicle_make = request.form['vehicle_make']
            vehicle_model = request.form['vehicle_model']
            license_plate_number = request.form['license_plate_number']
            maintenance_date = datetime.strptime(request.form['maintenance_date'], '%Y-%m-%d')

            # Validate fields using your custom validator
            if not FieldValidator.validate_vehicle_number(vehicle_number):
                error_messages['vehicle_number'] = "Invalid vehicle number, the format must be XX-XX-1234 (e.g., AB-01-1234)"
            
            if not FieldValidator.validate_vehicle_type(vehicle_type):
                error_messages['vehicle_type'] = "Invalid vehicle type. Please choose a valid type. 'car', 'truck', 'motorcycle', 'bus', 'van', 'bike', 'cycle', 'train']"
            
            if not FieldValidator.validate_vehicle_make(vehicle_make):
                error_messages['vehicle_make'] = "Vehicle make must contain only alphabetic characters."
            
            if not FieldValidator.validate_vehicle_model(vehicle_model):
                error_messages['vehicle_model'] = "Vehicle model must be between 1 and 20 characters."
            
            if not FieldValidator.validate_license_plate(license_plate_number):
                error_messages['license_plate_number'] = "Invalid license plate number. Format should be '1234567' or 'ABC-1234' or 'ABC 1234' "

            if error_messages:
                # If there are validation errors, render the form again with error messages
                return render_template('vehicle.html', error_messages=error_messages)
            
            # Handle the bill image upload
            bill_image_filename = None
            if 'bill_image' in request.files:
                bill_image = request.files['bill_image']
                if bill_image and allowed_file(bill_image.filename):
                    # Upload the bill image to S3 and get the S3 path
                    bill_image_filename = upload_file_to_s3(bill_image)
                    if bill_image_filename:
                        flash(f"Bill image uploaded successfully to S3: {bill_image_filename}", 'success')
                    else:
                        flash('Error uploading bill image to S3.', 'danger')

            # Create new vehicle entry in DynamoDB
            vehicles_table.put_item(
                Item={
                    'vehicle_number': vehicle_number,  # Use the vehicle number as the primary key
                    'license_plate_number': license_plate_number,
                    'username': current_user.id,
                    'vehicle_type': vehicle_type,
                    'vehicle_make': vehicle_make,
                    'vehicle_model': vehicle_model,
                    'maintenance_date': maintenance_date.isoformat(),
                    'bill_image': bill_image_filename,  # Store the S3 file path for the bill image
                }
            )

            # Generate the presigned URL for the uploaded bill image (if it exists)
            image_url = None
            if bill_image_filename:
                image_url = generate_presigned_url(S3_BUCKET_NAME, bill_image_filename)

            logger.info(f"Successfully added Vehicle maintenance details of vehicle {vehicle_number}")
            flash('Vehicle maintenance details added successfully!', 'success')
            return redirect(url_for('home'))

        return render_template('vehicle.html', error_messages=error_messages)


    @application.route('/edit_vehicle/<vehicle_number>', methods=['GET', 'POST'])
    @login_required
    def edit_vehicle(vehicle_number):
        error_messages = {}
        # Fetch the vehicle details from DynamoDB using the vehicle_number and username (current_user.id)
        response = vehicles_table.get_item(Key={'vehicle_number': vehicle_number, 'username': current_user.id})
        vehicle = response.get('Item')

        if not vehicle:
            flash('Vehicle not found!', 'danger')
            return redirect(url_for('home'))  # Redirect to home if vehicle is not found

        error_messages = {}

        if request.method == 'POST':
            # Get the updated details from the form
            vehicle_type = request.form['vehicle_type']
            vehicle_make = request.form['vehicle_make']
            vehicle_model = request.form['vehicle_model']
            license_plate_number = request.form['license_plate_number']
            maintenance_date_str = request.form['maintenance_date']
            maintenance_date = datetime.strptime(maintenance_date_str, '%Y-%m-%d') if maintenance_date_str else None

    # Validate fields using your custom validator (skip validation for maintenance_date and bill_image)
            if not FieldValidator.validate_vehicle_type(vehicle_type):
                error_messages['vehicle_type'] = "Invalid vehicle type. Please choose a valid type. 'car', 'truck', 'motorcycle', 'bus', 'van', 'bike', 'cycle', 'train']"
            
            if not FieldValidator.validate_vehicle_make(vehicle_make):
                error_messages['vehicle_make'] = "Vehicle make must contain only alphabetic characters."
            
            if not FieldValidator.validate_vehicle_model(vehicle_model):
                error_messages['vehicle_model'] = "Vehicle model must be between 1 and 20 characters."
            
            if not FieldValidator.validate_license_plate(license_plate_number):
                error_messages['license_plate_number'] = "Invalid license plate number. Format should be '1234567' or 'ABC-1234' or 'ABC 1234' "

            if error_messages:
                # If there are validation errors, render the form again with error messages
                return render_template('vehicle.html', error_messages=error_messages)

            # Handle bill image upload (optional)
            bill_image_filename = vehicle.get('bill_image')  # Keep the existing image if not uploading a new one
            if 'bill_image' in request.files and request.files['bill_image'].filename:
                bill_image = request.files['bill_image']
                if bill_image and allowed_file(bill_image.filename):
                    # Upload the bill image to S3 and get the S3 path
                    bill_image_filename = upload_file_to_s3(bill_image)
                    if bill_image_filename:
                        flash(f"New bill image uploaded successfully to S3: {bill_image_filename}", 'success')
                    else:
                        flash('Error uploading bill image to S3.', 'danger')

            # Prepare the update expression with all the updated values
            update_expression = "SET vehicle_type = :vehicle_type, vehicle_make = :vehicle_make, vehicle_model = :vehicle_model, license_plate_number = :license_plate_number"

            # Initialize the expression values
            expression_values = {
                ':vehicle_type': vehicle_type,
                ':vehicle_make': vehicle_make,
                ':vehicle_model': vehicle_model,
                ':license_plate_number': license_plate_number
            }

            # Only add maintenance_date to the update expression if it's not None
            if maintenance_date:
                update_expression += ", maintenance_date = :maintenance_date"
                expression_values[':maintenance_date'] = maintenance_date.isoformat()

            # Add bill_image only if it's not None or the same as the previous one
            if bill_image_filename != vehicle.get('bill_image'):
                update_expression += ", bill_image = :bill_image"
                expression_values[':bill_image'] = bill_image_filename

            # Update the vehicle in DynamoDB
            vehicles_table.update_item(
                Key={'vehicle_number': vehicle_number, 'username': current_user.id},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_values
            )
            
            logger.info(f"Successfully edited Vehicle maintenance details of vehicle {vehicle_number}")
            flash('Vehicle details updated successfully!', 'success')

            return redirect(url_for('home')) 

        # Return the edit vehicle page with the existing vehicle data
        return render_template('edit_vehicle.html', vehicle=vehicle, error_messages=error_messages)


    @application.route('/delete_vehicle/<vehicle_number>', methods=['POST'])
    @login_required
    def delete_vehicle(vehicle_number):
        # Delete the vehicle from DynamoDB
        response = vehicles_table.get_item(Key={'vehicle_number': vehicle_number, 'username': current_user.id})
        vehicle = response.get('Item')

        if not vehicle:
            flash('Vehicle not found!', 'danger')
            return redirect(url_for('home'))  # Redirect to home if vehicle is not found

        # Delete the vehicle from the table
        vehicles_table.delete_item(Key={'vehicle_number': vehicle_number, 'username': current_user.id})

        # Optionally, delete the associated bill image from S3 (if required)
        bill_image_filename = vehicle.get('bill_image')
        if bill_image_filename:
            delete_file_from_s3(bill_image_filename)

        logger.info(f"Successfully deleted Vehicle - {vehicle_number}")
        flash('Vehicle deleted successfully!', 'success')
        return redirect(url_for('home'))


    @application.route('/add_service_history', methods=['GET', 'POST'])
    @login_required
    def add_service_history():
        error_messages = {}
        if request.method == 'POST':
            # Getting the form data
            vehicle_number = request.form['vehicle_number']
            full_name = request.form['full_name']
            phone_number = request.form['phone_number']
            service_date = request.form['service_date']
            service_description = request.form['service_description']
            service_cost = Decimal(request.form['service_cost'])  # Used Decimal for cost precision

            # Validate full name
            if not FieldValidator.validate_full_name(full_name):
                error_messages['full_name'] = 'Invalid full name. Name should only contain letters and spaces, and each part should start with a capital letter e.g., John Doe.'
            
            # Validate phone number
            if not FieldValidator.validate_phone_number(phone_number, country_code='IE'):
                error_messages['phone_number'] = 'Invalid phone number format. Example: +353123456789 or 0123456789.'

            if error_messages:
                return render_template('add_service_history.html', error_messages=error_messages)
                                     

            # Adding service history to the vehicle_service_history table
            vehicle_service_history.put_item(
                Item={
                    'vehicle_number': vehicle_number,
                    'full_name': full_name,
                    'phone_number': phone_number,
                    'service_date': service_date,
                    'service_description': service_description,
                    'service_cost': service_cost,  # Storing as string or Decimal in DynamoDB
                }
            )
            logger.info(f"Service history added successfully for vehicle - {vehicle_number}")
            flash('Service history added successfully!', 'success')
            return redirect(url_for('view_service_history', vehicle_number=vehicle_number))  # Redirect back to the view history page
        
        return render_template('add_service_history.html', error_messages=error_messages)


    @application.route('/view_service_history/<vehicle_number>')
    @login_required
    def view_service_history(vehicle_number):
        # Fetch the service history for the specific vehicle
        service_response = vehicle_service_history.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key('vehicle_number').eq(vehicle_number)
        )

        service_history = service_response.get('Items', [])

        # Fetch vehicle details
        vehicle_response = vehicles_table.get_item(
            Key={'vehicle_number': vehicle_number, 'username': current_user.id}
        )

        vehicle = vehicle_response.get('Item', {})
        return render_template('view_service_history.html', service_history=service_history, vehicle=vehicle, vehicle_number=vehicle_number)



    @application.route('/edit_service_history/<vehicle_number>/<service_date>', methods=['GET', 'POST'])
    @login_required
    def edit_service_history(vehicle_number, service_date):
        error_messages = {}
        # Fetch the service history based on vehicle_number and service_date
        response = vehicle_service_history.get_item(
            Key={
                'vehicle_number': vehicle_number
            }
        )

        service = response.get('Item')  # Fetch the service item to edit

        if not service:
            flash('Service history not found!', 'danger')
            return redirect(url_for('view_service_history', vehicle_number=vehicle_number))

        if request.method == 'POST':
            # Get the updated form data
            updated_full_name = request.form['full_name']
            updated_phone_number = request.form['phone_number']
            updated_service_date = request.form['service_date']
            updated_service_description = request.form['service_description']
            updated_service_cost = Decimal(request.form['service_cost'])  # Use Decimal for precision

            # Validate full name
            if not FieldValidator.validate_full_name(updated_full_name):
                error_messages['full_name'] = 'Invalid full name. Name should only contain letters and spaces, and each part should start with a capital letter e.g., John Doe.'
            
            # Validate phone number
            if not FieldValidator.validate_phone_number(updated_phone_number, country_code='IE'):
                error_messages['phone_number'] = 'Invalid phone number format. Example: +353123456789 or 0123456789.'

            if error_messages:
                return render_template('edit_service_history.html', error_messages=error_messages, service=service, vehicle_number=vehicle_number)

            # Update the service history item in DynamoDB
            vehicle_service_history.update_item(
                Key={
                    'vehicle_number': vehicle_number
                },
                UpdateExpression="SET full_name = :fn, phone_number = :pn, service_date = :sd, service_description = :sd_desc, service_cost = :sd_cost",
                ExpressionAttributeValues={
                    ':fn': updated_full_name,
                    ':pn': updated_phone_number,
                    ':sd': updated_service_date,
                    ':sd_desc': updated_service_description,
                    ':sd_cost': updated_service_cost
                }
            )

            logger.info(f"Service history updated successfully for vehicle - {vehicle_number}")
            flash('Service history updated successfully!', 'success')
            return redirect(url_for('view_service_history', vehicle_number=vehicle_number))

        return render_template('edit_service_history.html', service=service, vehicle_number=vehicle_number, error_messages=error_messages)


    @application.route('/delete_service_history/<vehicle_number>/<service_date>', methods=['POST'])
    @login_required
    def delete_service_history(vehicle_number, service_date):
        # Delete the service history item from DynamoDB
        vehicle_service_history.delete_item(
            Key={
                'vehicle_number': vehicle_number
            }
        )
        logger.info(f"Service history deleted successfully for vehicle - {vehicle_number}")
        flash('Service history deleted successfully!', 'success')
        return redirect(url_for('view_service_history', vehicle_number=vehicle_number))

    @application.route('/filter_vehicles', methods=['GET'])
    @login_required
    def filter_vehicles():
        # Get filter parameters from the request
        vehicle_type = request.args.get('vehicle_type', '')
        vehicle_make = request.args.get('vehicle_make', '')
        license_plate_number = request.args.get('license_plate_number', '')
        maintenance_date = request.args.get('maintenance_date', '')
        vehicle_number = request.args.get('vehicle_number', '')


        # Initialize the filter expression list and expression values
        filter_expression = []
        expression_values = {}

        # Adding filters for vehicle type, make, license plate number, maintenance date, and vehicle number
        if vehicle_type:
            filter_expression.append("vehicle_type = :vehicle_type")
            expression_values[':vehicle_type'] = vehicle_type

        if vehicle_make:
            filter_expression.append("vehicle_make = :vehicle_make")
            expression_values[':vehicle_make'] = vehicle_make

        if license_plate_number:
            filter_expression.append("license_plate_number = :license_plate_number")
            expression_values[':license_plate_number'] = license_plate_number

        if maintenance_date:
            # The maintenance_date format is YYYY-MM-DDT00:00:00 for the comparison
            formatted_date = f"{maintenance_date}T00:00:00"
            filter_expression.append("maintenance_date = :maintenance_date")
            expression_values[':maintenance_date'] = formatted_date

        if vehicle_number:
            filter_expression.append("vehicle_number = :vehicle_number")
            expression_values[':vehicle_number'] = vehicle_number

        # Combining the filter expressions using "AND"
        if filter_expression:
            filter_expression = " AND ".join(filter_expression)
        else:
            filter_expression = None

        # Performing the scan query based on the filters
        if filter_expression:
            response = vehicles_table.scan(
                FilterExpression=filter_expression,
                ExpressionAttributeValues=expression_values
            )
        else:
            response = vehicles_table.scan()  # If no filters, return all vehicles

        # Fetch the results, including the 'bill_image'
        vehicles = response.get('Items', [])

        # Generate the presigned URL for the bill images if they exist
        for vehicle in vehicles:
            if vehicle.get('bill_image'):
                vehicle['image_url'] = generate_presigned_url(S3_BUCKET_NAME, vehicle['bill_image'])

        # Render the page with the filtered vehicles
        return render_template('home.html', vehicles=vehicles)


    # if __name__ == '__main__':
    #     application.run(debug=True, use_reloader=False)

    # if __name__ == '__main__':
    #     application.run(debug=False, host='0.0.0.0', port=3000)

    # if __name__ == '__main__':
    #     application.run(port=5000, debug=True)
    return application