from flask import Flask, render_template, request, redirect, url_for, flash, session
import boto3
from werkzeug.utils import secure_filename
from datetime import datetime
import bcrypt
import time
from botocore.exceptions import ClientError, EndpointConnectionError
import concurrent.futures
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask import make_response
import json
import os
import zipfile

app = Flask(__name__)

login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirects to the login page for unauthorized users
login_manager.login_message = 'Please log in to access this page.'

class User(UserMixin):
    def __init__(self, username, password=None, name=None, email=None, phone_number=None):
        self.id = username
        self.password = password
        self.name = name
        self.email = email
        self.phone_number = phone_number

    @staticmethod
    def get(username):
        response = users_table.get_item(Key={'username': username})
        if 'Item' in response:
            user_data = response['Item']
            return User(
                username=user_data['username'], 
                password=user_data['password'], 
                # name=user_data['name'],
                # email=user_data['email'],
                # phone_number=user_data['phone_number']
            )
        return None

    
    @login_manager.user_loader
    def load_user(username):
        return User.get(username)


# AWS DynamoDB setup (Make sure you have AWS credentials set up, or you can set them in environment variables)
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')  # Choose your region
users_table = dynamodb.Table('users')
vehicles_table = dynamodb.Table('vehicles')

# AWS S3 setup
S3_BUCKET_NAME = 'rhegi'  # Replace with your S3 bucket name
S3_REGION = 'us-east-1'  # Use your region
s3_client = boto3.client('s3', region_name=S3_REGION)

# AWS Clients
sqs_client = boto3.client('sqs', region_name='us-east-1')
sns_client = boto3.client('sns', region_name='us-east-1')
lambda_client = boto3.client('lambda', region_name='us-east-1')

# Flask configurations
app.config['SECRET_KEY'] = '1234'  # For CSRF protection and session management
app.config['ALLOWED_EXTENSIONS'] =  {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}


# Check if file type is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Function to check if tables exist and create them if not
def create_tables_if_not_exist():
    client = boto3.client('dynamodb', region_name='us-east-1')

    # Check if 'users' table exists
    try:
        client.describe_table(TableName='users')
        print("Table 'users' already exists.")
    except client.exceptions.ResourceNotFoundException:
        print("Table 'users' does not exist. Creating table...")
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
        print("Table 'vehicles' already exists.")
    except client.exceptions.ResourceNotFoundException:
        print("Table 'vehicles' does not exist. Creating table...")

        client.create_table(
            TableName='vehicles',
            KeySchema=[
                {'AttributeName': 'vehicle_number', 'KeyType': 'HASH'},  # Partition key
                {'AttributeName': 'username', 'KeyType': 'RANGE'}  # Sort key (username)
            ],
            AttributeDefinitions=[
                {'AttributeName': 'vehicle_number', 'AttributeType': 'S'},
                {'AttributeName': 'username', 'AttributeType': 'S'}
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            },
            GlobalSecondaryIndexes=[
                {
                    'IndexName': 'username-index',  # GSI name
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
                }
            ]
        )
        client.get_waiter('table_exists').wait(TableName='users')
        print("Table 'users' created successfully.")
        client.get_waiter('table_exists').wait(TableName='vehicles')
        print("Table 'vehicles' created successfully.")

# Function to ensure that the S3 bucket exists, and create it if not
def ensure_bucket_exists():
    try:
        s3_client.head_bucket(Bucket=S3_BUCKET_NAME)
        print(f"Bucket {S3_BUCKET_NAME} already exists.")
    except s3_client.exceptions.ClientError:
        print(f"Bucket {S3_BUCKET_NAME} does not exist. Creating bucket...")
        if S3_REGION == 'us-east-1':
            try:
                s3_client.create_bucket(Bucket=S3_BUCKET_NAME)
                print(f"Bucket {S3_BUCKET_NAME} created successfully in {S3_REGION} region.")
            except ClientError as e:
                print(f"Error creating bucket: {e}")
                retry_on_error()
        else:
            try:
                s3_client.create_bucket(
                    Bucket=S3_BUCKET_NAME,
                    CreateBucketConfiguration={'LocationConstraint': S3_REGION}
                )
                print(f"Bucket {S3_BUCKET_NAME} created successfully in {S3_REGION} region.")
            except ClientError as e:
                print(f"Error creating bucket: {e}")
                retry_on_error()

def retry_on_error(max_retries=5, delay=2):
    attempts = 0
    while attempts < max_retries:
        time.sleep(delay)  # Delay before retry
        print(f"Retrying in {delay} seconds...")
        attempts += 1
        try:
            ensure_bucket_exists()  # Try creating the bucket again
            break  # Exit the loop if successful
        except ClientError as e:
            if attempts == max_retries:
                print(f"Failed to create the bucket after {max_retries} attempts.")
                break  # Exit the loop after max retries
            continue  # Retry on failure



def check_or_create_sqs_queue():
    queue_name = 'maintenanceQueue'
    try:
        # Try to get the queue URL to check if the queue exists
        sqs_client.get_queue_url(QueueName=queue_name)
        print(f"SQS Queue '{queue_name}' already exists.")
    except sqs_client.exceptions.QueueDoesNotExist:
        print(f"SQS Queue '{queue_name}' does not exist. Creating it...")
        response = sqs_client.create_queue(QueueName=queue_name)
        queue_url = response['QueueUrl']
        
        # Poll to confirm that the queue has been created
        print(f"Waiting for SQS Queue '{queue_name}' to be created...")
        confirm_creation = False
        retries = 0
        while retries < 5 and not confirm_creation:
            try:
                sqs_client.get_queue_url(QueueName=queue_name)
                print(f"SQS Queue '{queue_name}' created successfully.")
                confirm_creation = True
            except sqs_client.exceptions.QueueDoesNotExist:
                time.sleep(2)  # Wait before retrying
                retries += 1
                if retries == 5:
                    print("SQS Queue creation failed after 5 retries.")

def check_or_create_sns_topic():
    topic_name = 'MaintenanceDueTopic'
    try:
        # Try to get the topic's attributes to check if it exists
        sns_client.get_topic_attributes(TopicArn=f'arn:aws:sns:us-east-1:073995508140:{topic_name}')
        print(f"SNS Topic '{topic_name}' already exists.")
    except sns_client.exceptions.NotFoundException:
        print(f"SNS Topic '{topic_name}' does not exist. Creating it...")
        response = sns_client.create_topic(Name=topic_name)
        topic_arn = response['TopicArn']
        
        # Poll to confirm the SNS topic is created
        print(f"Waiting for SNS Topic '{topic_name}' to be created...")
        confirm_creation = False
        retries = 0
        while retries < 5 and not confirm_creation:
            try:
                sns_client.get_topic_attributes(TopicArn=topic_arn)
                print(f"SNS Topic '{topic_name}' created successfully.")
                confirm_creation = True
            except sns_client.exceptions.NotFoundException:
                time.sleep(2)  # Wait before retrying
                retries += 1
                if retries == 5:
                    print("SNS Topic creation failed after 5 retries.")

def zip_lambda_function(source_dir, output_zip):
    """
    Zips the contents of a directory for Lambda deployment.
    """
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
        print(f"Lambda function '{function_name}' already exists.")
    except lambda_client.exceptions.ResourceNotFoundException:
        print(f"Lambda function '{function_name}' does not exist. Creating it...")
        
        # Path to Lambda code
        source_dir = '.'  # Replace with your Lambda code directory
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
            Role='arn:aws:iam::073995508140:role/LabRole',  # Replace with your ARN if different
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': zip_data},
            Timeout=30,
            MemorySize=128
        )
        print(f"Lambda function '{function_name}' created. Waiting for confirmation...")

        # Poll to confirm that the Lambda function is created
        confirm_creation = False
        retries = 0
        while retries < 5 and not confirm_creation:
            try:
                lambda_client.get_function(FunctionName=function_name)
                print(f"Lambda function '{function_name}' created successfully.")
                confirm_creation = True
            except lambda_client.exceptions.ResourceNotFoundException:
                time.sleep(2)  # Wait before retrying
                retries += 1
                if retries == 5:
                    print("Lambda function creation failed after 5 retries.")
    else:
        # Update the existing Lambda function code
        print(f"Updating code for Lambda function '{function_name}'...")
        
        # Path to Lambda code
        source_dir = 'path_to_lambda_code'  # Replace with your Lambda code directory
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
        print(f"Lambda function '{function_name}' code updated successfully.")

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
#                     print(f"Lambda function {lambda_function_arn} is already subscribed.")
#                     break

#             if not lambda_subscribed:
#                 # If not subscribed, attempt to subscribe the Lambda function
#                 sns_client.subscribe(
#                     TopicArn=topic_arn,
#                     Protocol='lambda',
#                     Endpoint=lambda_function_arn
#                 )
#                 print(f"Lambda function {lambda_function_arn} successfully subscribed to SNS topic.")

#             # Check if Email is already subscribed
#             email_subscribed = False
#             for subscription in subscriptions:
#                 if subscription['Endpoint'] == email_address:
#                     email_subscribed = True
#                     print(f"Email address {email_address} is already subscribed.")
#                     break

#             if not email_subscribed:
#                 # If not subscribed, attempt to subscribe the email address
#                 sns_client.subscribe(
#                     TopicArn=topic_arn,
#                     Protocol='email',
#                     Endpoint=email_address
#                 )
#                 print(f"Email address {email_address} successfully subscribed to SNS topic.")

#             # If both subscriptions are successful, break out of the retry loop
#             break

#         except Exception as e:
#             retries += 1
#             print(f"Error subscribing Lambda or Email to SNS topic (Attempt {retries}): {e}")
#             time.sleep(2)  # Retry after a brief pause

#     if retries == 5:
#         print("Failed to subscribe Lambda function or Email address after 5 attempts.")


# Function to ensure that tables and bucket exist before running the app
def setup_resources():

    topic_arn = 'arn:aws:sns:us-east-1:123456789012:MaintenanceDueTopic'  # Replace with your SNS topic ARN
    lambda_function_arn = 'arn:aws:lambda:us-east-1:123456789012:function:VehicleMaintenanceLambda'  # Replace with your Lambda ARN
    email_address = 'rhegisanjebas71@gmail.com'  # Replace with your email address

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        futures.append(executor.submit(check_or_create_lambda_function))
        futures.append(executor.submit(create_tables_if_not_exist))  # Submit the DynamoDB table creation task
        futures.append(executor.submit(ensure_bucket_exists))  # Submit the S3 bucket creation task
        futures.append(executor.submit(check_or_create_sns_topic))
        # futures.append(executor.submit(check_or_create_sqs_queue))
        # futures.append(executor.submit(subscribe_to_sns, topic_arn, lambda_function_arn, email_address))
        for future in futures:
            future.result()

# Call this function to ensure tables and bucket exist before running the app
setup_resources()

# Function to generate presigned URL for an image
def generate_presigned_url(bucket_name, object_key, expiration=3600):
    """Generate a presigned URL to share an S3 object

    :param bucket_name: string
    :param object_key: string
    :param expiration: Time in seconds for the presigned URL to remain valid (default is 1 hour)
    :return: Presigned URL as string if successful, else None
    """
    try:
        response = s3_client.generate_presigned_url('get_object',
                                                    Params={'Bucket': bucket_name, 'Key': object_key},
                                                    ExpiresIn=expiration)
    except ClientError as e:
        print(f"Error generating presigned URL: {e}")
        return None
    return response


# Send notification to SNS when a vehicle is added or updated
def send_sns_notification(vehicle_number, maintenance_date):
    try:
        message = {
            "vehicle_number": vehicle_number,
            "maintenance_date": maintenance_date.isoformat()  # ISO format for date
        }
        
        # SNS Topic ARN (Replace with your actual ARN)
        topic_arn = 'arn:aws:sns:us-east-1:073995508140:MaintenanceDueTopic'
        
        # Send message to SNS
        response = sns_client.publish(
            TopicArn=topic_arn,
            Message=json.dumps(message),
            Subject="Vehicle Maintenance Notification"
        )
        
        print(f"SNS notification sent for vehicle {vehicle_number}, response: {response}")
    except Exception as e:
        print(f"Error sending SNS notification: {e}")

# Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        full_name = request.form['full_name']
        email = request.form['email']
        phone_number = request.form['phone_number']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('signup'))

        # Check if the username already exists in DynamoDB
        response = users_table.get_item(Key={'username': username})
        if 'Item' in response:
            flash('Username already exists!', 'danger')
            return redirect(url_for('signup'))

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Create the new user item with basic personal info (no vehicle data here)
        user_item = {
            'username': username,
            'password': boto3.dynamodb.types.Binary(hashed_password),
            'full_name': full_name,
            'email': email,
            'phone_number': phone_number
        }

        # Store the user in DynamoDB
        users_table.put_item(Item=user_item)

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Retrieve user from the database
        user = User.get(username)
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.value):
            login_user(user)  # Pass the `User` object
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')


@app.route('/')
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

    # Pass the vehicles (with image_url) to the template
    return render_template('home.html', vehicles=vehicles)



# Logout Route
@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Function to upload files to S3
def upload_file_to_s3(file):
    """Uploads a single file to S3 and returns the file path."""
    # Generate a secure filename
    filename = secure_filename(file.filename)

    # User-specific S3 path (create a path with the username)
    s3_user_folder = f'users/{current_user.id}/bills/{filename}'
    
    try:
        # Upload the file to S3
        s3_client.upload_fileobj(file, S3_BUCKET_NAME, s3_user_folder)
        return s3_user_folder  # Return the S3 file path
    except Exception as e:
        print(f"Error uploading file to S3: {e}")
        return None

# Vehicle Maintenance Route
@app.route('/vehicle', methods=['GET', 'POST'])
@login_required
def vehicle():
    if request.method == 'POST':
        vehicle_number = request.form['vehicle_number']
        vehicle_type = request.form['vehicle_type']
        vehicle_make = request.form['vehicle_make']
        vehicle_model = request.form['vehicle_model']
        license_plate_number = request.form['license_plate_number']
        maintenance_date = datetime.strptime(request.form['maintenance_date'], '%Y-%m-%d')

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

        
        send_sns_notification(vehicle_number, maintenance_date)

        flash('Vehicle maintenance details added successfully!', 'success')
        return redirect(url_for('home'))  # Redirect to the home page where the image is displayed

    return render_template('vehicle.html')


@app.route('/edit_vehicle/<vehicle_number>', methods=['GET', 'POST'])
@login_required
def edit_vehicle(vehicle_number):
    # Fetch the vehicle details from DynamoDB using the vehicle_number and username (current_user.id)
    response = vehicles_table.get_item(Key={'vehicle_number': vehicle_number, 'username': current_user.id})
    vehicle = response.get('Item')

    if not vehicle:
        flash('Vehicle not found!', 'danger')
        return redirect(url_for('home'))  # Redirect to home if vehicle is not found

    if request.method == 'POST':
        # Get the updated details from the form
        vehicle_type = request.form['vehicle_type']
        vehicle_make = request.form['vehicle_make']
        vehicle_model = request.form['vehicle_model']
        license_plate_number = request.form['license_plate_number']
        maintenance_date_str = request.form['maintenance_date']
        maintenance_date = datetime.strptime(maintenance_date_str, '%Y-%m-%d') if maintenance_date_str else None

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

        send_sns_notification(vehicle_number, maintenance_date)

        flash('Vehicle details updated successfully!', 'success')

        return redirect(url_for('home')) 

    # Return the edit vehicle page with the existing vehicle data
    return render_template('edit_vehicle.html', vehicle=vehicle)




if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
