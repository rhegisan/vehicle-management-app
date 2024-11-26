# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Set the working directory in the container
WORKDIR /app

# Install system dependencies (optional but common in Flask applications)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 5000 available to the world outside this container
EXPOSE 3000
<<<<<<< HEAD

# Set the WSGI server (Gunicorn) command for starting the app
CMD ["gunicorn", "-b", "0.0.0.0:3000", "wsgi:application"]
=======

# Define environment variable for Flask
ENV FLASK_APP=application.py

# # Define environment variables (optional)
# ENV FLASK_APP=app.py
# ENV FLASK_RUN_HOST=0.0.0.0
# ENV FLASK_RUN_PORT=3000

# Run the Flask app
# CMD ["python", "application.py"]

# Set the WSGI server (Gunicorn) command for starting the app
CMD ["gunicorn", "-b", "0.0.0.0:3000", "application:create_application()"]
>>>>>>> db540ce79d82cf1a6e723773060efefa30c0291c
