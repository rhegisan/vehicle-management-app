#Flask installation
mkdir vehicleManagement
python -m ensurepip --upgrade
python -m pip install flask


#Creating virtual env
python -m venv myFlaskEnv
Set-ExecutionPolicy Unrestricted -Scope Process
.\myFlaskEnv\Scripts\activate
pip install flask


#Installing Dependencies #can be removed -> werkzeug
pip install Flask Flask-SQLAlchemy Flask-WTF werkzeug
pip install mysqlclient PyMySQL
pip install bcrypt
pip install flask-migrate
pip install flask-login




#Database commands
CREATE DATABASE flask_app;
USE flask_app;
show tables;


#Implementing migrations
flask db init
flask db migrate -m "Change password field to LargeBinary"
flask db upgrade


# AWS CREDS

$env:AWS_CONFIG_FILE="C:\path\to\your\custom\config"
$env:AWS_SHARED_CREDENTIALS_FILE="C:\path\to\your\custom\credentials"

$env:AWS_SHARED_CREDENTIALS_FILE="F:\NCI ACADEMICS\Cloud Computing Programming\PROJECT\vehicleManagement\aws\credentials"
[default]
aws_access_key_id=ASIARCOTZ3GWN5P6CAPT
aws_secret_access_key=B2zz/XyF0zXlFibz+1WtjedT/U8ChBq/MibmRwOl
aws_session_token=IQoJb3JpZ2luX2VjEJj//////////wEaCXVzLXdlc3QtMiJHMEUCIEvS66cFT0iT46e53tsZCE5vxWzlE7at3VXA1mtqUwXiAiEArxurx4MGfnvh///6P1E5pT29H+xnE++QhfDqFVK7TW0qtAIIMBABGgwwNzM5OTU1MDgxNDAiDKNiR8JTNuYRMTp01CqRArUgI3AQ8YdOGHOWoadyjM8GO0vfpRfd5cRTylmM+rcpRSpdF8imVuAgMamUXIhGuSy5+YpukbYEKyTQkBJmFYmF3vNhCCZp637NmiI4f1U626RCQStsELN6YLzg8EGauyJBRJCaISD5RF4sD7MSoAMDx1B57Q+4Sq/RtTznMQD9b0SrR298fjNfAZ4yhp0FZqu+FqpBrHesap7UVpmTvs530mPXmTS5TTqN4g3SNdYs3ksOI/c9liqRIrtUl8uSntJcVjRqd7ldZSt5oQ7EVoSfxB6Xj1Kg2lrT8Ho9L+5lzW5innOER7D7p3SQItoZzumn8++EPIqlJagpKEnsA5i/4E4cDM3VMB79eweRu2xBIDDo7+K5BjqdAX2e5P/o44uUiwFWkqwRMfyhHs12ZuP1dcEayvYvTx6CcK//lWgaoOTZNqic/AsMxhu666JmZB0QPw0coOfG3vjSt2BFL8E9+EUH5hmFTvY8HgQFLrHNFDtOE2rh6hKt1/Y1ZSIVKoRWGjx30gOVPI2V0Gscm6TKJSK+VY4OCiKthjd2aQgnQHH2d/o1iGIU7t4L7KhwZG4d4H7EfCo=


# Check if file type is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']