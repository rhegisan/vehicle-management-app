pipeline {
    agent any
    
    environment {
        AWS_DEFAULT_REGION = 'us-east-1'
        EB_APP_NAME = 'GarageSync'
        EB_ENV_NAME = 'GarageSync-env'
        GITHUB_TOKEN = credentials('github-pat')
    }
    
    stages {
        stage('Clone Repository') {
            steps {
                script {
                    sh 'git clone https://rhegisan:${GITHUB_TOKEN}@github.com/rhegisan/vehicle-management-app.git'
                }
            }
        }
        
        stage('Deploy to Elastic Beanstalk') {
            steps {
                script {
                    sh 'eb init -p docker ${EB_APP_NAME} --region ${AWS_DEFAULT_REGION}'
                    
                    sh 'eb use ${EB_ENV_NAME}'
                    
                    sh 'eb deploy'
                }
            }
        }
    }

    post {
        success {
            echo "Deployment successful"
        }
        failure {
            echo "Deployment failed"
        }
    }
}
