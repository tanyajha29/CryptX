pipeline {
    agent any

    stages {
        stage('Clone Repo') {
            steps {
                checkout scm
            }
        }

        stage('Build Docker Image') {
            steps {
                sh '''
                docker build -t cryptx-app .
                '''
            }
        }

        stage('Run Containers') {
            steps {
                sh '''
                docker compose down || true
                docker compose up -d
                '''
            }
        }

        stage('Verify Deployment') {
            steps {
                sh '''
                docker ps
                '''
            }
        }
    }

    post {
        success {
            echo '✅ CryptX deployed successfully!'
        }
        failure {
            echo '❌ Deployment failed.'
        }
    }
}
