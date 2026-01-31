pipeline {
    agent any

    stages {

        stage('Checkout Code') {
            steps {
                git branch: 'main',
                    url: 'https://github.com/tanyajha29/CryptX.git'
            }
        }

        stage('Cleanup Old Containers') {
            steps {
                sh '''
                docker compose down || true
                docker system prune -f || true
                '''
            }
        }

        stage('Build Docker Images') {
            steps {
                sh 'docker compose build'
            }
        }

        stage('Deploy Application') {
            steps {
                sh 'docker compose up -d'
            }
        }
    }
}
