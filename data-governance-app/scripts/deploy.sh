#!/bin/bash

# Deployment script for the data governance application

# Exit on any error
set -e

# Print script name
echo "Deploying Data Governance Application..."

# Check if we're on the main branch
current_branch=$(git rev-parse --abbrev-ref HEAD)
if [ "$current_branch" != "main" ] && [ "$current_branch" != "master" ]; then
    echo "Warning: You are not on the main branch. Do you want to continue? (y/N)"
    read -r response
    if [ "$response" != "y" ] && [ "$response" != "Y" ]; then
        echo "Deployment cancelled."
        exit 1
    fi
fi

# Run tests
echo "Running tests..."
python -m pytest tests/

# Build Docker image
echo "Building Docker image..."
docker build -t data-governance-app:latest .

# Push to container registry (example with Docker Hub)
# echo "Pushing to container registry..."
# docker tag data-governance-app:latest your-dockerhub-username/data-governance-app:latest
# docker push your-dockerhub-username/data-governance-app:latest

# Deploy to cloud platform (example with Kubernetes)
# echo "Deploying to Kubernetes..."
# kubectl apply -f k8s/

# Alternative deployment to cloud platform (example with Heroku)
# echo "Deploying to Heroku..."
# git push heroku main

echo "Deployment complete!"