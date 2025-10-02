#!/bin/bash

# Setup script for the data governance application

# Exit on any error
set -e

# Print script name
echo "Setting up Data Governance Application..."

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Install development dependencies if requested
if [ "$1" = "--dev" ]; then
    echo "Installing development dependencies..."
    pip install -r requirements-dev.txt
fi

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "Creating .env file from example..."
    cp .env.example .env
    echo "Please update the .env file with your configuration."
fi

# Run database migrations if needed
# echo "Running database migrations..."
# Add migration commands here

# Setup pre-commit hooks
if [ -f "requirements-dev.txt" ]; then
    echo "Setting up pre-commit hooks..."
    pre-commit install
fi

echo "Setup complete!"
echo "To activate the virtual environment, run: source venv/bin/activate"
echo "To run the application, run: streamlit run src/app.py"