#!/bin/bash

# Run script for PingHub
# This script starts all necessary components for the PingHub application

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Run migrations
echo "Running migrations..."
python manage.py makemigrations
python manage.py migrate

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --noinput

# Check if Redis is running
redis-cli ping > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Redis is not running. Please start Redis before continuing."
    exit 1
fi

# Start Celery worker in background
echo "Starting Celery worker..."
celery -A network_scanner worker -l info --detach

# Start Celery beat in background
echo "Starting Celery beat..."
celery -A network_scanner beat -l info --detach

# Start Django development server
echo "Starting Django development server..."
python manage.py runserver

# Cleanup function to stop background processes when script is terminated
cleanup() {
    echo "Stopping Celery worker and beat..."
    pkill -f "celery -A network_scanner"
    echo "Cleanup complete."
}

# Register cleanup function to be called on exit
trap cleanup EXIT

