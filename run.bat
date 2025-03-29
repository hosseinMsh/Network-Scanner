@echo off
REM Run script for PingHub on Windows
REM This script starts all necessary components for the PingHub application

REM Check if virtual environment exists
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
call venv\Scripts\activate

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt

REM Run migrations
echo Running migrations...
python manage.py migrate

REM Collect static files
echo Collecting static files...
python manage.py collectstatic --noinput

REM Check if Redis is running (requires Redis for Windows or WSL)
redis-cli ping > nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Redis is not running. Please start Redis before continuing.
    exit /b 1
)

REM Start Celery worker in a new window
echo Starting Celery worker...
start "Celery Worker" cmd /k "venv\Scripts\celery -A network_scanner worker -l info"

REM Start Celery beat in a new window
echo Starting Celery beat...
start "Celery Beat" cmd /k "venv\Scripts\celery -A network_scanner beat -l info"

REM Start Django development server
echo Starting Django development server...
python manage.py runserver

REM Note: You'll need to manually close the Celery windows when done

