@echo off
REM Sets up the backend virtual environment and installs dependencies.
REM Run this from the project root: setup.bat

cd backend

echo Creating virtual environment in backend\venv ...
python -m venv venv

echo Activating venv and installing dependencies ...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt

if not exist .env (
    copy .env.example .env
    echo.
    echo Created backend\.env - open it and paste in your GEMINI_API_KEY.
)

echo.
echo Done. To start the backend next time:
echo   cd backend
echo   venv\Scripts\activate.bat
echo   uvicorn main:app --reload --port 8000
echo.
echo (No need to re-enter the API key - it's read from backend\.env automatically.)
