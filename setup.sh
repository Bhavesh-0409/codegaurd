#!/usr/bin/env bash
# Sets up the backend virtual environment and installs dependencies.
# Run this from the project root: ./setup.sh

set -e

cd "$(dirname "$0")/backend"

echo "Creating virtual environment in backend/venv ..."
python3 -m venv venv

echo "Activating venv and installing dependencies ..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

if [ ! -f .env ]; then
  cp .env.example .env
  echo ""
  echo "Created backend/.env - open it and paste in your GEMINI_API_KEY."
fi

echo ""
echo "Done. To start the backend next time:"
echo "  cd backend"
echo "  source venv/bin/activate"
echo "  uvicorn main:app --reload --port 8000"
echo ""
echo "(No need to re-enter the API key - it's read from backend/.env automatically.)"
