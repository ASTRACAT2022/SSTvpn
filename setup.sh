#!/bin/bash

# ASTRACAT Cloud Setup Script

# Exit immediately if a command exits with a non-zero status.
set -e

echo "Starting ASTRACAT Cloud Setup..."

# --- Rebranding Step ---
echo "Rebranding from StealthNET to ASTRACAT Cloud..."

# Find the main JavaScript file dynamically
main_js_file=$(find frontend/build/static/js -name "main.*.js")

# List of files to rebrand
files_to_rebrand=(
    "README.md"
    "app.py"
    "frontend/build/index.html"
    "frontend/build/manifest.json"
    "$main_js_file"
)

for file in "${files_to_rebrand[@]}"; do
    if [ -f "$file" ]; then
        # Use a temporary file to handle in-place editing safely
        tmp_file=$(mktemp)
        sed 's/StealthNET/ASTRACAT Cloud/g' "$file" > "$tmp_file" && mv "$tmp_file" "$file"
        sed 's/stealthnet/astracat-cloud/g' "$file" > "$tmp_file" && mv "$tmp_file" "$file"
        echo "Rebranded $file"
    else
        echo "Warning: $file not found, skipping."
    fi
done

# Rename database
db_file="app.py"
if [ -f "$db_file" ]; then
    tmp_file=$(mktemp)
    sed "s/stealthnet.db/astracat_cloud.db/g" "$db_file" > "$tmp_file" && mv "$tmp_file" "$db_file"
    echo "Renamed database in $db_file"
else
    echo "Warning: $db_file not found, skipping database rename."
fi

# Rebrand manifest.json short_name and name
manifest_file="frontend/build/manifest.json"
if [ -f "$manifest_file" ]; then
    tmp_file=$(mktemp)
    sed 's/"short_name": "STEALTHNET"/"short_name": "ASTRACAT Cloud"/' "$manifest_file" > "$tmp_file" && mv "$tmp_file" "$manifest_file"
    sed 's/"name": "STEALTHNET Client Panel"/"name": "ASTRACAT Cloud Client Panel"/' "$manifest_file" > "$tmp_file" && mv "$tmp_file" "$manifest_file"
    echo "Rebranded manifest.json"
else
    echo "Warning: $manifest_file not found, skipping."
fi


echo "Rebranding complete."
# --- End Rebranding Step ---

# --- Dependency Installation Step ---
echo "Installing dependencies..."

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip3 install -r requirements.txt
pip3 install -r client_bot_requirements.txt

echo "Dependency installation complete."
# --- End Dependency Installation Step ---

# --- User Configuration Step ---
echo "Configuring user variables..."

# Create .env file
# Here, we'll read each variable from the user and write it to the .env file.
# This makes the setup interactive and user-friendly.

# API Configuration
read -p "Enter your admin token: " ADMIN_TOKEN
read -p "Enter your RemnaWave API URL: " API_URL
read -p "Enter your default squad ID: " DEFAULT_SQUAD_ID
read -p "Enter your server IP or domain: " YOUR_SERVER_IP

# Security
read -p "Enter your JWT secret key: " JWT_SECRET_KEY
read -p "Enter your Fernet key: " FERNET_KEY

# Telegram Bot (optional)
read -p "Enter your bot API URL (optional): " BOT_API_URL
read -p "Enter your bot API token (optional): " BOT_API_TOKEN
read -p "Enter your Telegram bot name (optional): " TELEGRAM_BOT_NAME

# Email Configuration (optional)
read -p "Enter your mail server (optional): " MAIL_SERVER
read -p "Enter your mail port (optional): " MAIL_PORT
read -p "Enter your mail username (optional): " MAIL_USERNAME
read -p "Enter your mail password (optional): " MAIL_PASSWORD

# Write to .env file
cat > .env << EOL
# API Configuration
ADMIN_TOKEN=${ADMIN_TOKEN}
API_URL=${API_URL}
DEFAULT_SQUAD_ID=${DEFAULT_SQUAD_ID}
YOUR_SERVER_IP=${YOUR_SERVER_IP}

# Security
JWT_SECRET_KEY=${JWT_SECRET_KEY}
FERNET_KEY=${FERNET_KEY}

# Telegram Bot (optional)
BOT_API_URL=${BOT_API_URL}
BOT_API_TOKEN=${BOT_API_TOKEN}
TELEGRAM_BOT_NAME=${TELEGRAM_BOT_NAME}

# Email Configuration (optional)
MAIL_SERVER=${MAIL_SERVER}
MAIL_PORT=${MAIL_PORT}
MAIL_USERNAME=${MAIL_USERNAME}
MAIL_PASSWORD=${MAIL_PASSWORD}
EOL

echo "User variables configured."
# --- End User Configuration Step ---

# --- Daemon Creation Step ---
echo "Creating and configuring daemon..."

read -p "Enter the service name for the application (e.g., astracat-cloud): " SERVICE_NAME

# Create systemd service file for app.py
sudo bash -c "cat > /etc/systemd/system/${SERVICE_NAME}.service << EOL
[Unit]
Description=ASTRACAT Cloud Application
After=network.target

[Service]
User=$(whoami)
Group=$(whoami)
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
EOL"

# Create systemd service file for client_bot.py
sudo bash -c "cat > /etc/systemd/system/${SERVICE_NAME}_bot.service << EOL
[Unit]
Description=ASTRACAT Cloud Telegram Bot
After=network.target

[Service]
User=$(whoami)
Group=$(whoami)
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/venv/bin/python3 client_bot.py
Restart=always

[Install]
WantedBy=multi-user.target
EOL"

# Reload systemd, enable and start the services
sudo systemctl daemon-reload
sudo systemctl enable ${SERVICE_NAME}.service
sudo systemctl start ${SERVICE_NAME}.service
sudo systemctl enable ${SERVICE_NAME}_bot.service
sudo systemctl start ${SERVICE_NAME}_bot.service

echo "Daemon created and configured."
# --- End Daemon Creation Step ---

# --- Verification Step ---
echo "Verifying setup..."

# Check the status of the services
sudo systemctl status ${SERVICE_NAME}.service --no-pager
sudo systemctl status ${SERVICE_NAME}_bot.service --no-pager

echo "Verification complete."
# --- End Verification Step ---


echo "Setup complete!"
echo "Please note: The application is now running on 0.0.0.0:5000. For production use, it is highly recommended to put it behind a reverse proxy like Nginx or Caddy."
