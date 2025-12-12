#!/bin/bash
# ASTRACAT Cloud Installer Script

set -e

echo "🚀 Welcome to the ASTRACAT Cloud Installer!"
echo "=========================================="
echo ""
echo "This script will automate the installation and configuration of the ASTRACAT Cloud panel and bot."
echo "Please be prepared to answer a few questions to configure your setup."
echo ""

# --- Gather User Input ---
echo "---"
echo "Please provide the following information:"
echo ""

# Domain and IP
read -r -p "Enter your domain name (e.g., panel.example.com): " DOMAIN
YOUR_SERVER_IP=$(curl -s ifconfig.me)
API_URL="https://$DOMAIN"

# Admin User
read -r -p "Enter the admin user's email address: " ADMIN_EMAIL
read -r -sp "Enter the admin user's password: " ADMIN_PASSWORD
echo ""

# Telegram Bot
read -r -p "Enter your Telegram Bot Token: " CLIENT_BOT_TOKEN
read -r -p "Enter your Telegram Bot Name (e.g., MyVPNBot): " TELEGRAM_BOT_NAME

# Email Configuration
read -r -p "Enter your SMTP server (e.g., smtp.gmail.com): " MAIL_SERVER
read -r -p "Enter your SMTP port (e.g., 465): " MAIL_PORT
read -r -p "Enter your SMTP username (email): " MAIL_USERNAME
read -r -sp "Enter your SMTP password (or app password): " MAIL_PASSWORD
echo ""

# Auto-generate secrets
echo "🔑 Generating secret keys..."
JWT_SECRET_KEY=$(openssl rand -hex 32)
FERNET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
ADMIN_TOKEN=$(openssl rand -hex 16)
echo "✅ Secret keys generated successfully."
echo ""

# --- Install Dependencies ---
echo "---"
echo "Installing system dependencies..."
echo "This may take a few minutes."
echo ""
sudo apt-get update
sudo apt-get install -y python3-venv python3-pip nginx certbot python3-certbot-nginx curl

echo "✅ System dependencies installed."
echo ""

# --- Setup Python Virtual Environment ---
echo "---"
echo "Setting up Python virtual environment..."
echo ""
python3 -m venv venv
source venv/bin/activate

echo "✅ Virtual environment created."
echo ""

# --- Install Python Packages ---
echo "---"
echo "Installing Python packages..."
echo ""
pip install -r requirements.txt
pip install -r client_bot_requirements.txt

echo "✅ Python packages installed."
echo ""

# --- Configure Environment ---
echo "---"
echo "Creating .env file..."
echo ""

# Create .env file from user input
cat > .env << EOL
# API Configuration
ADMIN_TOKEN=${ADMIN_TOKEN}
API_URL=${API_URL}
DEFAULT_SQUAD_ID=1
YOUR_SERVER_IP=${YOUR_SERVER_IP}

# Security
JWT_SECRET_KEY=${JWT_SECRET_KEY}
FERNET_KEY=${FERNET_KEY}

# Telegram Bot (optional)
BOT_API_URL=
BOT_API_TOKEN=
TELEGRAM_BOT_NAME=${TELEGRAM_BOT_NAME}
CLIENT_BOT_TOKEN=${CLIENT_BOT_TOKEN}

# Email Configuration (optional)
MAIL_SERVER=${MAIL_SERVER}
MAIL_PORT=${MAIL_PORT}
MAIL_USERNAME=${MAIL_USERNAME}
MAIL_PASSWORD=${MAIL_PASSWORD}
EOL

echo "✅ .env file created successfully."
echo ""

# --- Setup Frontend ---
echo "---"
echo "Setting up the frontend..."
echo ""
sudo mkdir -p /opt/frontend/build
sudo cp -r frontend/build/* /opt/frontend/build/
echo "✅ Frontend files copied to /opt/frontend/build."
echo ""

# --- Configure Web Server (NGINX) ---
echo "---"
echo "Configuring NGINX and obtaining SSL certificate..."
echo ""

# Create NGINX config file
sudo bash -c "cat > /etc/nginx/sites-available/${DOMAIN} << EOL
server {
    listen 80;
    server_name ${DOMAIN};

    root /opt/frontend/build;
    index index.html;

    location / {
        try_files \\\$uri \\\$uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \\\$host;
        proxy_set_header X-Real-IP \\\$remote_addr;
        proxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \\\$scheme;
    }

    location /miniapp/ {
        try_files \\\$uri \\\$uri/ /miniapp/index.html;
    }
}
EOL"

# Enable the new site and remove the default
sudo ln -s -f "/etc/nginx/sites-available/${DOMAIN}" /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Test NGINX configuration
sudo nginx -t

# Obtain SSL certificate with Certbot
sudo certbot --nginx -d "${DOMAIN}" --non-interactive --agree-tos -m "${ADMIN_EMAIL}"

# Restart NGINX to apply all changes
sudo systemctl restart nginx

echo "✅ NGINX configured and SSL certificate obtained successfully."
echo ""

# --- Create systemd Services ---
echo "---"
echo "Creating systemd services to run the application and bot as daemons..."
echo ""

# Get the full path to the project directory
PROJECT_DIR=$(pwd)
# Get the current user
CURRENT_USER=$(whoami)

# Create systemd service for the Flask App
sudo bash -c "cat > /etc/systemd/system/astracat-panel.service << EOL
[Unit]
Description=ASTRACAT Cloud Panel
After=network.target

[Service]
User=${CURRENT_USER}
WorkingDirectory=${PROJECT_DIR}
ExecStart=${PROJECT_DIR}/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
EOL"

# Create systemd service for the Telegram Bot
sudo bash -c "cat > /etc/systemd/system/astracat-bot.service << EOL
[Unit]
Description=ASTRACAT Cloud Telegram Bot
After=network.target

[Service]
User=${CURRENT_USER}
WorkingDirectory=${PROJECT_DIR}
ExecStart=${PROJECT_DIR}/venv/bin/python ${PROJECT_DIR}/client_bot.py
Restart=always

[Install]
WantedBy=multi-user.target
EOL"

# Reload systemd, enable and start the services
sudo systemctl daemon-reload
sudo systemctl enable --now astracat-panel.service
sudo systemctl enable --now astracat-bot.service

echo "✅ Systemd services created and started."
echo ""

# --- Create Admin User ---
echo "---"
echo "Creating the initial admin user..."
echo ""

# Wait for the panel to be ready
sleep 5

# Create the admin user
export FLASK_APP=app
venv/bin/flask make-admin "${ADMIN_EMAIL}" "${ADMIN_PASSWORD}"

echo "✅ Admin user created successfully."
echo ""

# --- Perform Rebranding ---
echo "---"
echo "Rebranding the application to ASTRACAT Cloud..."
echo ""

# Replace "StealthNET" with "ASTRACAT Cloud" in all frontend files
sudo find /opt/frontend/build -type f \( -name "*.html" -o -name "*.js" -o -name "*.css" -o -name "*.json" \) -exec sed -i 's/StealthNET/ASTRACAT Cloud/g' {} +

echo "✅ Rebranding completed successfully."
echo ""

# --- Verify Installation ---
echo "---"
echo "Verifying the installation..."
echo ""

# Check service status
PANEL_STATUS=$(systemctl is-active astracat-panel.service)
BOT_STATUS=$(systemctl is-active astracat-bot.service)
NGINX_STATUS=$(systemctl is-active nginx.service)

INSTALL_SUCCESS=true

if [ "$PANEL_STATUS" = "active" ]; then
    echo "✅ ASTRACAT Cloud Panel service is running."
else
    echo "❌ ASTRACAT Cloud Panel service failed to start."
    INSTALL_SUCCESS=false
fi

if [ "$BOT_STATUS" = "active" ]; then
    echo "✅ ASTRACAT Cloud Bot service is running."
else
    echo "❌ ASTRACAT Cloud Bot service failed to start."
    INSTALL_SUCCESS=false
fi

if [ "$NGINX_STATUS" = "active" ]; then
    echo "✅ NGINX service is running."
else
    echo "❌ NGINX service failed to start."
    INSTALL_SUCCESS=false
fi

echo ""

# --- Final Message ---
if [ "$INSTALL_SUCCESS" = true ]; then
    echo "🎉🚀 ASTRACAT Cloud Installation Successful! 🚀🎉"
    echo "================================================="
    echo ""
    echo "You can now access your panel at: https://${DOMAIN}"
    echo "Log in with the admin credentials you provided."
    echo ""
    echo "Thank you for using ASTRACAT Cloud!"
    echo ""
else
    echo "🔥 Installation encountered errors. 🔥"
    echo "======================================="
    echo ""
    echo "Please check the logs for more information:"
    echo "  - Panel Logs: sudo journalctl -u astracat-panel.service"
    echo "  - Bot Logs:   sudo journalctl -u astracat-bot.service"
    echo "  - NGINX Logs: sudo journalctl -u nginx.service"
    echo ""
    echo "If you need assistance, please visit our support channels."
    echo ""
fi
