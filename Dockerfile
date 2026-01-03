FROM python:3.13-slim

# Install nmap and system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Set workdir
WORKDIR /app

# Copy requirements and install
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy app code
COPY scan_bot.py /app/scan_bot.py

# Use environment variable for token
ENV BOT_TOKEN=""

# Run the bot
CMD ["python", "scan_bot.py"]
