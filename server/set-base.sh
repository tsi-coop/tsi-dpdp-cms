#!/bin/bash

# Source the .env file to load variables into the current shell session
# Adjust path if .env is not in the same directory as the script
if [ -f ./.env ]; then
    source ./.env
else
    echo "Error: .env file not found. Please create it."
    exit 1
fi

export JETTY_HOME=$JETTY_HOME
java -jar $JETTY_HOME/start.jar --add-modules=http,jdbc,jndi,ee10-deploy