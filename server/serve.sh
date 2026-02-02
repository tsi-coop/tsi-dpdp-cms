#!/bin/bash

# Source the .env file to load variables into the current shell session
# Adjust path if .env is not in the same directory as the script
if [ -f ./.env ]; then
    source ./.env
else
    echo "Error: .env file not found. Please create it."
    exit 1
fi

export JAVA_HOME=$JAVA_HOME
export TSI_DPDP_CMS_ENV=$TSI_DPDP_CMS_ENV
export TSI_DPDP_CMS_HOME=$TSI_DPDP_CMS_HOME
export POSTGRES_HOST=$POSTGRES_HOST
export POSTGRES_DB=$POSTGRES_DB
export POSTGRES_USER=$POSTGRES_USER
export POSTGRES_PASSWD=$POSTGRES_PASSWD
export JETTY_HOME=$JETTY_HOME
export JETTY_BASE=$JETTY_BASE
export TSI_EXPORT_PATH=$TSI_EXPORT_PATH
cp $TSI_DPDP_CMS_HOME/target/tsi_dpdp_cms.war $JETTY_BASE/webapps/ROOT.war
java -jar $JETTY_HOME/start.jar