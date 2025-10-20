#!/bin/bash

# This script deploys the IR-BOT agent to Google Cloud Agent Engine.
# It will prompt for the necessary parameters at runtime.
# IMPORTANT: Make sure you have activated your Python virtual environment before running this script.

# Prompt for user input
read -p "Enter your Google Cloud project ID (e.g., ken-project): " project
read -p "Enter the Google Cloud region (e.g., us-central1): " region
read -p "Enter the GCS staging bucket name (e.g., gs://my-staging-bucket): " staging_bucket
read -p "Enter the agent name in Agent Engine (e.g., ir-bot): " agent_name
read -p "Enter the display name for the agent (e.g., I'm an IR bot): " display_name


# Validate that all required parameters are provided
if [ -z "$project" ] || [ -z "$region" ] || [ -z "$staging_bucket" ]; then
    echo "Error: All parameters (project, region, and staging_bucket) are required."
    exit 1
fi

# Construct and run the deployment command
echo "--------------------------------------------------"
echo "Deploying agent '$agent_name' to Agent Engine with the following parameters:"
echo "Project: $project"
echo "Region: $region"
echo "Staging Bucket: $staging_bucket"
echo "Display Name: $display_name"
echo "--------------------------------------------------"

adk deploy agent_engine \
    --project="$project" \
    --region="$region" \
    --staging_bucket="$staging_bucket" \
    --display_name="$display_name" \
    "$agent_name"

echo "Deployment process initiated."
