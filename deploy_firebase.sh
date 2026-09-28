#!/usr/bin/env bash
set -e

PROJECT_ID=${1:-"pramaan-1"}
REGION=${2:-"us-central1"}

if [ -z "$PROJECT_ID" ]; then
    read -p "Enter your Firebase / Google Cloud Project ID: " PROJECT_ID
fi

if [ -z "$PROJECT_ID" ]; then
    echo "Error: Project ID is required."
    exit 1
fi

echo "==> [1/4] Setting active GCP project to '$PROJECT_ID'..."
gcloud config set project "$PROJECT_ID"

echo "==> [2/4] Building Docker container on Cloud Build..."
gcloud builds submit --tag "gcr.io/$PROJECT_ID/pramaan-backend"

echo "==> [3/4] Deploying to Cloud Run (Service: pramaan-backend)..."
gcloud run deploy pramaan-backend \
    --image "gcr.io/$PROJECT_ID/pramaan-backend" \
    --platform managed \
    --region "$REGION" \
    --allow-unauthenticated \
    --memory 1Gi \
    --cpu 1 \
    --timeout 120

echo "==> [4/4] Deploying Firebase Hosting & Firestore Rules..."
firebase deploy --only hosting,firestore:rules --project "$PROJECT_ID"

echo -e "\nDeployment complete! You can view your app at https://${PROJECT_ID}.web.app"
