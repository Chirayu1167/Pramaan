# Automated Firebase & Cloud Run Deployment Script for Pramaan (PowerShell)
param(
    [Parameter(Mandatory=$false)]
    [string]$ProjectId = "pramaan-1",
    [Parameter(Mandatory=$false)]
    [string]$Region = "us-central1"
)

if (-not $ProjectId) {
    $ProjectId = Read-Host "Enter your Firebase / Google Cloud Project ID"
}

if (-not $ProjectId) {
    Write-Error "Project ID is required."
    exit 1
}

Write-Host "==> [1/4] Setting active GCP project to '$ProjectId'..." -ForegroundColor Cyan
gcloud config set project $ProjectId

Write-Host "==> [2/4] Building Docker container on Cloud Build..." -ForegroundColor Cyan
gcloud builds submit --tag "gcr.io/$ProjectId/pramaan-backend"

Write-Host "==> [3/4] Deploying to Cloud Run (Service: pramaan-backend)..." -ForegroundColor Cyan
gcloud run deploy pramaan-backend `
    --image "gcr.io/$ProjectId/pramaan-backend" `
    --platform managed `
    --region $Region `
    --allow-unauthenticated `
    --memory 1Gi `
    --cpu 1 `
    --timeout 120

Write-Host "==> [4/4] Deploying Firebase Hosting & Firestore Rules..." -ForegroundColor Cyan
firebase deploy --only hosting,firestore:rules --project $ProjectId

Write-Host "`nDeployment complete! You can view your app at https://$ProjectId.web.app" -ForegroundColor Green
