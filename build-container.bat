REM Ensure all required environment variables are set and in sync with create-agent.bat

@echo on
set PROJECT_ID=lappuai-prod
set SERVICE=ai-agent-dmarc-processor
set REGION=us-east1
set RUNTIME_SA_NAME=ai-agent-dmarc-processor-sa
set RUNTIME_SA=%RUNTIME_SA_NAME%@%PROJECT_ID%.iam.gserviceaccount.com
set ENV_COMPONENT_NAME=%SERVICE%
set ENV_EXPECTED_EVENT_TYPE=OBJECT_FINALIZE
set ENV_OBJECT_PREFIX=reports/
set ENV_OUTPUT_PREFIX=outputs/%SERVICE%/
set PUSH_SA_NAME=pubsub-push-dmarc-processor-sa
set PUSH_SA=%PUSH_SA_NAME%@%PROJECT_ID%.iam.gserviceaccount.com
set CONNECTOR=lai-vpc-connector


for /f %%I in ('powershell -NoProfile -Command "(Get-Date).ToString('yyyyMMdd-HHmmss')"') do set "TS=%%I"
set IMAGE=gcr.io/%PROJECT_ID%/%SERVICE%:%TS%


call gcloud builds submit --tag "%IMAGE%" --project "%PROJECT_ID%"
timeout /t 5

@echo on
REM Deploy Cloud Run (private)
call gcloud run deploy "%SERVICE%" ^
  --image "%IMAGE%" ^
  --region "%REGION%" ^
  --service-account "%RUNTIME_SA%" ^
  --no-allow-unauthenticated ^
  --concurrency 10 ^
  --memory 512Mi ^
  --timeout 60 ^
  --platform managed ^
  --project "%PROJECT_ID%" ^
  --set-env-vars COMPONENT_NAME=%ENV_COMPONENT_NAME%,EXPECTED_EVENT_TYPE=%ENV_EXPECTED_EVENT_TYPE%,OBJECT_PREFIX=%ENV_OBJECT_PREFIX%,OUTPUT_PREFIX=%ENV_OUTPUT_PREFIX%,GCE_ENV=true,GCP_PROJECT_ID=%PROJECT_ID% ^
  --set-secrets DATABASE_URL=ASYNC_DATABASE_URL:latest ^
  --vpc-connector "%CONNECTOR%" ^
  --vpc-egress=private-ranges-only

@echo on
echo Granting run.invoker on %SERVICE% to %PUSH_SA%
call gcloud run services add-iam-policy-binding "%SERVICE%" --region "%REGION%" --project "%PROJECT_ID%" --member="serviceAccount:%PUSH_SA%" --role="roles/run.invoker"
