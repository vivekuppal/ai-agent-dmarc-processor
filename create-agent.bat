REM @echo off
setlocal EnableExtensions EnableDelayedExpansion
REM ===========================================================
REM  Create AI Agent Infra (Windows CMD)
REM  - Enables APIs
REM  - Creates SAs + IAM
REM  - Builds (Cloud Build) and deploys Cloud Run
REM  - Creates Pub/Sub topic, DLQ, filtered push subscription
REM  - Wires GCS bucket notifications -> Pub/Sub
REM ===========================================================

REM ========== CONFIG (EDIT ME) ==========
set PROJECT_ID=lappuai-prod
echo PROJECT_ID=%PROJECT_ID%
set REGION=us-east1

REM Ingest bucket (no gs://)
set BUCKET=lai-dmarc-reports
set CONNECTOR=lai-vpc-connector

REM Component / service name (deploy one per run)
set SERVICE=ai-agent-dmarc-processor

REM Pub/Sub plumbing
set TOPIC=ai-agent-dmarc-processor-topic
set SUB=ai-agent-dmarc-processor-sub

REM GCS object prefix to trigger on (can be empty for all)
set OBJECT_PREFIX=reports/

REM Subscription filter:
REM Use doubled quotes inside the value to survive CMD parsing.
set FILTER=attributes.eventType=""OBJECT_FINALIZE"" AND hasPrefix(attributes.objectId,""%OBJECT_PREFIX%"")

REM Dead-letter topic name (defaults to dlq.<SUB> if left blank)
set DLQ_TOPIC=

REM Service accounts (names only)
set RUNTIME_SA_NAME=ai-agent-dmarc-processor-sa
set PUSH_SA_NAME=pubsub-push-dmarc-processor-sa

REM ===== Optional Cloud Run runtime envs for the app =====
set ENV_COMPONENT_NAME=%SERVICE%
set ENV_EXPECTED_EVENT_TYPE=OBJECT_FINALIZE
set ENV_OBJECT_PREFIX=%OBJECT_PREFIX%
set ENV_OUTPUT_PREFIX=outputs/%SERVICE%/
REM Set REQUIRE_JWT=true if you want the app to verify the OIDC token too.
set ENV_REQUIRE_JWT=true
REM PUBSUB_ALLOWED_AUDIENCE is set AFTER deploy since we need the service URL.

REM ========== DERIVED ==========
for /f %%P in ('call gcloud projects describe "%PROJECT_ID%" --format^=value^(projectNumber^) -q') do set "PROJECT_NUMBER=%%P"
REM All application specific privileges should be granted to the runtime service account.
set RUNTIME_SA=%RUNTIME_SA_NAME%@%PROJECT_ID%.iam.gserviceaccount.com
set PUSH_SA=%PUSH_SA_NAME%@%PROJECT_ID%.iam.gserviceaccount.com
set PUBSUB_SERVICE_AGENT=service-%PROJECT_NUMBER%@gcp-sa-pubsub.iam.gserviceaccount.com
set GCS_SERVICE_AGENT=service-%PROJECT_NUMBER%@gs-project-accounts.iam.gserviceaccount.com

set DLQ_TOPIC=dlq.%SUB%

:: Enable necessary APIs
echo -^> Enabling required APIs
call gcloud services enable run.googleapis.com pubsub.googleapis.com storage.googleapis.com cloudbuild.googleapis.com ^
  secretmanager.googleapis.com vpcaccess.googleapis.com iamcredentials.googleapis.com --project "%PROJECT_ID%"


REM Timestamp safe for docker tags (no colons)
for /f %%I in ('powershell -NoProfile -Command "(Get-Date).ToString('yyyyMMdd-HHmmss')"') do set "TS=%%I"
set IMAGE=gcr.io/%PROJECT_ID%/%SERVICE%:%TS%

echo === Creating infra for project: %PROJECT_ID% (region: %REGION%) ===
echo SERVICE=%SERVICE%
echo TOPIC=%TOPIC%, SUB=%SUB%, DLQ=%DLQ_TOPIC%
echo BUCKET=%BUCKET%, OBJECT_PREFIX=%OBJECT_PREFIX%
echo IMAGE=%IMAGE%
echo.

echo %PROJECT_ID%
REM (Optional) Force-create Pub/Sub service identity if it hasn't appeared yet
call gcloud beta services identity create --service=pubsub.googleapis.com --project "%PROJECT_ID%"
@echo on

echo Completed creation of identity

REM 1) Check for existence of service accounts and create if missing
echo Check service accounts

for /f %%I in ('call gcloud iam service-accounts list --project %PROJECT_ID% --filter="email:%RUNTIME_SA_NAME%" --format^=value^(email^)') do set "RESULT1=%%I"

if defined RESULT1 (
    echo Service account %RUNTIME_SA_NAME% already exists.
) else (
    echo Creating service account %RUNTIME_SA_NAME%...
    call gcloud iam service-accounts create "%RUNTIME_SA_NAME%" ^
        --project "%PROJECT_ID%" ^
        --display-name "AI DMARC processor Agent Runtime SA"
)

@echo on
timeout /t 5

for /f %%I in ('call gcloud iam service-accounts list --project %PROJECT_ID% --filter="email:%PUSH_SA_NAME%" --format^=value^(email^)') do set "RESULT2=%%I"

if defined RESULT2 (
    echo Service account %PUSH_SA_NAME% already exists.
) else (
    echo Creating service account %PUSH_SA_NAME%...
    call gcloud iam service-accounts create "%PUSH_SA_NAME%" ^
        --project "%PROJECT_ID%" ^
        --display-name "Pub/Sub Push DMARC processor Invoker SA"
)

@echo on
timeout /t 5
REM 2) Bucket-scoped IAM for Runtime SA
echo Granting bucket IAM to runtime SA on gs://%BUCKET%
@echo on
REM call gcloud storage buckets add-iam-policy-binding "gs://%BUCKET%" --member="serviceAccount:%RUNTIME_SA%" --role="roles/storage.objectViewer"  --project "%PROJECT_ID%"
@echo on
REM call gcloud storage buckets add-iam-policy-binding "gs://%BUCKET%" --member="serviceAccount:%RUNTIME_SA%" --role="roles/storage.objectCreator" --project "%PROJECT_ID%"
@echo on
REM Full control over objects in the bucket (get/list/create/delete/overwrite)
call gcloud storage buckets add-iam-policy-binding "gs://%BUCKET%" --member="serviceAccount:%RUNTIME_SA%" --role="roles/storage.objectAdmin" --project "%PROJECT_ID%"

REM The Cloud Run runtime SA must have VPC Access User
call gcloud projects add-iam-policy-binding "%PROJECT_ID%" --member="serviceAccount:%RUNTIME_SA%" --role="roles/vpcaccess.user"
@echo on
timeout /t 5

REM 3) Allow Pub/Sub service agent to mint OIDC token for PUSH_SA
echo Granting roles/iam.serviceAccountTokenCreator on %PUSH_SA% to %PUBSUB_SERVICE_AGENT%
call gcloud iam service-accounts add-iam-policy-binding "%PUSH_SA%" ^
  --member="serviceAccount:%PUBSUB_SERVICE_AGENT%" ^
  --role="roles/iam.serviceAccountTokenCreator" ^
  --project "%PROJECT_ID%"

REM 4) Build container (Cloud Build) and push to gcr.io
@echo on
echo Building image %IMAGE%
call gcloud builds submit --tag "%IMAGE%" --project "%PROJECT_ID%"
timeout /t 5

call gcloud secrets add-iam-policy-binding DATABASE_URL --member="serviceAccount:%RUNTIME_SA%" --role="roles/secretmanager.secretAccessor" --project "%PROJECT_ID%"
call gcloud secrets add-iam-policy-binding STAGING_DATABASE_URL --member="serviceAccount:%RUNTIME_SA%" --role="roles/secretmanager.secretAccessor" --project "%PROJECT_ID%"
timeout /t 5

REM 5) Deploy Cloud Run (private)
@echo on
echo Deploying Cloud Run service %SERVICE%
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
  --set-env-vars COMPONENT_NAME=%ENV_COMPONENT_NAME%,EXPECTED_EVENT_TYPE=%ENV_EXPECTED_EVENT_TYPE%,OBJECT_PREFIX=%ENV_OBJECT_PREFIX%,OUTPUT_PREFIX=%ENV_OUTPUT_PREFIX%,GCE_ENV=true,GCP_PROJECT_ID=%PROJECT_ID%,GOOGLE_BUCKET=%BUCKET% ^
  --vpc-connector "%CONNECTOR%" ^
  --vpc-egress=private-ranges-only
REM --set-secrets DATABASE_URL=STAGING_DATABASE_URL:latest ^

REM 6) Get service URL
for /f "usebackq tokens=*" %%U in (`gcloud run services describe "%SERVICE%" --region "%REGION%" --project "%PROJECT_ID%" --format^=value^(status.url^)`) do set "SERVICE_URL=%%U"
echo    Service URL: %SERVICE_URL%

REM 7) Grant run.invoker to PUSH_SA
echo Granting run.invoker on %SERVICE% to %PUSH_SA%
call gcloud run services add-iam-policy-binding "%SERVICE%" --region "%REGION%" --project "%PROJECT_ID%" --member="serviceAccount:%PUSH_SA%" --role="roles/run.invoker"

REM 8) (Optional) In-app JWT verification audience
if /I "%ENV_REQUIRE_JWT%"=="true" (
  echo -^> Enabling in-app JWT verification (REQUIRE_JWT=true, AUD=%SERVICE_URL%)
  call gcloud run services update "%SERVICE%" --region "%REGION%" --project "%PROJECT_ID%" --update-env-vars REQUIRE_JWT=true,PUBSUB_ALLOWED_AUDIENCE=%SERVICE_URL%
)

REM 9) Pub/Sub topic + DLQ
echo Creating Pub/Sub topic %TOPIC% and DLQ %DLQ_TOPIC%
REM TODO: check if the topic already exists, do not create if it does
call gcloud pubsub topics create "%TOPIC%"    --project "%PROJECT_ID%"
REM TODO: check if the topic already exists, do not create if it does
call gcloud pubsub topics create "%DLQ_TOPIC%" --project "%PROJECT_ID%"

REM 10) Allow service agent to publish to DLQ
call gcloud pubsub topics add-iam-policy-binding "%DLQ_TOPIC%" --member="serviceAccount:%PUBSUB_SERVICE_AGENT%" --role="roles/pubsub.publisher" --project "%PROJECT_ID%"

REM call gcloud secrets add-iam-policy-binding SMTP_PASSWORD --member="serviceAccount:%PUBSUB_SERVICE_AGENT%" --role="roles/secretmanager.secretAccessor" --project "%PROJECT_ID%"
REM call gcloud secrets add-iam-policy-binding SMTP_PASSWORD --member="serviceAccount:%RUNTIME_SA%" --role="roles/secretmanager.secretAccessor" --project "%PROJECT_ID%"

@echo on
REM 11) Create filtered push subscription with OIDC auth + DLQ
echo Creating subscription %SUB% (filter + push auth + DLQ)
call gcloud pubsub subscriptions create "%SUB%" ^
  --topic="%TOPIC%" ^
  --message-filter="%FILTER%" ^
  --push-endpoint="%SERVICE_URL%/trigger" ^
  --push-auth-service-account="%PUSH_SA%" ^
  --push-auth-token-audience="%SERVICE_URL%/trigger" ^
  --dead-letter-topic="%DLQ_TOPIC%" ^
  --max-delivery-attempts=10 ^
  --min-retry-delay=10s ^
  --max-retry-delay=600s ^
  --project "%PROJECT_ID%"


REM 12) (DLQ flow) Let service agent ack when forwarding to DLQ
call gcloud pubsub subscriptions add-iam-policy-binding "%SUB%" --member="serviceAccount:%PUBSUB_SERVICE_AGENT%" --role="roles/pubsub.subscriber" --project "%PROJECT_ID%"

REM 13) Allow GCS to publish to the main topic (explicit; CLI often does this automatically)
echo Granting Pub/Sub publisher on %TOPIC% to GCS service agent %GCS_SERVICE_AGENT%
call gcloud pubsub topics add-iam-policy-binding "%TOPIC%" --member="serviceAccount:%GCS_SERVICE_AGENT%" --role="roles/pubsub.publisher" --project "%PROJECT_ID%"

REM 14) Create GCS bucket notification (OBJECT_FINALIZE only, optional prefix)
echo Creating GCS notification on gs://%BUCKET% -^> topic %TOPIC%
if "%OBJECT_PREFIX%"=="" (
  call gcloud storage buckets notifications create "gs://%BUCKET%" --topic="%TOPIC%" --event-types=OBJECT_FINALIZE --payload-format=json --project="%PROJECT_ID%"
) else (
  call gcloud storage buckets notifications create "gs://%BUCKET%" --topic="%TOPIC%" --event-types=OBJECT_FINALIZE --payload-format=json --object-prefix="%OBJECT_PREFIX%" --project="%PROJECT_ID%"
)

:: update Cloud Run env (after deploy) to match
call gcloud run services update "%SERVICE%" ^
  --region "%REGION%" --project "%PROJECT_ID%" ^
  --update-env-vars PUBSUB_ALLOWED_AUDIENCE=%SERVICE_URL%/trigger

REM to invoke the non triggered endpoints requires to give the user account ability to impersonate the pub sub service account.
REM Uncomment the below lines if you wish to run the test.bat script

REM call gcloud iam service-accounts add-iam-policy-binding ^
REM   pubsub-push-dmarc-processor-sa@lappuai-prod.iam.gserviceaccount.com ^
REM   --member="user:vivek.uppal@gmail.com" ^
REM   --role="roles/iam.serviceAccountTokenCreator" ^
REM   --project lappuai-prod

REM call gcloud iam service-accounts add-iam-policy-binding ^
REM   pubsub-push-dmarc-processor-sa@lappuai-prod.iam.gserviceaccount.com ^
REM   --member="user:vivek.uppal@gmail.com" ^
REM   --role="roles/iam.serviceAccountUser" ^
REM   --project lappuai-prod


echo.
echo === All set! ===
echo Service:   %SERVICE%   URL: %SERVICE_URL%
echo Topic:     %TOPIC%
echo Sub:       %SUB%       DLQ: %DLQ_TOPIC%
echo Bucket:    gs://%BUCKET% (prefix=%OBJECT_PREFIX%)
echo.
echo To add another component, re-run with new SERVICE/SUB/OBJECT_PREFIX and (optionally) adjust FILTER.
endlocal
