@echo on

set SERVICE_URL=https://ai-agent-dmarc-processor-rfoksailya-ue.a.run.app

for /f "usebackq tokens=*" %%I in (`
  gcloud auth print-identity-token ^
    --impersonate-service-account=pubsub-push-dmarc-processor-sa@lappuai-prod.iam.gserviceaccount.com ^
    --audiences="%SERVICE_URL%"
`) do set "IDTOKEN=%%I"

curl -H "Authorization: Bearer %IDTOKEN%" "%SERVICE_URL%/list-all-bucket-files"
