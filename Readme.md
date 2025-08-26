# Introduction
Event based processing of dmarc reports. Triggered by pub sub when a new report file is placed in the GCS bucket.


# Running the app locally
```
SET DATABASE_URL=
SET GOOGLE_BUCKET=


```

Two ways to invoke the app locally
```
python -m app.main
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

# Deploying the app on GCS

```
secret DATABASE_URL=
SET GOOGLE_BUCKET=
SET GCE_ENV=True
```

Test the non triggered endpoints <br/>
This will require to give the user account ability to impersonate the pub sub service account.
```
gcloud iam service-accounts add-iam-policy-binding ^
  pubsub-push-dmarc-processor-sa@lappuai-prod.iam.gserviceaccount.com ^
  --member="user:vivek.uppal@gmail.com" ^
  --role="roles/iam.serviceAccountTokenCreator" ^
  --project lappuai-prod
```

```
test.bat
```
