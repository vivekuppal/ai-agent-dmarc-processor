# Introduction
Event based processing of dmarc reports. Triggered by pub sub when a new report file is placed in the GCS bucket.


# Running the app locally
```
SET DATABASE_URL=
SET GOOGLE_BUCKET=<optional> # Not needed if testing locally
```

Invoke the app locally
```
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

To test<br/>
Place a sample DMARC aggregate report in app/test_dmarc_sample.xml<br/>
Invoke the URL - http://127.0.0.1:8080/local-test


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
