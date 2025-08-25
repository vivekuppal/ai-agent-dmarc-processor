# Introduction
Event based processing of dmarc reports. Triggered by pub sub when a new report file is placed in the GCS bucket.


# Running the app locally
```
SET DATABASE_URL=
SET GOOGLE_BUCKET=
set SMTP_PASSWORD=

```

Two ways to invoke the app locally
```
python -m app.main
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

# Deploying the app in production

```
secret DATABASE_URL=
SET GOOGLE_BUCKET=
secret SMTP_PASSWORD=
SET GCE_ENV=True
```