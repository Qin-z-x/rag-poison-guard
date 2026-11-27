# Deployment runbook

The API service is deployed with the standard pipeline. No customer data is
stored in this document.

## Steps

1. Run the migration job.
2. Deploy the new build to the staging cluster.
3. Verify the health endpoint and the dashboards.

```bash
kubectl rollout status deployment/api
```

The rendering pipeline strips HTML comments and inline styles before indexing,
so documentation examples such as `<div style="display:none">` are treated as
code, not as hidden content.
