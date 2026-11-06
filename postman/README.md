# Postman collection: plugin flow replica

`HydrantID-Plugin-Flow.postman_collection.json` has one request per method in
`HydrantIdClient.cs`, grouped into folders that mirror the plugin's actual
call order for an enroll-with-DCV flow: connectivity check, list policies,
domain validation (list/create/check), submit CSR, retrieve/list
certificates, revoke, renew. Each request's description names the
`HydrantIdClient`/`RequestManager` method and file:line it mirrors.

## Setup

1. Import both files into Postman: the collection and
   `HydrantID-Staging.postman_environment.json`.
2. Copy the environment to a local file and fill in real values — **do not
   put real Hawk credentials into the tracked template**:

   ```
   cp postman/HydrantID-Staging.postman_environment.json postman/HydrantID-Staging.postman_environment.local.json
   ```

   `*.postman_environment.local.json` under `postman/` is gitignored.
3. In Postman, select the local environment and fill in `hawkAuthId` /
   `hawkAuthKey` (marked as secret) plus whichever of `policyId`,
   `validatorId`, `domainName`, `csr`, etc. you're testing with.

Auth (Hawk, `sha256`) is configured once at the collection level and
inherited by every request.

## Known discrepancy to check

"Get Certificate by CSR Tracking Id" calls `GET /api/v2/csr/{id}/certificate`,
which is not a path documented in HydrantID's swagger (which only documents
`GET /api/v2/csr/{id}/status`). If that request 404s against real HydrantID,
flag it — the plugin may need to poll `/status` and then fetch
`/certificates/{certificateId}` instead.
