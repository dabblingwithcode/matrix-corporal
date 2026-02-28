# HTTP API reference

All endpoints require **Bearer token** authentication. Set your token in config (`HttpApi.AuthorizationBearerToken`) and pass it in the `Authorization` header.

**Base URL:** Your HTTP API server (e.g. `http://localhost:41081` when `HttpApi.ListenAddress` is `0.0.0.0:41081`).

**Auth header:** `Authorization: Bearer YOUR_TOKEN`

---

## Policy

### GET policy

Returns the current policy.

```bash
curl -s -X GET \
  -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:41081/_matrix/corporal/policy"
```

**Response (200):** `{"policy": { ... }}`

---

### PUT policy

Set the policy. Body must be valid policy JSON.

```bash
curl -s -X PUT \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"users":{},"schemaVersion":1}' \
  "http://localhost:41081/_matrix/corporal/policy"
```

**Response (200):** `{}`  
**Errors:** `400` – bad JSON; `200` with `errcode` – set failed (e.g. validation).

---

### POST policy provider reload

Trigger a reload of the policy provider (e.g. re-read file or HTTP).

```bash
curl -s -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:41081/_matrix/corporal/policy/provider/reload"
```

**Response (200):** `{}`

---

## User (access tokens)

### POST obtain new access token

Obtain a new Matrix access token for a user. `userId` must be a full MXID on your homeserver (e.g. `@alice:example.com`).

```bash
curl -s -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"deviceId":"DEVICE_ID","validitySeconds":3600}' \
  "http://localhost:41081/_matrix/corporal/user/%40alice%3Aexample.com/access-token/new"
```

**Body:**
- `deviceId` (string, required)
- `validitySeconds` (number, optional) – token validity; may be ignored by Synapse

**Response (200):** `{"accessToken":"syt_..."}`  
**Errors:** `400` – bad userId / bad JSON / missing deviceId; `200` with `errcode` – obtain failed.

---

### DELETE release access token

Invalidate (logout) a specific access token for a user.

```bash
curl -s -X DELETE \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"accessToken":"syt_..."}' \
  "http://localhost:41081/_matrix/corporal/user/%40alice%3Aexample.com/access-token"
```

**Body:**
- `accessToken` (string, required)

**Response (200):** `{}`  
**Errors:** `400` – bad userId / bad JSON / missing accessToken; `200` with `errcode` – destroy failed.

---

## Logs

### GET list logs

List stored log entries (newest first). Optional query: `limit` (default 50, max 500), `offset` (default 0).

```bash
curl -s -X GET \
  -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:41081/_matrix/corporal/logs"
```

With pagination:

```bash
curl -s -X GET \
  -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:41081/_matrix/corporal/logs?limit=100&offset=0"
```

**Response (200):** `{"logs":[{"id":"...","time":"...","level":"info","message":"...","fields":{...}}],"total":N}`

---

### DELETE one log

Delete a single log entry by id.

```bash
curl -s -X DELETE \
  -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:41081/_matrix/corporal/logs/123"
```

**Response (204):** no body  
**Errors:** `400` – missing log id; `404` – log entry not found.

---

### DELETE all logs

Clear all stored log entries.

```bash
curl -s -X DELETE \
  -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:41081/_matrix/corporal/logs"
```

**Response (204):** no body

---

### GET logs config

Return which log levels are currently stored (e.g. debug on/off).

```bash
curl -s -X GET \
  -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:41081/_matrix/corporal/logs/config"
```

**Response (200):** `{"levels":{"trace":false,"debug":false,"info":true,"warning":true,"error":true,"fatal":true,"panic":true}}`

---

### PUT logs config

Set which log levels to store. Only levels you send are applied; others are unchanged. At least one level is required.

Exclude debug (default-like):

```bash
curl -s -X PUT \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"levels":{"debug":false,"info":true,"warning":true,"error":true,"fatal":true,"panic":true}}' \
  "http://localhost:41081/_matrix/corporal/logs/config"
```

Include debug:

```bash
curl -s -X PUT \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"levels":{"debug":true,"info":true}}' \
  "http://localhost:41081/_matrix/corporal/logs/config"
```

**Response (200):** `{"levels":{...}}` (current filter after update)  
**Errors:** `400` – bad JSON or empty `levels`.

---

## Gateway: encrypted auth (client-facing)

These endpoints are on the **HTTP Gateway** (e.g. `http://localhost:41080`), not the management API. They do **not** use Bearer token; the client sends encrypted credentials. Corporal decrypts with `Misc.DecryptKey` from config, then proxies to Synapse’s normal `/login` and `/account/password`. Ensure `DecryptKey` is set in config or the gateway returns an error.

---

### POST encryptedLogin

Login with encrypted credentials. Path supports `r0` or `v1`, `v2`, etc.

**Path:** `POST /_matrix/client/{apiVersion}/encryptedLogin`  
Example: `POST /_matrix/client/r0/encryptedLogin`

**Request body:** Same shape as Matrix Client-Server [login](https://spec.matrix.org/v1.9/client-server-api/#post_matrixclientv3login), except:

- `password` – **required.** AES-CBC (Base64) encrypted string that decrypts to `username*password` (two parts separated by `*`).
- `identifier.user` (or legacy `user`) – **required.** PIN string appended to the decrypted password before forwarding to Synapse (e.g. `"1234"`).

```bash
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "type": "m.login.password",
    "identifier": { "type": "m.id.user", "user": "PIN_OR_USER_ID" },
    "password": "BASE64_AES_CBC_ENCRYPTED_USERNAME_STAR_PASSWORD"
  }' \
  "http://localhost:41080/_matrix/client/r0/encryptedLogin"
```

**Response:** Same as Synapse `POST /_matrix/client/.../login` (e.g. `access_token`, `device_id`, `user_id`).  
**Errors:** `400` / `403` – bad JSON, decryption failure, or policy (e.g. deactivated user).

---

### POST encryptedPassword

Change account password using encrypted auth. Path supports `r0` or `v1`, `v2`, etc.

**Path:** `POST /_matrix/client/{apiVersion}/account/encryptedPassword`  
Example: `POST /_matrix/client/r0/account/encryptedPassword`

**Request body:**

- `auth.password` – **required.** AES-CBC (Base64) encrypted string that decrypts to `username*password`.
- `auth.identifier` – **required.** PIN: either a string (e.g. `"1234"`) or an object `{ "user": "1234" }`.
- `new_password` – (optional) new password to set.
- `logout_devices` – (optional) whether to invalidate other sessions.

```bash
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "auth": {
      "password": "BASE64_AES_CBC_ENCRYPTED_USERNAME_STAR_PASSWORD",
      "identifier": "1234"
    },
    "logout_devices": false,
    "new_password": "newPlainPassword"
  }' \
  "http://localhost:41080/_matrix/client/r0/account/encryptedPassword"
```

With identifier as object:

```bash
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "auth": {
      "password": "BASE64_AES_CBC_ENCRYPTED_USERNAME_STAR_PASSWORD",
      "identifier": { "user": "1234" }
    },
    "new_password": "newPlainPassword"
  }' \
  "http://localhost:41080/_matrix/client/r0/account/encryptedPassword"
```

**Response:** Same as Synapse `POST /_matrix/client/.../account/password`:
- **200** – password changed (body `{}`).
- **401** – homeserver requires [additional interactive auth](https://spec.matrix.org/v1.9/client-server-api/#user-interactive-authentication-api) (e.g. `session`, `flows` like `m.login.email.identity`). The client must repeat the request with the same `session` and the extra auth data; the password is only changed after all required stages complete.

**Errors:** `400` – bad JSON, missing `auth.password` or `auth.identifier`, or decryption failure.

---

## Error format

Failed requests return JSON like:

```json
{"errcode":"M_BAD_JSON","error":"Bad body payload"}
```

Common errcodes: `M_MISSING_TOKEN`, `M_UNKNOWN_TOKEN`, `M_BAD_JSON`, `M_UNKNOWN`, `M_INVALID_USERNAME`, `M_MISSING_PARAM`, `M_NOT_FOUND`.
