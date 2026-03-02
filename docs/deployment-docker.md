# Deploying Matrix-Corporal to a VPS using Docker

**This is heavily based on https://github.com/inf0rmatix/serverpod_vps and AI generated !**
This guide walks you through deploying the full matrix-corporal stack to a Virtual Private Server (VPS) with Docker.

The deployment includes:

- **Traefik** reverse proxy with automatic Let's Encrypt TLS certificates
- **PostgreSQL** database for Synapse
- **Matrix Synapse** homeserver
- **Element-web** Matrix client
- **matrix-corporal** gateway and reconciliation proxy

GitHub Actions builds the matrix-corporal Docker image, pushes it to the GitHub Container Registry (GHCR), substitutes secrets into config templates, copies everything to the VPS, and starts the stack. All secrets are stored as GitHub repository secrets -- nothing sensitive is committed to git.

## Prerequisites

- A GitHub repository containing the matrix-corporal source code
- A VPS with at least 2 GB RAM (4 GB recommended)
- A domain name with DNS access
- Basic knowledge of Docker, SSH, and command-line usage
- Terminal commands in this guide are for Unix-based systems (macOS & Linux)

## Table of Contents

- [Deploying Matrix-Corporal to a VPS using Docker](#deploying-matrix-corporal-to-a-vps-using-docker)
  - [Prerequisites](#prerequisites)
  - [Table of Contents](#table-of-contents)
  - [Architecture overview](#architecture-overview)
  - [Preparing the server](#preparing-the-server)
    - [Registering at Hetzner Cloud](#registering-at-hetzner-cloud)
    - [Setting up an SSH key to connect to the server](#setting-up-an-ssh-key-to-connect-to-the-server)
    - [Creating a new server](#creating-a-new-server)
    - [Setting up the server](#setting-up-the-server)
      - [Step 1: Create a deployment user](#step-1-create-a-deployment-user)
      - [Step 2: Grant Docker permissions](#step-2-grant-docker-permissions)
      - [Step 3: Enable SSH access](#step-3-enable-ssh-access)
      - [Step 4: Set up SSH key-based authentication](#step-4-set-up-ssh-key-based-authentication)
      - [Step 5: Create the deployment directory](#step-5-create-the-deployment-directory)
    - [Firewall configuration](#firewall-configuration)
  - [Preparing the domain](#preparing-the-domain)
  - [Preparing the repository](#preparing-the-repository)
    - [Adding the secrets to the repository](#adding-the-secrets-to-the-repository)
  - [Configuring the GitHub Action](#configuring-the-github-action)
    - [How the workflow works](#how-the-workflow-works)
  - [First deployment](#first-deployment)
    - [Generating the Synapse signing key](#generating-the-synapse-signing-key)
    - [Running the workflow](#running-the-workflow)
    - [Creating the system user](#creating-the-system-user)
  - [Subsequent deployments](#subsequent-deployments)
  - [Updating the policy](#updating-the-policy)
  - [Connecting to the database](#connecting-to-the-database)
  - [Troubleshooting](#troubleshooting)
    - [Checking service logs](#checking-service-logs)
    - [Synapse won't start](#synapse-wont-start)
    - [TLS certificate issues](#tls-certificate-issues)
    - [matrix-corporal can't reach Synapse](#matrix-corporal-cant-reach-synapse)
    - [Shared secrets don't match](#shared-secrets-dont-match)
    - [Restarting services](#restarting-services)
    - [Viewing the running containers](#viewing-the-running-containers)

## Architecture overview

In production, all HTTP traffic enters through Traefik on ports 80/443. Traefik terminates TLS and routes requests based on the hostname:

```
Internet (HTTPS)
    |
    v
 Traefik (:80/:443)
    |
    +-- matrix.your-domain.com --> matrix-corporal (:41080) --> Synapse (:8008) --> Postgres (:5432)
    |                                       ^
    |                                       | (REST auth callback)
    |                              Synapse -+
    |
    +-- element.your-domain.com --> Element-web (:8080)
```

- **matrix-corporal** sits in front of Synapse as a gateway. All Matrix client API requests go through it.
- **Synapse** calls back to matrix-corporal for password authentication via the `rest_auth_provider` module.
- **Element-web** is configured to talk to the matrix-corporal gateway URL (not directly to Synapse).

User IDs will be `@username:your-domain.com` (the Synapse `server_name` is the base domain).

## Preparing the server

This guide uses Hetzner Cloud. You can use any VPS provider, but Hetzner is a good and cost-effective option.

### Registering at Hetzner Cloud

Register an account at Hetzner Cloud and create a new project.
[Use this referral link to get EUR 20 credits for free at Hetzner Cloud](https://hetzner.cloud/?ref=BFdFFipLgfDs)

Next, go to the [Cloud Console](https://console.hetzner.cloud/) and create a project.

### Setting up an SSH key to connect to the server

You need SSH access to configure your server. Create an SSH keypair if you don't have one yet. Check if you already have one:

```bash
cat ~/.ssh/id_rsa.pub
```

To create a new keypair:

```bash
ssh-keygen -t rsa -b 4096
```

Leave all options at their default values by pressing enter. When asked for a password, just press enter.

Copy the public key to your clipboard:

```bash
cat ~/.ssh/id_rsa.pub
```

In your Hetzner project:

1. In the left-hand menu, click on **Security** > **SSH keys** > **Add SSH key**.
2. Paste the public key you generated.

### Creating a new server

In your Hetzner project, create a new server:

1. In the left-hand menu, go to **Server** and click **Create server**.
2. In the **Image** section, click on **Apps** and select **Docker CE**.
3. **Type/Architecture:** Select an appropriate tier -- the CX22 (2 vCPU, 4 GB RAM) is a good starting point. You can always upgrade later.
4. Ensure that the public IPv4 address is enabled.
5. In the SSH-Keys section, make sure your SSH key is selected.
6. Name your server and create it.

### Setting up the server

Once the server is created, connect to it:

```bash
ssh root@<your-server-ip>
```

When prompted with "Are you sure you want to continue connecting?" type "yes" and press enter.

#### Step 1: Create a deployment user

For security, create a non-root user to manage the deployment:

```bash
sudo adduser github-actions
```

#### Step 2: Grant Docker permissions

```bash
sudo usermod -aG docker github-actions
```

#### Step 3: Enable SSH access

Check the SSH config:

```bash
sudo nano /etc/ssh/sshd_config
```

Find or add the `AllowUsers` directive:

```text
AllowUsers root github-actions
```

Save and restart SSH:

```bash
sudo systemctl restart ssh
```

#### Step 4: Set up SSH key-based authentication

1. Log in as the new user:

   ```bash
   su - github-actions
   ```

2. Create an SSH keypair:

   ```bash
   ssh-keygen -t rsa -b 4096
   ```

   Leave all options at defaults.

3. Add the public key to authorized_keys:

   ```bash
   cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
   ```

4. Copy the private key -- you will need it as a GitHub secret later. Include the `-----BEGIN OPENSSH PRIVATE KEY-----` and `-----END OPENSSH PRIVATE KEY-----` lines:

   ```bash
   cat ~/.ssh/id_rsa
   ```

   Save this key in a secure place.

5. Exit back to root and restart SSH:

   ```bash
   exit
   sudo systemctl restart ssh
   ```

#### Step 5: Create the deployment directory

```bash
su - github-actions
mkdir -p ~/matrix-corporal/docker
exit
```

### Firewall configuration

In the Hetzner Web Interface, enter your server configuration and click on **Firewalls**, then click **Create Firewall**.

By default, there will be two inbound rules: SSH (port 22) and ICMP. Add two more:

1. Click on **Add Rule**, name it HTTP, set the port to 80, protocol TCP.
2. Click on **Add Rule**, name it HTTPS, set the port to 443, protocol TCP.
3. In the "apply to" section, select your server.
4. Click **Create Firewall**.

## Preparing the domain

You need a domain with access to its DNS settings. Create the following DNS A records, replacing `Your server IP` with your VPS IP address:

| Type | Name    | Value          |
| ---- | ------- | -------------- |
| A    | matrix  | Your server IP |
| A    | element | Your server IP |

This gives you:

- `matrix.your-domain.com` -- the Matrix homeserver API (via matrix-corporal gateway)
- `element.your-domain.com` -- the Element web client

The Synapse `server_name` is set to `your-domain.com` (the base domain, without subdomain). User IDs will look like `@username:your-domain.com`.

## Preparing the repository

### Adding the secrets to the repository

Go to your GitHub repository, navigate to **Settings** > **Secrets and variables** > **Actions**, and create the following secrets:

**SSH and deployment:**

| Secret Name       | Value                                                     |
| ----------------- | --------------------------------------------------------- |
| `SSH_HOST`        | The IP address of your VPS                                |
| `SSH_USER`        | The deployment username (e.g., `github-actions`)          |
| `SSH_PRIVATE_KEY` | The private key you generated on the server               |

**Database:**

| Secret Name         | Value                                |
| ------------------- | ------------------------------------ |
| `POSTGRES_USER`     | Database username (e.g., `synapse`)  |
| `POSTGRES_PASSWORD` | A strong random database password    |
| `POSTGRES_DB`       | Database name (e.g., `homeserver`)   |

**Matrix / Synapse:**

| Secret Name                         | Value                                                               |
| ----------------------------------- | ------------------------------------------------------------------- |
| `MATRIX_SERVER_NAME`                | Your base domain (e.g., `schulpostmedien-sandkasten.de`)            |
| `MATRIX_AUTH_SHARED_SECRET`         | A long random string -- shared between Synapse and matrix-corporal  |
| `MATRIX_REGISTRATION_SHARED_SECRET` | A long random string -- used for Synapse admin registration API     |
| `MATRIX_MACAROON_SECRET_KEY`        | A long random string -- used by Synapse to sign access tokens       |
| `MATRIX_FORM_SECRET`                | A long random string -- used by Synapse for form HMAC values        |

**matrix-corporal:**

| Secret Name          | Value                                                               |
| -------------------- | ------------------------------------------------------------------- |
| `CORPORAL_API_TOKEN` | A long random string -- Bearer token for the matrix-corporal HTTP API |

**TLS / Let's Encrypt:**

| Secret Name  | Value                                              |
| ------------ | -------------------------------------------------- |
| `ACME_EMAIL` | Email address for Let's Encrypt certificate alerts |

You can generate strong random strings with:

```bash
openssl rand -base64 48
```

## Configuring the GitHub Action

Open `.github/workflows/deploy.yml` and update the `GHCR_ORG` variable with your GitHub username or organization name.

You can also change the trigger branch at the top of the file (default is `main`).

### How the workflow works

The GitHub Action performs two jobs:

**Job 1: Build and push image**
1. Checks out the repository.
2. Builds the matrix-corporal Docker image using `etc/docker/Dockerfile`.
3. Pushes it to `ghcr.io/<your-org>/matrix-corporal:latest`.

**Job 2: Deploy**
1. Checks out the repository.
2. Runs `envsubst` on the config templates (`homeserver.production.yaml` and `config.production.json`) to replace `${VAR}` placeholders with the actual secret values.
3. Copies all deployment files to the VPS via `rsync` (compose file, substituted configs, Python auth modules, etc.).
4. SSHs into the VPS to pull the new Docker images and start/restart the stack.

The config template files in the repository contain `${VARIABLE}` placeholders that are safe to commit -- the actual secrets only exist in GitHub Actions secrets and are substituted at deploy time.

## First deployment

### Generating the Synapse signing key

Before the first deployment, SSH into the VPS and generate the Synapse signing key:

```bash
ssh github-actions@<your-server-ip>

mkdir -p ~/matrix-corporal/docker/synapse

docker run --rm \
  -v ~/matrix-corporal/docker/synapse:/data \
  docker.io/matrixdotorg/synapse:v1.136.0 \
  generate \
  --server-name your-domain.com \
  --report-stats no

# Rename the signing key to match what the config expects
mv ~/matrix-corporal/docker/synapse/your-domain.com.signing.key \
   ~/matrix-corporal/docker/synapse/signing.key
```

Replace `your-domain.com` with your actual domain. The signing key will persist in the `synapse/` directory on the VPS and won't be overwritten by deployments (rsync only syncs files that exist in the source).

> **Important:** You can delete the generated `homeserver.yaml` and log config from this directory -- the deployment will overwrite them with the proper versions. Only the `signing.key` needs to persist.

```bash
rm ~/matrix-corporal/docker/synapse/homeserver.yaml
rm ~/matrix-corporal/docker/synapse/*.log.config
rm ~/matrix-corporal/docker/synapse/*.signing.key 2>/dev/null
```

### Running the workflow

Push your changes to the `main` branch, or manually trigger the workflow:

1. Go to the **Actions** tab in your GitHub repository.
2. Click on the **Deploy to Docker** workflow.
3. Click **Run workflow** and select the branch.

Wait for the workflow to complete. Then verify:

- `https://element.your-domain.com` should show the Element login page.
- `https://matrix.your-domain.com/_matrix/client/versions` should return a JSON response.

If Traefik needs a moment to obtain TLS certificates, wait a minute and try again.

### Creating the system user

After the first deployment, SSH into the VPS and create the matrix-corporal system user:

```bash
ssh github-actions@<your-server-ip>

cd ~/matrix-corporal/docker

docker compose -f compose.production.yml -p matrix-corporal \
  exec synapse \
  register_new_matrix_user \
  -a \
  -u matrix-corporal \
  -p <choose-a-strong-password> \
  -c /data/homeserver.yaml \
  http://localhost:8008
```

## Subsequent deployments

After the initial setup, deployments are fully automatic:

1. Push changes to the `main` branch.
2. GitHub Actions builds a new matrix-corporal Docker image.
3. Config templates are substituted with secrets.
4. All files are rsynced to the VPS.
5. The stack is pulled and restarted.

To manually trigger a deployment without code changes, use the **Run workflow** button in the Actions tab.

## Updating the policy

The policy file is at `etc/docker/corporal/policy.json` in the repository. Edit it, commit, and push -- the next deployment will copy the updated policy to the VPS.

Alternatively, you can SSH into the VPS and edit it directly for quick changes:

```bash
ssh github-actions@<your-server-ip>
nano ~/matrix-corporal/docker/corporal/policy.json
```

matrix-corporal watches the policy file for changes (when using the `static_file` provider) and will automatically reconcile.

> **Note:** An existing `corporal/policy.json` on the VPS is preserved across deploys. The repo version is only copied when the file is missing (e.g. on first deploy). To reset to the repo version, remove the file on the VPS and redeploy.

## Connecting to the database

To manage the PostgreSQL database, set up an SSH tunnel:

1. Open your database client (e.g., DBeaver).
2. Create a new PostgreSQL connection.
3. In the **SSH** tab:
   - **Host/IP:** Your VPS IP
   - **Port:** 22
   - **Username:** root (or your SSH user)
   - **Authentication method:** Public key
   - **Private key:** Your local SSH private key
4. In the **Main** tab:
   - **Host:** localhost
   - **Port:** 5432
   - **Database:** The database name from your GitHub secrets
   - **Username:** The database user from your GitHub secrets
   - **Password:** The database password from your GitHub secrets

The Postgres container does not expose port 5432 to the public internet. You must use an SSH tunnel.

## Troubleshooting

### Checking service logs

SSH into the VPS and view logs:

```bash
cd ~/matrix-corporal/docker

# All services
docker compose -f compose.production.yml -p matrix-corporal logs -f

# Specific service
docker compose -f compose.production.yml -p matrix-corporal logs -f synapse
docker compose -f compose.production.yml -p matrix-corporal logs -f matrix-corporal
docker compose -f compose.production.yml -p matrix-corporal logs -f traefik
```

### Synapse won't start

- Check that `synapse/signing.key` exists on the VPS at `~/matrix-corporal/docker/synapse/signing.key`.
- Verify that database credentials match between the Synapse config and the Postgres environment variables.
- Ensure the `shared_secret_authenticator.py` and `rest_auth_provider.py` files were rsynced to the VPS.

### TLS certificate issues

- Ensure DNS A records point to the correct VPS IP.
- Check Traefik logs for ACME/Let's Encrypt errors.
- Verify that ports 80 and 443 are open in the firewall.
- Let's Encrypt has rate limits -- if you hit them, wait and retry.

### matrix-corporal can't reach Synapse

- Both containers must be on the same Docker network (Docker Compose does this by default).
- The Synapse endpoint in `corporal/config.production.json` should be `http://synapse:8008` (using the Docker Compose service name).

### Shared secrets don't match

The `MATRIX_AUTH_SHARED_SECRET` GitHub secret is used in both the Synapse config (as `shared_secret` in the `shared_secret_authenticator` module) and the corporal config (as `AuthSharedSecret`). If authentication fails silently, verify that this secret is set correctly in the repository.

Similarly, `MATRIX_REGISTRATION_SHARED_SECRET` must match between both configs.

### Restarting services

```bash
cd ~/matrix-corporal/docker

# Restart everything
docker compose -f compose.production.yml -p matrix-corporal restart

# Restart a single service
docker compose -f compose.production.yml -p matrix-corporal restart matrix-corporal
```

### Viewing the running containers

```bash
docker compose -f compose.production.yml -p matrix-corporal ps
```
