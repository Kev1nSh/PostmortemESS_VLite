# PostmortemESS_VLite – Deployment

This guide explains how to set up and run PostmortemESS_VLite locally using Docker or Podman.

## Prerequisites

Install:

- Python 3
- Git
- Docker or Podman

Verify the container runtime:

```bash
docker --version
```

or:

```bash
podman --version
```

## 1. Clone the repository

```bash
git clone https://github.com/Kev1nSh/PostmortemESS_VLite
cd PostmortemESS_VLite
```

## 2. Initial setup

Run:

```bash
python3 launcher.py setup
```

This creates the local `.env` file and automatically generates a random `HASH_KEY`.

### API keys

The external API integrations are an important part of the email analysis functionality. Without the relevant API keys, some enrichment and threat-intelligence checks will be unavailable.

For the most complete analysis results, configure all supported API integrations.

| API | Purpose | Get API key |
|---|---|---|
| **VirusTotal** | File, URL and threat intelligence lookups | [Create an account](https://www.virustotal.com/gui/join-us) |
| **Google Safe Browsing** | URL reputation and safety checks | [Get started](https://developers.google.com/safe-browsing/v4/get-started) |
| **Abuse.ch** | Threat intelligence and IOC lookups | [Create an account](https://auth.abuse.ch/) |
| **AbuseIPDB** | IP reputation and abuse checks | [Create an account](https://www.abuseipdb.com/register) |
| **OpenLookup** | Email and domain intelligence | [Create an account](https://www.openlookup.io/signup) |

Add the API keys to `.env`:

```env
VIRUSTOTAL_API_KEY=
GOOGLE_SAFE_BROWSING_KEY=
ABUSEIPDB_API_KEY=
ABUSE_CH_API_KEY=
OPENLOOKUP_API_KEY=
```

The `HASH_KEY` is generated automatically by `launcher.py` during setup and does not need to be manually created or entered.

Do not commit `.env` to Git.

## 3. Build

Build the API and frontend containers:

```bash
python3 launcher.py build
```

## 4. Start

Start PostmortemESS_VLite:

```bash
python3 launcher.py start
```

The launcher automatically creates the required container network and persistent data volume.

## 5. Access the application

Once started:

| Service | URL |
|---|---|
| Web UI | `http://localhost:8080` |
| API | `http://localhost:8000` |
| Swagger | `http://localhost:8000/docs` |

## 6. Verify

Check the container status:

```bash
python3 launcher.py status
```

View API logs:

```bash
python3 launcher.py logs api
```

View frontend logs:

```bash
python3 launcher.py logs frontend
```

## 7. Updating the application

After changing the source code, rebuild the images and restart:

```bash
python3 launcher.py build
python3 launcher.py restart
```

`start` does not rebuild existing images.

## 8. Stop and restart

Stop:

```bash
python3 launcher.py stop
```

Restart:

```bash
python3 launcher.py restart
```

## 9. Persistent data

Application data is stored in the named volume:

```text
postmortemess-data
```

The volume is mounted to `/data` inside the API container.

Stopping or recreating the containers does not remove this volume.

## 10. Troubleshooting

### API is not responding

```bash
python3 launcher.py status
python3 launcher.py logs api
```

### Frontend is not responding

```bash
python3 launcher.py logs frontend
```

Check that port `8080` is available.

### Frontend returns 502

Make sure the API container is running:

```bash
python3 launcher.py status
```

The frontend communicates with the API through the internal container network.

### Source-code changes

For source-code changes:

```bash
python3 launcher.py build
python3 launcher.py restart
```

## 11. k3s

For a Kubernetes-based deployment, the repository also contains the `k3s/` directory with example manifests illustrating the Kubernetes resources that may be required.

They are separate from the local `launcher.py` deployment and may require environment-specific modifications. The local VLite deployment therefore remains the simplest way to run the application.

## Quick start

```bash
git clone https://github.com/Kev1nSh/PostmortemESS_VLite
cd PostmortemESS_VLite

python3 launcher.py setup
python3 launcher.py build
python3 launcher.py start
```

Then open:

```text
http://localhost:8080
```