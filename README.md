# PostmortemESS VLite

**PostmortemESS VLite** is a lightweight, locally deployable version of PostmortemESS for analyzing suspicious email messages through a web-based interface.

This project was developed as part of my **LIA/Internship placement at SMHI**, where I have been working with the development and evolution of the PostmortemESS email-security platform.

The project builds on the existing **PostmortemCLI** email-analysis functionality and combines it with a React/Vite frontend and a Python/FastAPI backend. VLite was developed as a smaller and portable version of the system, making the core email-analysis functionality easier to run and demonstrate in a local environment without requiring the full PostmortemESS infrastructure.

The application can be run locally using either **Docker** or **Podman**.

---

# Project Background

PostmortemESS VLite is the **Lite** version of the development work carried out during my LIA placement at **SMHI**.

The project evolved from the existing PostmortemCLI email-analysis tool into a broader web-based security analysis platform. During the development, the work has involved multiple areas of IT, including:

- Cybersecurity and email security
- Application architecture
- Python, API development with FastAPI
- React/Vite frontend development
- Containerization with Docker/Podman
- Software development
- Threat intelligence integrations
- Data storage and reporting

VLite represents a lightweight version of this work, focusing on the core application and analysis functionality while leaving the environment-specific infrastructure of the full PostmortemESS deployment outside its scope.

---

# Overview

PostmortemESS VLite provides a centralized interface for submitting and analyzing suspicious email messages.

Instead of running the analysis directly from a command-line interface, users can upload an email through the web application and receive a structured analysis report containing security-related findings and a final verdict.

The main workflow is:

```text
Suspicious Email
       │
       ▼
Web Interface
       │
       ▼
FastAPI API
       │
       ▼
Email Processing
       │
       ├── File handling
       ├── Email parsing
       ├── Header analysis
       ├── URL analysis
       ├── Security checks
       ├── Threat intelligence
       └── Verdict generation
              │
              ▼
       Analysis Report
              │
              ▼
        SQLite Storage
```

---

# Scope

PostmortemESS VLite focuses on the core functionality required to analyze suspicious emails locally.

### Included

- Web-based email submission
- `.eml` email processing
- `.msg` file handling through the email conversion workflow
- Email parsing
- Header and authentication analysis
- URL and domain analysis
- Threat intelligence lookups
- Security analysis
- Verdict generation
- Structured analysis reports
- Report storage
- Statistics and historical reports
- Local containerized deployment

---

### Deployment

For detailed installation, configuration, and deployment instructions, see:

**[`docs/deployment.md`](docs/deployment.md)**

The deployment guide covers:
- Prerequisites
- Environment configuration
- Docker and Podman setup
- Building the application
- Starting and stopping the services
- Accessing the web interface and API
- Troubleshooting and operational notes

For a quick overview, the application can be started with:

```bash
git clone https://github.com/Kev1nSh/PostmortemESS_VLite
cd PostmortemESS_VLite

python3 launcher.py setup
python3 launcher.py build
python3 launcher.py start
```

After startup:

- **Web UI:** `http://localhost:8080`
- **API:** `http://localhost:8000`
- **Swagger UI:** `http://localhost:8000/docs`

For the complete deployment procedure and configuration details, refer to **[`docs/deployment.md`](docs/deployment.md)**.
# Features

## Email Analysis

PostmortemESS VLite accepts suspicious email messages and processes them through the analysis pipeline.

The backend handles:

- Email file processing
- Email parsing
- Header extraction
- Authentication-related checks
- URL extraction
- Domain analysis
- IP-related analysis
- Attachment information
- Security indicators
- Threat intelligence lookups
- Verdict generation
- Report generation

The API returns structured JSON data, allowing the frontend to present individual analysis components independently.

---

# Analysis Workflow

The analysis process follows a structured pipeline.

```text
Email File
    │
    ▼
File Handling
    │
    ├── .eml
    │
    └── .msg
          │
          ▼
    MSG → EML conversion
          │
          ▼
      Email Parser
          │
          ▼
     Security Analyzer
          │
          ├── Headers
          ├── Authentication
          ├── URLs
          ├── Domains
          ├── IPs
          └── Threat Intelligence
          │
          ▼
     Verdict Generation
          │
          ▼
      Report Generation
          │
          ▼
      SQLite Storage
```

The `.msg` workflow converts Microsoft Outlook messages into `.eml` before they enter the established email-analysis pipeline.

This allows the same analysis logic to be reused regardless of the original email format.

---

# Verdicts

The analysis produces a final verdict based on the available security findings.

The frontend presents the results using the following main categories:

| Verdict | Meaning |
| --- | --- |
| **SAFE** | The message is most likely safe based on the available analysis. |
| **UNSAFE** | The message contains indicators associated with malicious or suspicious activity. |
| **FURTHER ANALYSIS** | The available evidence is insufficient to confidently classify the message. |

The verdict is accompanied by the underlying analysis results so that users can review the findings rather than relying solely on the final classification.

---

# Threat Intelligence

PostmortemESS VLite can integrate with external threat-intelligence and reputation services to enrich the email analysis.

Supported integrations include:

| Service | Purpose |
| --- | --- |
| **VirusTotal** | File, URL and threat-intelligence lookups |
| **Google Safe Browsing** | URL reputation and safety checks |
| **AbuseIPDB** | IP reputation and abuse checks |
| **Abuse.ch** | Threat intelligence and IOC lookups |
| **OpenLookup** | Email and domain intelligence |

API keys are configured through the local `.env` file.

The application can operate without every integration being configured, but unavailable API keys will prevent the corresponding enrichment or reputation checks from being performed.

---

# Architecture

PostmortemESS VLite uses a small two-container architecture.

```text
                        Host
                         │
                         ▼
                    launcher.py
                         │
                Docker / Podman
                         │
              postmortemess-net
                  │             │
                  ▼             ▼
        ┌────────────────┐  ┌──────────────────┐
        │   Frontend     │  │       API        │
        │                │  │                  │
        │ React + Vite   │  │ Python + FastAPI │
        │ Nginx          │  │ Uvicorn          │
        └───────┬────────┘  └────────┬─────────┘
                │                    │
                │  /api/ proxy      │
                └───────────────────►│
                                     │
                                     ▼
                              SQLite / /data
                                     │
                                     ▼
                          postmortemess-data
```

The frontend is served through Nginx and proxies `/api/` requests to the FastAPI backend over the internal container network.

The API stores persistent application data in a dedicated Docker/Podman volume.

---

# Frontend

The frontend is built using:

- React
- Vite
- Aurora components
- Custom React components
- Custom CSS
- Nginx

The frontend provides the user-facing interface for:

- Uploading suspicious emails
- Viewing analysis results
- Viewing verdicts
- Viewing reports
- Viewing statistics
- Reviewing historical analysis data

The frontend communicates with the backend through the `/api/` route.

---

# Backend

The backend is implemented using **Python and FastAPI**.

It provides the API layer between the frontend and the underlying email-analysis functionality.

The API is responsible for:

- File uploads
- Email processing
- `.msg` conversion
- Email parsing
- Security analysis
- Threat-intelligence integration
- Verdict generation
- Report generation
- Report storage
- Statistics endpoints

The API is served using **Uvicorn**.

API documentation is automatically available through FastAPI's Swagger UI.

```text
http://localhost:8000/docs
```

---

# Containerization

PostmortemESS VLite is designed to run using either **Docker** or **Podman**.

The application is separated into two containers:

```text
postmortem-api
    │
    └── Python 3.12
        FastAPI
        Uvicorn
        Email analysis

postmortem-frontend
    │
    └── Node.js build
        React
        Vite
        Nginx
```

The containers communicate through a dedicated container network.

A persistent volume is used for application data:

```text
postmortemess-data
        │
        ▼
      /data
        │
        ▼
      SQLite
```

This allows application data to survive container recreation.

---

# Security

VLite follows several security-oriented design principles inherited from the main PostmortemESS implementation.

### API

The API container runs as a dedicated non-root user rather than root.

```text
Container
    │
    └── app user
         └── FastAPI
```

Application data is stored in a dedicated `/data` directory owned by the application user.

### Secrets

External API keys are provided through environment variables using `.env`.

The `.env` file should **never be committed to the repository**.

The launcher automatically generates a random `HASH_KEY` during initial setup.

### Container separation

The frontend and backend run in separate containers and communicate through a dedicated container network.

This keeps the presentation layer and analysis backend separated while allowing the frontend to access the API through its internal service name.

---

# Application Structure

The main application logic is separated from the API and frontend layers.

```text
PostmortemESS_VLite/
│
├── api/
│   ├── app.py
│   └── Dockerfile
│
├── converter/
│   └── ...
│
├── src/
│   ├── analyzer.py
│   ├── parser.py
│   ├── reporter.py
│   ├── db.py
│   ├── logger.py
│   └── ...
│
├── frontend/
│   ├── src/
│   ├── Dockerfile
│   ├── nginx.conf
│   ├── package.json
│   └── pnpm-lock.yaml
│
├── launcher.py
├── requirements.txt
├── .env
├── README.md
└── docs/
    └── deployment.md
```

The main responsibilities are separated as follows:

| Component | Purpose |
| --- | --- |
| `src/parser.py` | Parses email messages and extracts relevant email data. |
| `src/analyzer.py` | Performs the main security analysis. |
| `src/reporter.py` | Generates structured analysis reports and results. |
| `src/db.py` | Handles application data and report storage. |
| `src/logger.py` | Provides application logging functionality. |
| `converter/` | Provides email format conversion functionality. |
| `api/app.py` | FastAPI application and API endpoints. |
| `frontend/` | React/Vite web application. |
| `launcher.py` | Local Docker/Podman lifecycle management. |

This separation allows the analysis logic, API layer and frontend to evolve independently.

---

# Local Runtime

The local runtime is intentionally simple.

```text
launcher.py
     │
     ├── Detect Docker / Podman
     │
     ├── Create network
     │
     ├── Create persistent volume
     │
     ├── Build API image
     │
     ├── Build frontend image
     │
     └── Start containers
```

The launcher provides commands for the complete local lifecycle:

```bash
python3 launcher.py setup
python3 launcher.py build
python3 launcher.py start
python3 launcher.py stop
python3 launcher.py restart
python3 launcher.py status
python3 launcher.py logs api
python3 launcher.py logs frontend
```

The launcher automatically detects whether Docker or Podman is available.

---

# Technology Stack

| Area | Technology |
| --- | --- |
| Backend | Python |
| API | FastAPI |
| API Server | Uvicorn |
| Email Analysis | PostmortemCLI analysis components |
| Frontend | React |
| Frontend Build | Vite |
| UI Components | Aurora |
| Web Server | Nginx |
| Database | SQLite |
| Containers | Docker / Podman |
| Package Management | pnpm |
| Threat Intelligence | VirusTotal, Google Safe Browsing, AbuseIPDB, Abuse.ch, OpenLookup |

---

# Project Structure

The repository is organized around the application logic, API, frontend, container configuration and documentation.

```text
PostmortemESS_VLite/
├── api/
│   ├── app.py
│   └── Dockerfile
│
├── converter/
│   └── ...
│
├── frontend/
│   ├── src/
│   ├── Dockerfile
│   ├── nginx.conf
│   ├── package.json
│   └── pnpm-lock.yaml
│
├── src/
│   ├── analyzer.py
│   ├── parser.py
│   ├── reporter.py
│   ├── db.py
│   ├── logger.py
│   └── ...
│
├── docs/
│   └── deployment.md
│
├── launcher.py
├── requirements.txt
├── README.md
└── .env
```

The exact contents of generated, local or environment-specific files may vary.

---

# Deployment

PostmortemESS VLite is intended to be straightforward to run locally.

Detailed setup and deployment instructions are maintained separately in:

```text
docs/deployment.md
```

This keeps installation instructions, environment configuration and operational details separate from the high-level project documentation.

The basic workflow is:

```bash
git clone https://github.com/Kev1nSh/PostmortemESS_VLite
cd PostmortemESS_VLite

python3 launcher.py setup
python3 launcher.py build
python3 launcher.py start
```

The application is then available at:

```text
Web UI:  http://localhost:8080
API:     http://localhost:8000
Swagger: http://localhost:8000/docs
```

---

# Development

The VLite architecture is intended to make local development straightforward.

Changes to the application source can be rebuilt using:

```bash
python3 launcher.py build
python3 launcher.py restart
```

The `start` command does not rebuild container images.

This makes it possible to work independently on the frontend, backend and analysis logic while using the same local runtime architecture.

---

# Relationship to PostmortemESS

PostmortemESS VLite is derived from the broader **PostmortemESS** project.

The purpose of VLite is not to replace the full deployment architecture, but to provide a smaller and portable version containing the core application functionality.

Conceptually:

```text
PostmortemCLI
      │
      ▼
Email Analysis Engine
      │
      ▼
PostmortemESS
      │
      ├── Web Interface
      ├── API
      ├── Reporting
      ├── Statistics
      ├── Containerization
      └── Full deployment infrastructure
             │
             ▼
       PostmortemESS VLite
             │
             ├── Web Interface
             ├── API
             ├── Email Analysis
             ├── Reporting
             ├── Statistics
             └── Local Docker / Podman runtime
```

VLite therefore preserves the central email-analysis workflow while removing infrastructure that is specific to the full deployment environment.

---

# Acknowledgments

A special thanks to [Filip Andersson](https://github.com/Filipanderssondev) for developing [PostmortemCLI](https://github.com/Filipanderssondev/PostmortemCLI-email-security-analyzer), which provides the foundation for the email-analysis functionality used by PostmortemESS.

A special thanks to [JoshData](https://github.com/JoshData) for developing [convert-outlook-msg-file](https://github.com/JoshData/convert-outlook-msg-file), which supports the conversion of Microsoft Outlook `.msg` files into `.eml` before they enter the established email-analysis pipeline.

These projects provide important building blocks that allow PostmortemESS VLite to focus on email analysis, centralized processing, reporting and usability while keeping the local deployment lightweight.

---

# License

See [`LICENSE.md`](LICENSE.md) for the applicable project license.
```