# JS API Extractor — OffSec Framework & Burp Suite Extension

> **AST-Driven Client-Side Reverse Engineering & API Contract Mapping Framework**

---

## 1. Executive Summary & Purpose

### The Problem
Modern web applications built with **React, Next.js, Angular, Vue, Nuxt, SvelteKit, and Blazor** decouple the user interface from backend microservices. In single-page architectures (SPAs), security assessments face significant blind spots:

1. **Invisible Attack Surface:** Traditional web crawlers and URI fuzzers only discover endpoints linked in raw HTML. They cannot uncover dynamic routes hidden inside minified JavaScript bundles or lazy-loaded code chunks.
2. **False Security Boundaries:** Developers frequently enforce access controls on the client side using UI route guards (`if (!user.isAdmin) navigate('/')`). This hides the UI component but leaves underlying server-side API endpoints completely exposed.
3. **Complex Parameter Templates & Payload Contracts:** Modern APIs expect structured JSON request bodies, path parameters (`/api/tenants/{tenantId}/users/{userId}`), GraphQL operations, or WebSocket channels that cannot be inferred through simple string fuzzing.
4. **Noise from Legacy Tools:** Generic JS link finders rely on simple string regexes, filling pentest reports with useless false positives like W3C XML namespaces (`http://www.w3.org/1999/xhtml`), CDN script libraries, and code keywords.

### The Solution: JS API Extractor
**JS API Extractor** bridges client-side JavaScript analysis directly to server-side vulnerability testing. 

By combining an in-memory **Abstract Syntax Tree (AST) parsing engine** with a **Burp Suite Montoya Extension**, the system passively analyzes JavaScript bundles as you browse a target application. It automatically reverse-engineers:
* **API Endpoints & HTTP Verbs** (REST, GraphQL, WebSockets, SignalR).
* **Framework Router Definitions** (Angular `$stateProvider`, React Router, Vue Router).
* **POST/PUT Request Body Schemas** (extracting JSON DTO shapes directly from AST object literals).
* **BOLA / IDOR Attack Targets** (flagging dynamic resource identifiers).
* **Client-Side Secrets & Token Sinks** (API keys, AWS credentials, JWT storage locations).
* **Feature Toggles & Role Guards** (`isAdmin()`, `hasPermission()`).

The resulting intelligence is presented in a dedicated Burp Suite dashboard and can be exported instantly to **OpenAPI 3.0 (Swagger)** or **Postman Collections**.

---

## 2. Technical Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 BURP SUITE EXTENSION                                   │
│                                                                                        │
│  ┌──────────────────────┐     ┌──────────────────────┐     ┌────────────────────────┐  │
│  │   Proxy Interceptor  │ ──> │   REST Bridge Client │ ──> │ Local Python AST Server│  │
│  │ (ProxyResponseHandler)│    │ (HttpURLConnection)  │     │ (FastAPI @ :8000)      │  │
│  └──────────────────────┘     └──────────────────────┘     └────────────────────────┘  │
│                                                                        │               │
│                                                                        ▼               │
│  ┌──────────────────────┐     ┌──────────────────────┐     ┌────────────────────────┐  │
│  │ OpenAPI / Postman    │ <── │ Custom UI Dashboard  │ <── │ Burp Site Map Injector │  │
│  │ Exporter             │     │ (JTable / UI Tab)    │     │ (Montoya SiteMap API)  │  │
│  └──────────────────────┘     └──────────────────────┘     └────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

The system operates via a **hybrid dual-engine architecture**:

1. **Python AST & Normalization Engine (`python_service/`):**
   * **FastAPI Service:** Runs locally on `http://127.0.0.1:8000`.
   * **AST Parser Engine (`parser.py`):** Uses Esprima to traverse AST node structures (`CallExpression`, `TemplateLiteral`, `MemberExpression`, `ObjectExpression`), extracting exact API signatures and JSON payload shapes.
   * **Noise Reduction Pipeline:** Applies strict exclusion rules against W3C namespaces, CDN script tags, and reserved code keywords.
   * **Schema Normalizer (`normalizer.py`):** Reconstructs dynamic URL paths into standard URI templates (`/api/v1/users/{userId}`) and formats output into OpenAPI 3.0 and Postman schemas.

2. **Burp Suite Montoya Extension (`burp_extension/`):**
   * **Passive Interceptor (`ProxyHandler.java`):** Hooked into Burp's Proxy response handler. Asynchronously captures `.js`, `.map`, and chunk assets without delaying browser traffic.
   * **Multi-Tab UI Dashboard (`JSExtractorTab.java`):** Provides a 3-tab Swing GUI inside Burp Suite for Endpoints, Secrets, and Feature Flags.
   * **Interactive Context Actions:** Right-click integration allowing testers to copy cURL commands, copy request JSON, or execute **"Send BOLA Pair to Repeater"**.

---

## 3. Key Features

### A. Multi-Framework Route & API Extraction
* **REST APIs:** Captures `fetch()`, `axios.get()`, `axios.post()`, `$.ajax()`, and `XMLHttpRequest` calls.
* **Angular UI Router & Framework Routes:** Parses `$stateProvider.state()`, `url: '/...'`, `path: '/...'`, and `templateUrl` definitions.
* **Service Method Discovery:** Detects Angular/JS service invocations (e.g., `recruiterAccountService.getRecruiterByInvitationId()`).
* **GraphQL:** Identifies GraphQL queries, mutations, and operation names (`/graphql?op=GetUserProfile`).
* **WebSockets & SignalR:** Extracts `new WebSocket("wss://...")` connections and SignalR hub endpoints.

### B. Request Body JSON Reconstruction (POST / PUT / PATCH)
Instead of returning empty requests, the AST parser analyzes `ObjectExpression` payload arguments inside `axios.post(url, data)` or `fetch(url, { body: JSON.stringify(data) })`, generating sample JSON payload shapes:
```json
{
  "name": "<string>",
  "role": "<string>",
  "tenantId": 123
}
```

### C. BOLA / IDOR Attack Matrix & One-Click Repeater Injection
* Endpoints containing resource identifiers (`{userId}`, `{docId}`, `{candidateId}`, `:id`) are automatically flagged as **BOLA Candidates** and highlighted in bold red.
* **Send BOLA Pair to Repeater:** Right-clicking any BOLA endpoint opens **two side-by-side Repeater tabs**:
  * **Tab 1:** Configured with User A's session token.
  * **Tab 2:** Configured with User B's session token targeting the same object ID.

### D. Client-Side Secret & Token Extractor
Scans client bundles for embedded sensitive keys:
* API Keys (`apiKey`, `client_secret`, Stripe keys, Firebase URLs)
* AWS Credentials (`AKIA...`)
* Internal Network Addresses (`http://10.x.x.x`, `http://192.168.x.x`, `localhost`)
* JWT Storage Sinks (`localStorage.setItem('access_token', ...)`)

### E. Feature Flags & Role Guard Detector
Identifies client-side permission string checks (`USER_DELETE`), role guards (`isAdmin()`, `hasRole()`, `user.role`), and feature toggles (`features.enableAdminExport`).

### F. Strict False-Positive Exclusion Engine
Filters out irrelevancies that pollute other tools:
* **Excluded Namespaces:** `w3.org/1999/xhtml`, `schemas.xmlsoap.org`, `schema.org`, `schemas.microsoft.com`.
* **Excluded Asset Files:** `.js`, `.css`, `.png`, `.jpg`, `.svg`, `.woff`.
* **Excluded Keywords:** `of`, `in`, `for`, `function`, `return`, `var`, `let`, `const`.

---

## 4. OWASP API Security Mapping

| Extracted Intelligence | OWASP API Security Top 10 Alignment | Security Testing Impact |
| :--- | :--- | :--- |
| **BOLA Candidates (`{userId}`)** | **API1:2023 Broken Object Level Authorization** | Enables rapid cross-tenant IDOR verification across endpoints. |
| **JWT Storage & API Keys** | **API2:2023 Broken Authentication** | Discovers exposed credentials and insecure token storage sinks. |
| **POST/PUT Body Schemas** | **API3:2023 Broken Object Property Level Auth** | Identifies Mass Assignment candidates for unauthorized property injection (`isAdmin`). |
| **UI Route Guards & Feature Flags** | **API5:2023 Broken Function Level Authorization** | Uncovers admin-only endpoints hidden behind front-end UI checks. |
| **Full Discovered Route Schema** | **API9:2023 Improper Inventory Management** | Reverse-engineers unlinked or undocumented API endpoints. |

---

## 5. Installation & Setup Guide

### Prerequisites
* **Python 3.10+**
* **Burp Suite Professional / Community Edition**
* **Java 17+** (Burp Suite's embedded OpenJDK is supported automatically)

### Step 1: Start the Python AST Backend Service

1. Navigate to the `python_service` directory:
   ```powershell
   js_api_extractor\python_service
   ```
2. Install Python dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
3. Run the standalone parser test to verify environment health:
   ```powershell
   python test_standalone.py
   ```
4. Start the REST service (runs on `http://127.0.0.1:8000`):
   ```powershell
   python main.py
   ```

### Step 2: Build the Burp Extension JAR

1. Navigate to the `burp_extension` directory:
   ```powershell
   js_api_extractor\burp_extension
   ```
2. Run the automated compiler script:
   ```powershell
   python build_extension.py
   ```
   *This uses Burp's embedded JDK compiler (`javac`) to package `js-api-extractor-1.0.0.jar`.*

### Step 3: Load into Burp Suite

1. Open **Burp Suite**.
2. Go to **Extensions** -> **Installed** -> click **Add**.
3. Select **Extension type**: `Java`.
4. Browse and select:
   `js_api_extractor\burp_extension\js-api-extractor-1.0.0.jar`
5. Confirm output log message:
   ```text
   [+] JS API Extractor Montoya Extension Initializing...
   [+] JS API Extractor successfully registered with Burp Suite!
   [+] Python REST Bridge configured for: http://127.0.0.1:8000
   ```

---

## 6. End-to-End Operational Workflow

```
1. Start Python API (main.py)  ──>  2. Load Extension in Burp  ──>  3. Browse Target Web App
                                                                          │
4. Export OpenAPI / Postman   <──  5. Test BOLA Pairs in Repeater <──  4. Review Dashboard Inventory
```

1. **Passive Discovery:** Browse the target web app using Burp Proxy. As JavaScript files are downloaded, the extension automatically sends them to the local AST parser.
2. **Review Inventory:** Switch to the **JS API Extractor** tab in Burp:
   * Inspect discovered routes in **API Endpoints & BOLA Matrix**.
   * Check **Discovered Secrets & Tokens** for hardcoded keys or storage sinks.
   * Check **Feature Flags & Role Guards** for admin permissions.
3. **Execute BOLA Testing:** Right-click any red-highlighted BOLA endpoint -> select **Send BOLA Pair to Repeater**. Replace `<INSERT_USER_A_TOKEN>` and `<INSERT_USER_B_TOKEN>` to verify object-level authorization.
4. **Export OpenAPI / Postman Specs:**
   * Fetch `http://127.0.0.1:8000/export/openapi` to download full Swagger JSON.
   * Fetch `http://127.0.0.1:8000/export/postman` to import into Postman for automated fuzzing.

---

## 7. License & Author

* **Author:** Offensive Security Assessment Team
* **License:** MIT License
* **Repository Structure:**
  * `python_service/`: FastAPI AST Engine & Schema Normalizer.
  * `burp_extension/`: Burp Suite Montoya API Java Extension.
