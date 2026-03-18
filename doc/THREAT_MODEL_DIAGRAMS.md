# OpenMRS Core Threat Model Diagrams

This document translates the supplied threat model into visual diagrams for architecture, trust boundaries, and prioritized threats.

## 1) High-Level Architecture (Deployment / Component View)

```mermaid
flowchart LR
  U["End User Browser\n(Clinician/Admin)"]
  I["External Integrations\n(LIS, Devices, HL7 Feed)"]
  A["Attacker-Controlled Clients\n(Web Requests / Payloads)"]

  subgraph INFRA["Deployment Infrastructure"]
    RP["Reverse Proxy / TLS Terminator"]
    SC["Servlet Container\nTomcat / Jetty"]

    subgraph APP["OpenMRS Core JVM"]
      WF["Web Layer\nweb/ + webapp/"]
      OF["OpenmrsFilter / CSRFGuard / Session Filters"]
      API["Service API Layer\napi/"]
      AUTH["AuthN/AuthZ\nContext, UserContext, @Authorized"]
      MOD["Module System\norg.openmrs.module.*\n(no sandbox)"]
      HL7["HL7 Processing\napi/.../hl7/"]
      SER["Serialization/XML\nXStream, Jackson, XmlUtils"]
      STOR["Storage Services\nLocalStorageService / S3StorageService"]
      AUD["Audit & Revision\nAuditableInterceptor, Envers"]
    end

    DB[("Relational DB\nMySQL / Postgres")]
    FS[("Local File Storage")]
    S3[("S3/Object Storage")]
    CFG["Runtime + Global Properties\nopenmrs-runtime.properties"]
    MODREP["Module Repository URLs\nUpdate Sources"]
  end

  U --> RP --> SC --> WF
  A --> RP
  I --> RP

  WF --> OF --> API
  API --> AUTH
  API --> HL7
  API --> SER
  API --> STOR
  API --> AUD
  API --> DB
  STOR --> FS
  STOR --> S3

  MOD -. adds endpoints/filters .-> WF
  MOD -. can call services/DAO .-> API
  MOD -. may load/update from .-> MODREP

  CFG -. controls policies/secrets .-> API
  CFG -. controls module upload/admin .-> MOD
```

## 2) Trust Boundary Diagram (Threat-Focused DFD)

```mermaid
flowchart TB
  subgraph TB1["Boundary A: Untrusted External Inputs"]
    WEBIN["HTTP Requests\n(params, JSON/XML, multipart)"]
    UGC["User-Generated Content\n(names, notes, concepts)"]
    HL7IN["HL7 Messages\nfrom external systems"]
    XMLIN["Serialized/XML payloads\n(module/admin endpoints)"]
  end

  subgraph TB2["Boundary B: OpenMRS Application Trust Zone"]
    WEB["Spring MVC + Module Endpoints"]
    FILTERS["OpenmrsFilter\nCSRFGuard\nCookieClearingFilter"]
    SERVICES["Service Layer + AOP Authorization"]
    DAO["Hibernate DAO / Criteria / Native Queries"]
    SERIAL["Serializer/Marshaller\nXStream/Jackson"]
    MODULES["Installed Modules\nFull JVM privilege"]
  end

  subgraph TB3["Boundary C: Operator-Controlled Configuration"]
    RUNTIME["openmrs-runtime.properties"]
    GLOBAL["Global Properties\n(password policy, serializer whitelist)"]
    ADMIN["Admin Module Upload / Update Settings"]
  end

  subgraph TB4["Boundary D: Data/External Services"]
    DBASE[("Clinical + Auth Data DB")]
    FILES[("Local/S3 Attachments")]
    SMTP["SMTP / External Services"]
    MODURL["Module Update URLs"]
  end

  WEBIN --> WEB
  UGC --> WEB
  HL7IN --> SERVICES
  XMLIN --> SERIAL

  WEB --> FILTERS --> SERVICES --> DAO --> DBASE
  SERVICES --> FILES
  SERVICES --> SMTP
  SERVICES --> SERIAL
  MODULES --> WEB
  MODULES --> SERVICES
  MODULES --> DAO

  RUNTIME --> SERVICES
  GLOBAL --> SERIAL
  ADMIN --> MODULES
  MODURL --> MODULES

  classDef risky fill:#ffe6e6,stroke:#d60000,stroke-width:1px;
  class XMLIN,SERIAL,MODULES,MODURL,DAO risky;
```

## 3) STRIDE-Style Threat Mapping Diagram

```mermaid
flowchart LR
  T1["S: Spoofing\n- Credential stuffing\n- Weak reset token RNG"]
  T2["T: Tampering\n- HL7 data poisoning\n- Unauthorized clinical edits"]
  T3["R: Repudiation\n- Insufficient audit trails\n- Log manipulation"]
  T4["I: Information Disclosure\n- PHI leakage\n- Runtime properties exposure"]
  T5["D: Denial of Service\n- Large uploads/HL7 floods\n- Expensive queries"]
  T6["E: Elevation of Privilege\n- Missing @Authorized\n- Module abuse\n- Unsafe deserialization"]

  C1["AuthN/AuthZ Controls\nContext/UserContext, lockout, @Authorized"]
  C2["Web Defenses\nCSRFGuard, output encoding"]
  C3["Data Access Controls\nHibernate patterns, validation"]
  C4["Serialization Hardening\nXStream whitelist, XXE-safe XML"]
  C5["Operational Controls\nModule governance, secrets mgmt"]
  C6["Audit Controls\nAuditableInterceptor, Envers"]

  T1 --> C1
  T2 --> C3
  T2 --> C6
  T3 --> C6
  T4 --> C2
  T4 --> C5
  T5 --> C3
  T6 --> C1
  T6 --> C4
  T6 --> C5
```

## 4) Attack Paths (Kill Chain View)

```mermaid
flowchart TD
  A["Initial Access"] --> B{"Path"}

  B -->|"Stored XSS"| C["Inject payload in patient/concept field"]
  C --> D["Admin views poisoned page"]
  D --> E["Session hijack"]
  E --> F["Install malicious module"]
  F --> G["RCE + DB exfiltration"]

  B -->|"AuthZ gap"| H["Probe endpoint/service missing @Authorized"]
  H --> I["Read/modify PHI"]

  B -->|"Deserialization"| J["Send crafted XML/serialized object"]
  J --> K["Unsafe marshaller/DAO path"]
  K --> L["Code execution or data corruption"]

  B -->|"Supply chain"| M["Compromise module update URL"]
  M --> N["Admin updates module"]
  N --> O["Malicious code in JVM"]
```

## 5) Critical Risk Heatmap (from supplied calibration)

```mermaid
quadrantChart
  title OpenMRS Threat Priority (Impact vs Likelihood)
  x-axis Low Likelihood --> High Likelihood
  y-axis Low Impact --> High Impact
  quadrant-1 Monitor
  quadrant-2 Reduce
  quadrant-3 Review
  quadrant-4 Immediate Action
  "Stored XSS -> Admin Hijack" : [0.67, 0.82]
  "Missing @Authorized / Priv Esc" : [0.60, 0.90]
  "Unsafe Deserialization RCE" : [0.45, 0.98]
  "Module Upload/Update Compromise" : [0.40, 1.00]
  "SQL/HQL Injection" : [0.50, 0.96]
  "CSRF on non-critical action" : [0.62, 0.42]
  "Password reset token predictability" : [0.58, 0.48]
  "Version/banner info leak" : [0.78, 0.18]
```

## 6) Diagram Notes and Usage

- The **Module System** is explicitly modeled as a **high-trust, high-impact boundary** because installed modules run with full JVM permissions and can bypass normal guardrails.
- The **serialization path** (XStream/XML/Jackson plus serialized-object persistence) is highlighted as a critical control point where whitelist misconfiguration can create RCE conditions.
- The **operator configuration boundary** is shown separately because runtime/global properties directly influence security posture (lockout, serializer whitelist, module upload).
- Use these diagrams in design reviews to ensure every new endpoint/module change is checked for: authentication, authorization, output encoding, CSRF, validation, and secure serialization.

## 7) How to View These Diagrams

You can view these Mermaid diagrams in several ways:

1. **On GitHub/GitLab UI (recommended)**
   - Open `doc/THREAT_MODEL_DIAGRAMS.md` in the repository web UI.
   - Mermaid code blocks are rendered automatically in modern GitHub markdown viewers.

2. **In VS Code**
   - Open this file in VS Code.
   - Use Markdown preview (`Ctrl+Shift+V` / `Cmd+Shift+V`).
   - If Mermaid is not rendered by your current setup, install a Markdown Mermaid preview extension.

3. **In Mermaid Live Editor**
   - Go to [https://mermaid.live](https://mermaid.live).
   - Copy one Mermaid block (between ```mermaid ... ```), paste it into the editor, and render/export PNG/SVG.

4. **From CLI (optional)**
   - If `@mermaid-js/mermaid-cli` is installed, save a diagram block as `.mmd` and run:
     - `mmdc -i diagram.mmd -o diagram.svg`

If you want, I can also split this file into:
- `doc/diagrams/architecture.mmd`
- `doc/diagrams/trust-boundary.mmd`
- `doc/diagrams/attack-paths.mmd`

so each diagram can be rendered/exported independently in CI.
