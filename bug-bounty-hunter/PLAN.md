# BugBountyHunter - Sistema Automatizado de Caza de Vulnerabilidades

## Visión General

**BugBountyHunter** es un sistema automatizado end-to-end diseñado para descubrir vulnerabilidades de seguridad en repositorios públicos de GitHub, generar reportes profesionales y facilitar su envío a plataformas de Bug Bounty (HackerOne, Bugcrowd, Intigriti) para generar ingresos.

---

## Arquitectura del Sistema

```
┌─────────────────────────────────────────────────────────────────────┐
│                        BugBountyHunter                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────────────────┐  │
│  │   Target      │   │  Repo        │   │  Security Scanners     │  │
│  │   Discovery   │──▶│  Fetcher     │──▶│                        │  │
│  │   Module      │   │  & Cloner    │   │  ┌──────────────────┐  │  │
│  └──────────────┘   └──────────────┘   │  │ SAST Scanner     │  │  │
│         │                               │  │ (Semgrep)        │  │  │
│         │                               │  └──────────────────┘  │  │
│  ┌──────────────┐                      │  ┌──────────────────┐  │  │
│  │  Bug Bounty   │                      │  │ Dependency       │  │  │
│  │  Platform     │                      │  │ Scanner (OSV)    │  │  │
│  │  Integrator   │                      │  └──────────────────┘  │  │
│  └──────────────┘                      │  ┌──────────────────┐  │  │
│         │                               │  │ Secret Scanner   │  │  │
│         │                               │  │ (TruffleHog)     │  │  │
│  ┌──────────────┐                      │  └──────────────────┘  │  │
│  │  Report       │                      │  ┌──────────────────┐  │  │
│  │  Generator    │◀─────────────────────│  │ Misconfig        │  │  │
│  │  & Submitter  │                      │  │ Scanner          │  │  │
│  └──────────────┘                      │  └──────────────────┘  │  │
│         │                               │  ┌──────────────────┐  │  │
│         │                               │  │ AI Triage &      │  │  │
│  ┌──────────────┐                      │  │ Dedup Engine     │  │  │
│  │  Dashboard    │                      │  └──────────────────┘  │  │
│  │  & Tracker    │                      └────────────────────────┘  │
│  └──────────────┘                                                   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    PostgreSQL Database                        │   │
│  │  (targets, scans, findings, reports, submissions, earnings)  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Job Queue (BullMQ/Redis)                   │   │
│  │  (scan jobs, report jobs, scheduled discovery)                │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Módulos Detallados

### 1. Target Discovery Module

**Propósito:** Descubrir automáticamente repositorios y organizaciones en GitHub que tengan programas de Bug Bounty activos.

**Fuentes de datos:**
- **HackerOne API** - Programas públicos con scope de GitHub
- **Bugcrowd API** - Programas públicos
- **Intigriti API** - Programas públicos
- **GitHub Search API** - Repos con archivos `SECURITY.md`, `security.txt`, `.well-known/security.txt`
- **Scraping de programas** - Páginas de política de divulgación responsable
- **Listas curadas** - Repos como `disclose/diodb`, `projectdiscovery/public-bugbounty-programs`

**Funcionalidades:**
- Descubrimiento automático de nuevos programas de Bug Bounty
- Mapping entre programas de bounty y repos de GitHub
- Filtrado por: lenguaje, tamaño, actividad, payout range
- Priorización por: ratio de pagos, velocidad de respuesta, bounty medio
- Cache y actualización periódica de la lista de targets
- Detección de scope (qué repos/dominios están in-scope)

**Base de datos - Tabla `targets`:**
```sql
CREATE TABLE targets (
  id UUID PRIMARY KEY,
  platform VARCHAR(50),        -- hackerone, bugcrowd, intigriti
  program_slug VARCHAR(255),
  program_name VARCHAR(255),
  github_org VARCHAR(255),
  github_repos JSONB,          -- lista de repos in-scope
  scope_rules JSONB,           -- reglas de scope detalladas
  avg_bounty DECIMAL,
  response_time_days INTEGER,
  last_scanned_at TIMESTAMP,
  priority_score DECIMAL,
  status VARCHAR(20),          -- active, paused, archived
  created_at TIMESTAMP,
  updated_at TIMESTAMP
);
```

---

### 2. Repository Fetcher & Cloner

**Propósito:** Clonar y preparar repos para análisis, respetando rate limits.

**Funcionalidades:**
- Clonado shallow (`--depth 1`) para análisis rápido
- Clonado completo para análisis de historial (secrets en commits antiguos)
- Rate limiting inteligente con la API de GitHub
- Cache de repos ya clonados con detección de cambios
- Detección automática de lenguaje y stack tecnológico
- Extracción de metadatos (CI/CD configs, docker files, dependencias)

**Estrategia de clonado:**
```
1. Clone shallow → análisis rápido (SAST, deps, misconfig)
2. Si hay hallazgos interesantes → clone completo
3. Análisis de historial git para secrets
4. Cleanup automático de repos viejos (LRU cache)
```

---

### 3. Security Scanners

#### 3.1 SAST Scanner (Static Application Security Testing)

**Motor principal:** Semgrep (open-source, multi-lenguaje)

**Vulnerabilidades a detectar:**
- **Injection Flaws:** SQL Injection, NoSQL Injection, Command Injection, LDAP Injection
- **XSS:** Reflected, Stored, DOM-based
- **SSRF:** Server-Side Request Forgery
- **Path Traversal:** Directory traversal, file inclusion
- **Insecure Deserialization:** pickle, yaml.load, JSON parse unsafe
- **Broken Authentication:** JWT sin verificación, tokens hardcoded
- **IDOR:** Insecure Direct Object References (patrones comunes)
- **Race Conditions:** TOCTOU, doble-spending
- **Crypto Issues:** Algoritmos débiles, IV reutilizados, ECB mode

**Reglas personalizadas Semgrep:**
```yaml
# Ejemplo: Detectar SQL injection en Node.js
rules:
  - id: node-sql-injection
    patterns:
      - pattern: |
          $DB.query(`...${$INPUT}...`)
      - pattern-not: |
          $DB.query(`...${$SAFE}...`, [...])
    message: "Potential SQL injection via string interpolation"
    severity: ERROR
    metadata:
      cwe: CWE-89
      bounty_potential: high
```

**Reglas por lenguaje:**
- **JavaScript/TypeScript:** ~150 reglas (prototype pollution, eval, innerHTML, etc.)
- **Python:** ~120 reglas (pickle, subprocess, os.system, etc.)
- **Java:** ~100 reglas (Spring vulnerabilities, JNDI, etc.)
- **Go:** ~80 reglas (unsafe, command execution, etc.)
- **Ruby:** ~60 reglas (Rails-specific, ERB injection, etc.)
- **PHP:** ~80 reglas (include, eval, unserialize, etc.)

#### 3.2 Dependency Scanner

**Motor principal:** OSV-Scanner + Trivy

**Funcionalidades:**
- Escaneo de `package.json`, `requirements.txt`, `Gemfile`, `pom.xml`, `go.mod`, etc.
- Verificación contra bases de datos de CVEs: NVD, GitHub Advisory, OSV
- Scoring de severidad basado en CVSS + explotabilidad
- Detección de dependencias transitivas vulnerables
- Verificación de si la vulnerabilidad es realmente alcanzable en el código
- Priorización: RCE > Auth Bypass > Info Disclosure > DoS

**Base de datos - Tabla `findings`:**
```sql
CREATE TABLE findings (
  id UUID PRIMARY KEY,
  target_id UUID REFERENCES targets(id),
  scan_id UUID REFERENCES scans(id),
  scanner_type VARCHAR(50),     -- sast, dependency, secret, misconfig
  vulnerability_type VARCHAR(100),
  severity VARCHAR(20),          -- critical, high, medium, low, info
  cvss_score DECIMAL,
  cwe_id VARCHAR(20),
  title VARCHAR(500),
  description TEXT,
  file_path VARCHAR(1000),
  line_number INTEGER,
  code_snippet TEXT,
  remediation TEXT,
  false_positive BOOLEAN DEFAULT false,
  triage_status VARCHAR(20),    -- pending, confirmed, rejected, submitted
  confidence_score DECIMAL,     -- 0.0 - 1.0 AI confidence
  bounty_estimate DECIMAL,
  created_at TIMESTAMP,
  updated_at TIMESTAMP
);
```

#### 3.3 Secret Scanner

**Motor principal:** TruffleHog + reglas custom

**Tipos de secrets a detectar:**
- API Keys (AWS, GCP, Azure, Stripe, Twilio, SendGrid, etc.)
- Tokens de OAuth/JWT hardcoded
- Contraseñas en archivos de configuración
- Certificados y claves privadas
- Database connection strings
- Webhooks URLs con tokens
- Secrets en variables de entorno commiteadas (.env files)

**Análisis de historial:**
```
1. Escanear todos los commits del historial
2. Detectar secrets que fueron añadidos y luego removidos
3. Verificar si el secret sigue siendo válido (con cuidado, sin abusar)
4. Priorizar secrets de producción vs desarrollo
```

#### 3.4 Misconfiguration Scanner

**Targets:**
- **Docker:** Dockerfiles inseguros (root, secrets en build, puertos expuestos)
- **Kubernetes:** RBAC permisivo, secrets sin encriptar, pods privilegiados
- **Terraform/CloudFormation:** S3 público, security groups abiertos, IAM excesivo
- **CI/CD:** GitHub Actions con injection, secrets expuestos en logs
- **CORS:** Configuraciones permisivas
- **Headers:** Missing security headers en configs de servidores
- **Package configs:** npm scripts maliciosos, postinstall hooks

---

### 4. AI Triage & Deduplication Engine

**Propósito:** Reducir falsos positivos y priorizar hallazgos con mayor probabilidad de ser bounty-worthy.

**Funcionalidades:**
- **Clasificación de confianza:** Score 0-1 de probabilidad de ser un bug real
- **Deduplicación:** Detectar si el mismo bug ya fue reportado antes
- **Análisis de contexto:** Verificar si el código vulnerable es realmente alcanzable
- **Estimación de bounty:** Predecir el rango de pago basado en tipo y severidad
- **Priorización:** Ordenar hallazgos por ROI esperado (bounty * probabilidad)

**Modelo de scoring:**
```
FinalScore = (Severity * 0.3) + (Confidence * 0.25) + (Reachability * 0.2) 
           + (BountyEstimate * 0.15) + (Novelty * 0.1)
```

**Integración con LLM (opcional):**
- Usar OpenAI/Claude API para analizar el contexto del código
- Generar explicación de la vulnerabilidad
- Verificar si la vulnerabilidad tiene impact real
- Sugerir pasos de reproducción

---

### 5. Report Generator

**Propósito:** Generar reportes de vulnerabilidades profesionales listos para enviar a plataformas de Bug Bounty.

**Formato del reporte:**
```markdown
## Title: [CWE-ID] Vulnerability Type in component/file

### Summary
Brief description of the vulnerability.

### Severity
CVSS Score: X.X (Critical/High/Medium/Low)

### Description
Detailed technical explanation.

### Steps to Reproduce
1. Step 1
2. Step 2
3. Step 3

### Impact
What can an attacker do with this vulnerability.

### Affected Code
File: path/to/file.js
Line: 42
```code snippet```

### Remediation
How to fix the vulnerability.

### References
- CWE link
- OWASP link
- Similar CVEs
```

**Templates por plataforma:**
- HackerOne format
- Bugcrowd format
- Intigriti format
- Generic markdown

**Base de datos - Tabla `reports`:**
```sql
CREATE TABLE reports (
  id UUID PRIMARY KEY,
  finding_id UUID REFERENCES findings(id),
  target_id UUID REFERENCES targets(id),
  platform VARCHAR(50),
  title VARCHAR(500),
  severity VARCHAR(20),
  report_body TEXT,
  status VARCHAR(30),           -- draft, ready, submitted, triaged, resolved, paid
  submitted_at TIMESTAMP,
  bounty_amount DECIMAL,
  platform_report_id VARCHAR(255),
  response_notes TEXT,
  created_at TIMESTAMP,
  updated_at TIMESTAMP
);
```

---

### 6. Dashboard & Tracker

**Propósito:** Visualizar el estado de escaneos, hallazgos, reportes y ganancias.

**Métricas del Dashboard:**
- Total de targets monitoreados
- Escaneos ejecutados (hoy/semana/mes)
- Hallazgos por severidad y tipo
- Reportes enviados vs aceptados vs pagados
- Ganancias totales y por mes
- Tasa de falsos positivos
- Tiempo promedio de respuesta por plataforma
- ROI por programa de bounty

---

## Stack Tecnológico

| Componente | Tecnología | Justificación |
|---|---|---|
| Runtime | Node.js 20+ | Tu expertise, ecosistema rico |
| Lenguaje | TypeScript 5+ | Type safety, mejor mantenimiento |
| Framework API | Fastify | Performance superior a Express |
| Base de datos | PostgreSQL 16 | JSONB, full-text search, robustez |
| ORM | Prisma | Type-safe queries, migrations |
| Job Queue | BullMQ + Redis | Jobs distribuidos, retry, scheduling |
| SAST Engine | Semgrep | Open-source, multi-lenguaje, extensible |
| Dep Scanner | OSV-Scanner | Google-backed, base de datos completa |
| Secret Scanner | TruffleHog | Detector de entropía + patrones |
| Misconfig | Custom + Checkov | IaC scanning |
| Containerización | Docker + Docker Compose | Reproducibilidad |
| CI/CD | GitHub Actions | Integración nativa |
| Dashboard | Next.js + Tailwind | SSR, UI moderna |
| Logging | Pino | Structured logging, performance |
| Testing | Vitest | Rápido, compatible con Jest |

---

## Plan de Desarrollo - Fases

### Fase 1: Foundation (Core)
**Objetivo:** Tener el sistema base funcionando con un scanner.

- [x] Definir arquitectura y plan
- [x] Scaffolding del proyecto
- [x] Setup de base de datos PostgreSQL + schema Prisma
- [x] Setup de Redis + BullMQ (job processors implementados)
- [x] Módulo de configuración centralizado (Zod-validated)
- [x] Target Discovery básico (HackerOne, Bugcrowd, GitHub)
- [x] Repository Fetcher (clone + metadata + cache)
- [x] SAST Scanner con Semgrep (reglas JS/TS/Python/Go/Java + fallback)
- [x] Report Generator (templates HackerOne, Bugcrowd, Generic)
- [x] CLI para ejecutar escaneos manuales (6 comandos)
- [x] Tests unitarios básicos (36 tests)
- [x] Docker Compose para desarrollo local

### Fase 2: Scanners Completos
**Objetivo:** Todos los scanners funcionando y produciendo resultados.

- [x] Dependency Scanner con OSV (multi-ecosystem: npm, PyPI, Go, Cargo, Maven, etc.)
- [x] Secret Scanner con TruffleHog (+ 14 patrones regex built-in)
- [x] Misconfiguration Scanner (8 reglas: Docker, GHA, CORS, Terraform, K8s, npm)
- [x] Reglas Semgrep personalizadas (JavaScript, Python, Go, Java)
- [x] Deduplicación de hallazgos (SHA-256 fingerprinting)
- [x] Scoring de confianza básico (multi-factor weighted scoring)
- [x] Integración con más plataformas de bounty (HackerOne + Bugcrowd submitters)
- [x] Pipeline de escaneo completo (discovery → scan → triage → report)
- [x] Tests unitarios extensos (36 tests en 6 suites)
- [ ] Tests de integración end-to-end

### Fase 3: Inteligencia & Automatización
**Objetivo:** AI triage y automatización del flujo completo.

- [ ] Integración con LLM para triage
- [x] Verificación de alcanzabilidad del código vulnerable (heuristic reachability scoring)
- [x] Estimación automática de bounty (por severidad/tipo/confianza)
- [ ] Scheduling de escaneos periódicos (BullMQ job infrastructure ready)
- [ ] Notificaciones (email, Slack, Discord)
- [x] Auto-submission a plataformas (HackerOne API + Bugcrowd API)
- [x] API server básico (Fastify: /api/scan, /api/discover, /health)

### Fase 4: Optimización & Escala
**Objetivo:** Maximizar ROI y reducir falsos positivos.

- [ ] ML model para clasificación de FP
- [ ] Análisis de repos que han pagado bounties antes
- [ ] Priorización inteligente de targets
- [ ] Paralelización de escaneos
- [ ] Métricas y analytics avanzados
- [ ] Dashboard completo con gráficos
- [ ] Rate limiting y respeto de ToS
- [ ] Documentación completa

---

## Consideraciones Legales y Éticas

### IMPORTANTE - Reglas a seguir SIEMPRE:

1. **Solo escanear repos públicos** - Nunca repos privados sin autorización
2. **Respetar el scope** - Solo reportar bugs dentro del scope definido por el programa
3. **No explotar vulnerabilidades** - Solo identificar y reportar
4. **No acceder a datos de usuarios** - Si encuentras un secret válido, reportarlo sin usarlo
5. **Respetar rate limits** - No hacer DoS accidental a GitHub o a los targets
6. **Divulgación responsable** - Seguir los tiempos de disclosure de cada programa
7. **No duplicar reportes** - Verificar que el bug no haya sido reportado antes
8. **Ser honesto** - No inflar la severidad para obtener más bounty
9. **Cumplir ToS** - De GitHub, HackerOne, Bugcrowd, etc.
10. **Mantener registros** - Documentar todo el proceso para transparencia

### Legalidad por jurisdicción:
- Verificar las leyes de computer fraud de tu país
- Algunos países tienen excepciones para security research
- Siempre tener evidence de que el programa autoriza testing

---

## Estimación de Ingresos Potenciales

### Datos del mercado (2024-2025):
- **Bounty medio por bug:** $200 - $2,000 (dependiendo de severidad)
- **Critical bugs:** $5,000 - $50,000+
- **High bugs:** $1,000 - $10,000
- **Medium bugs:** $200 - $2,000
- **Low bugs:** $50 - $500

### Proyección conservadora:
```
Mes 1-2: Desarrollo + calibración → $0
Mes 3: 2-3 bugs medium reportados → $400-$2,000
Mes 4-6: 5-10 bugs/mes (mix) → $2,000-$10,000/mes
Mes 6+: Sistema optimizado → $5,000-$20,000/mes (optimista)
```

### Factores clave para maximizar ingresos:
1. **Velocidad** - Ser el primero en reportar
2. **Calidad** - Reportes claros y bien documentados
3. **Targets** - Enfocarse en programas con buenos payouts
4. **Reglas custom** - Detectar vulnerabilidades que otros tools no detectan
5. **Triage** - Minimizar tiempo en falsos positivos

---

## Estructura del Proyecto

```
bug-bounty-hunter/
├── PLAN.md                          # Este archivo
├── README.md                        # Documentación del proyecto
├── package.json                     # Dependencias raíz
├── tsconfig.json                    # TypeScript config base
├── docker-compose.yml               # Setup de desarrollo
├── .env.example                     # Variables de entorno ejemplo
├── prisma/
│   └── schema.prisma                # Schema de base de datos
├── src/
│   ├── index.ts                     # Entry point
│   ├── cli.ts                       # CLI interface
│   ├── config/
│   │   └── index.ts                 # Configuración centralizada
│   ├── core/
│   │   ├── target-discovery/
│   │   │   ├── index.ts             # Orquestador de discovery
│   │   │   ├── hackerone.ts         # HackerOne integration
│   │   │   ├── bugcrowd.ts         # Bugcrowd integration
│   │   │   └── github-search.ts    # GitHub search integration
│   │   ├── repo-fetcher/
│   │   │   ├── index.ts             # Cloner & manager
│   │   │   └── git-client.ts       # Git operations
│   │   ├── scanners/
│   │   │   ├── index.ts             # Scanner orchestrator
│   │   │   ├── sast/
│   │   │   │   ├── index.ts         # SAST scanner
│   │   │   │   └── rules/           # Semgrep rules custom
│   │   │   ├── dependency/
│   │   │   │   └── index.ts         # Dependency scanner
│   │   │   ├── secrets/
│   │   │   │   └── index.ts         # Secret scanner
│   │   │   └── misconfig/
│   │   │       └── index.ts         # Misconfiguration scanner
│   │   ├── triage/
│   │   │   ├── index.ts             # AI triage engine
│   │   │   ├── dedup.ts            # Deduplication
│   │   │   └── scorer.ts           # Confidence scoring
│   │   └── reporter/
│   │       ├── index.ts             # Report orchestrator
│   │       ├── generator.ts        # Report generator
│   │       ├── templates/           # Report templates
│   │       └── submitter.ts        # Platform submission
│   ├── jobs/
│   │   ├── scan-job.ts              # Scan job processor
│   │   ├── discovery-job.ts        # Discovery job processor
│   │   └── report-job.ts           # Report job processor
│   ├── api/
│   │   ├── server.ts                # Fastify server
│   │   └── routes/                  # API routes
│   ├── dashboard/                   # Next.js dashboard (Fase 3+)
│   └── utils/
│       ├── logger.ts                # Pino logger
│       ├── rate-limiter.ts         # Rate limiting
│       └── github-client.ts        # GitHub API wrapper
├── rules/
│   ├── semgrep/
│   │   ├── javascript/              # JS/TS rules
│   │   ├── python/                  # Python rules
│   │   ├── java/                    # Java rules
│   │   └── go/                      # Go rules
│   └── misconfig/
│       ├── docker.yaml              # Docker rules
│       ├── kubernetes.yaml          # K8s rules
│       └── cicd.yaml                # CI/CD rules
└── tests/
    ├── unit/                        # Unit tests
    ├── integration/                 # Integration tests
    └── fixtures/                    # Test fixtures
```

---

## Cómo Empezar

```bash
# 1. Clonar y setup
git clone <repo>
cd bug-bounty-hunter
npm install

# 2. Configurar variables de entorno
cp .env.example .env
# Editar .env con tus API keys

# 3. Levantar servicios
docker-compose up -d  # PostgreSQL + Redis

# 4. Migrar base de datos
npx prisma migrate dev

# 5. Ejecutar un escaneo manual
npx ts-node src/cli.ts scan --repo https://github.com/org/repo

# 6. Ver resultados
npx ts-node src/cli.ts findings --severity high

# 7. Generar reporte
npx ts-node src/cli.ts report --finding-id <id>
```

---

## Siguiente Paso Inmediato

El scaffolding del proyecto ya está creado con los módulos iniciales. Revisa el código fuente en `src/` para ver la implementación base de cada componente.
