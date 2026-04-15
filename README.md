<h1 align="center">Alejandro Perez Abreu</h1>
<h3 align="center">Backend Engineer &bull; Software Architect &bull; Security-First Development</h3>

<p align="center">
  <a href="https://www.linkedin.com/in/alejandroperezabreu"><img src="https://img.shields.io/badge/LinkedIn-0A66C2?style=flat&logo=linkedin&logoColor=white" alt="LinkedIn"/></a>
  <a href="mailto:alejandroperezabreu.dev@gmail.com"><img src="https://img.shields.io/badge/Email-D14836?style=flat&logo=gmail&logoColor=white" alt="Email"/></a>
</p>

---

## Core Stack

| Layer | Technologies |
|---|---|
| **Languages** | ![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=flat&logo=typescript&logoColor=white) ![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat&logo=javascript&logoColor=black) ![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white) |
| **Backend** | ![Node.js](https://img.shields.io/badge/Node.js-339933?style=flat&logo=node.js&logoColor=white) ![Express](https://img.shields.io/badge/Express-000000?style=flat&logo=express&logoColor=white) ![Next.js](https://img.shields.io/badge/Next.js-000000?style=flat&logo=next.js&logoColor=white) |
| **Databases** | ![MySQL](https://img.shields.io/badge/MySQL-4479A1?style=flat&logo=mysql&logoColor=white) ![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=flat&logo=postgresql&logoColor=white) ![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=flat&logo=mongodb&logoColor=white) ![SQLite](https://img.shields.io/badge/SQLite-003B57?style=flat&logo=sqlite&logoColor=white) |
| **Cloud & BaaS** | ![Firebase](https://img.shields.io/badge/Firebase-DD2C00?style=flat&logo=firebase&logoColor=white) ![AWS](https://img.shields.io/badge/AWS-232F3E?style=flat&logo=amazon-web-services&logoColor=white) |
| **ORM / Data** | ![Prisma](https://img.shields.io/badge/Prisma-2D3748?style=flat&logo=prisma&logoColor=white) |

## Tools & DevOps

![Git](https://img.shields.io/badge/Git-F05032?style=flat&logo=git&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat&logo=docker&logoColor=white)
![Postman](https://img.shields.io/badge/Postman-FF6C37?style=flat&logo=postman&logoColor=white)
![pnpm](https://img.shields.io/badge/pnpm-F69220?style=flat&logo=pnpm&logoColor=white)
![Turborepo](https://img.shields.io/badge/Turborepo-EF4444?style=flat&logo=turborepo&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)
![Kali Linux](https://img.shields.io/badge/Kali_Linux-557C94?style=flat&logo=kalilinux&logoColor=white)

---

## Projects Where I Lead Development

### [Smart Legal Architecture CRM](https://github.com/Circe07/smart-legal-architecture-crm) &mdash; SaaS AI-Powered CRM

> Omnichannel CRM for Architectural Law firms, powered by **Gemini 3** and a local RAG engine with Zero-Hallucination protocol.

| Aspect | Detail |
|---|---|
| **Problem** | Architecture and legal professionals manage client queries across fragmented channels (WhatsApp, Email) with no unified triage, causing missed deadlines and duplicated effort. |
| **Solution** | A single AI backend that ingests all channels, classifies intent and urgency automatically, and escalates complex cases with enriched summaries. |
| **Stack** | TypeScript, Next.js 16, Prisma, Inngest, Vercel AI SDK, Gemini 3 Flash / 3.1 Pro |
| **Architecture** | Monorepo (Turborepo + pnpm Workspaces) with scoped packages: `@archi-legal/core`, `@archi-legal/db`, `@archi-legal/domain`, `@archi-legal/ai` |
| **AI Engineering** | AI-assisted frontend development (v0 / Claude) to accelerate UI iteration &mdash; a workflow increasingly adopted in production teams. |
| **Security** | Input validation with Zod schemas, parameterized queries via Prisma ORM (SQL Injection prevention), environment-based secret management (`.env.example` provided, zero credentials in repo). |

---

### [StartAndConnect](https://github.com/Circe07/Start-Connect) &mdash; Social Sports Platform (Team Project)

> RESTful API for sports community management: users, groups, posts, real-time chat, geolocation, and social interactions.

| Aspect | Detail |
|---|---|
| **Problem** | Sports communities lack a single platform to organize groups, discover nearby facilities, and communicate in real time. |
| **Solution** | Full-featured API with Auth, Groups, Posts, Comments, Likes, Chat, Maps (geolocation), and Admin modules &mdash; built for production with a comprehensive test suite. |
| **Stack** | Node.js, Express, Firebase Cloud Functions, Cloud Firestore |
| **Collaboration** | Multi-developer project using Pull Requests, code reviews, and branch-based workflows. OpenAPI spec documented. |
| **Testing** | Phase-gated pipeline: unit tests, contract tests, E2E tests, security tests, and performance smoke tests. |
| **Security** | Firebase Auth token verification, role-based access control (Owner/Admin/Member), rate limiting on auth endpoints, CORS allowlist configuration, Firestore security rules. |

**API Coverage:** 30+ endpoints across 7 modules (Auth, Users, Contacts, Groups, Centers, Maps, Social).

---

### [Financial Search API](https://github.com/Circe07/financial-search-api) &mdash; Offline-First Market Screener

> Local-first financial data search engine with advanced filtering. Data syncs from Alpha Vantage into SQLite for unlimited, fast, complex queries without API rate limits.

| Aspect | Detail |
|---|---|
| **Stack** | Node.js, Express, SQLite, Alpha Vantage API |
| **Architecture** | Offline-First pattern: periodic data sync to local DB, zero external API calls at query time. |
| **Security** | API key managed via environment variables, input validation on all query parameters. |

---

## Security Practices Across All Projects

As someone with a background in cybersecurity (OSINT, Kali Linux, Python scripting), I apply security-by-design principles in every backend I build:

| Practice | Implementation |
|---|---|
| **SQL Injection Prevention** | Parameterized queries via Prisma ORM and prepared statements |
| **Authentication** | Firebase Auth with JWT token verification, session management |
| **Authorization** | Role-based access control (RBAC) at the middleware level |
| **Input Validation** | Schema validation with Zod / Joi before any data processing |
| **Secret Management** | `.env`-based configuration, `.env.example` templates, zero credentials committed |
| **HTTP Hardening** | Helmet.js for security headers, CORS allowlists, rate limiting |
| **Dependency Auditing** | Regular `npm audit` / `pnpm audit` checks |

---

## GitHub Stats

<p align="center">
  <img src="https://github-readme-stats.vercel.app/api?username=Circe07&show_icons=true&theme=github_dark&hide_border=true&count_private=true&rank_icon=github" alt="GitHub Stats" height="165"/>
  <img src="https://github-readme-stats.vercel.app/api/top-langs/?username=Circe07&layout=compact&theme=github_dark&hide_border=true&langs_count=8" alt="Top Languages" height="165"/>
</p>

---

<details>
<summary><strong>Versión en Español</strong></summary>

### Sobre mí

Ingeniero Backend especializado en construir sistemas robustos, escalables y seguros. Mi enfoque combina arquitectura de software sólida con prácticas de ciberseguridad aplicadas a cada proyecto que desarrollo.

### Proyectos destacados

- **Smart Legal Architecture CRM** &mdash; CRM SaaS con IA (Gemini 3) para despachos de arquitectura legal. Monorepo en TypeScript con RAG local y protocolo Zero-Hallucination.
- **StartAndConnect** &mdash; API REST para comunidades deportivas. Proyecto colaborativo con +30 endpoints, testing por fases y documentación OpenAPI.
- **Financial Search API** &mdash; Motor de búsqueda financiera offline-first con SQLite y filtrado avanzado.

### Enfoque

- Arquitectura de software: patrones de diseño, Service Layer, Clean Architecture
- Seguridad: OSINT, hardening, validación de inputs, RBAC
- AI-Assisted Engineering: uso de herramientas de IA para acelerar el desarrollo sin sacrificar calidad

</details>
