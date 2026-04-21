# ALEJANDRO PEREZ ABREU

**Backend Engineer | Node.js | TypeScript | AI/LLM Integration**

Viladecans, Barcelona, Spain  
Email: alejandroperezabreu.dev@gmail.com  
Phone: +34 662 011 364  
LinkedIn: linkedin.com/in/alejandroperezabreu  
GitHub: github.com/Circe07

---

## PROFESSIONAL SUMMARY

Backend Engineer specialized in the Node.js and TypeScript ecosystem, with proven
experience designing and building robust, scalable REST APIs and event-driven services.
Skilled in integrating Large Language Models (LLMs) and Retrieval-Augmented Generation
(RAG) pipelines to automate business processes. Strong background in service-oriented
architectures, secure API design (OWASP Top 10, OAuth 2.0, JWT, RBAC) and
Test-Driven Development (TDD) with Jest. Experienced leading product-oriented
features end to end, from data modeling to deployment with Docker.

---

## CORE SKILLS

- **Languages:** TypeScript, JavaScript (ES2022+), SQL, HTML, CSS
- **Backend & Frameworks:** Node.js, Express, Next.js (App Router), REST APIs, WebSockets, Firebase Cloud Functions
- **AI / LLM:** Google Gemini 3 (Flash / 3.1 Pro), Vercel AI SDK, Local Vector Store, Retrieval-Augmented Generation (RAG), Prompt Engineering
- **Databases:** PostgreSQL, MySQL, MongoDB, Firestore, SQLite, Redis, Prisma ORM
- **Testing & Quality:** Jest, TDD, Contract Testing, End-to-End Testing, Postman
- **Security:** OAuth 2.0, JWT, OWASP Top 10, API Hardening, RBAC, Rate Limiting, Security Headers, Input Validation
- **DevOps & Tooling:** Docker, Git, GitHub Actions, Firebase Emulators, Inngest (async jobs), pnpm, CI/CD
- **Architecture:** REST, Microservices, Event-Driven, Monorepo (pnpm workspaces), SOLID Principles, Clean Architecture

---

## PROFESSIONAL EXPERIENCE

### Store Manager (previously Specialized Sales Associate)
**TI PC Shop** — Viladecans, Barcelona, Spain  
**August 2023 – December 2024**

- Led end-to-end store operations and managed a small team, handling B2B and B2C customer relations.
- Digitized inventory and customer-service processes, reducing manual tracking errors and improving order turnaround.
- Delivered technical consulting on digital ecosystems (hardware, networking, software) to recurring business clients.
- Optimized sales conversion through targeted product-marketing strategies and structured upsell/cross-sell flows.

### Technical Sales Specialist
**Honor Spain** — Barcelona, Spain  
*(Retail technical promoter)*

- Advised customers on product specifications, features and integration across the mobile ecosystem.
- Delivered in-store training and product demos, improving brand positioning and conversion metrics.

---

## FEATURED SOFTWARE PROJECTS

### Archi-Legal CRM — Smart Omnichannel AI Backend
*Next.js 16, TypeScript, Gemini 3, Inngest, Local Vector Store, Prisma, SQLite*  
Repository: github.com/Circe07/smart-legal-architecture-crm

- Designed and built a multi-package monorepo (pnpm workspaces) for an AI-powered CRM targeting architecture and legal firms.
- Implemented omnichannel ingestion unifying WhatsApp Cloud API and Email webhooks into a single processing pipeline.
- Engineered an asynchronous workflow with Inngest so all heavy AI operations run in the background, keeping webhook response times near-instant and improving reliability.
- Integrated Google Gemini 3 Flash and 3.1 Pro via the Vercel AI SDK for automated intent classification, urgency detection and missing-document identification.
- Built a local Retrieval-Augmented Generation (RAG) layer with a pure-JS Vector Store and a zero-hallucination protocol, so answers are grounded only in verified firm knowledge (FAQs).
- Implemented smart escalation logic that differentiates simple queries from complex legal cases, delivering enriched summaries and priority alerts to professionals.
- Organized the codebase into clear domains: `apps/web` (Next.js dashboard and API routes), `packages/core` (Inngest functions, Gemini agents, vector store), `packages/db` (Prisma-compatible data layer) and `packages/domain` (shared types and schemas).

### Start & Connect — RESTful Social Platform API
*Node.js, Express, Firebase Cloud Functions, Cloud Firestore, React Native*  
Repository: github.com/Circe07/Start-Connect

- Developed a production-oriented REST API for users, community groups and posts, deployed on Firebase Cloud Functions.
- Implemented secure authentication (JWT / Firebase Auth), role-based access control, rate limiting and configurable CORS allowlists for production hardening.
- Modeled geospatial data in Firestore to power real-time matching and proximity-based features.
- Integrated transactional push notifications and real-time chat.
- Authored OpenAPI documentation and a full testing suite covering contract, end-to-end, security and performance-smoke tests, plus Postman collections for frontend integration.
- Set up environment-based configuration and Firebase emulator workflows for local development and CI.

### Financial Search API — Offline-First Market Data Engine
*Node.js, Express, SQLite, Alpha Vantage API*  
Repository: github.com/Circe07/financial-search-api

- Built an offline-first search API that periodically ingests market data from Alpha Vantage into a local SQLite database, removing real-time API rate-limit bottlenecks.
- Designed a flexible `/search` endpoint supporting full-text queries combined with advanced filters (market, sector, P/E ratio, volume, YTD performance).
- Implemented a scheduled data-update script respecting external API rate limits, suitable for CRON-based execution.
- Delivered clean error handling and structured JSON responses aligned with REST best practices.

---

## EDUCATION

**Technological Baccalaureate (Bachillerato Tecnologico, BTO)**

---

## LANGUAGES

- **Spanish:** Native
- **English:** Intermediate (B1–B2), professional working proficiency

---

## ADDITIONAL INFORMATION

- Open to hybrid and remote roles based in Spain or the EU.
- Strong interest in AI-driven backend systems, secure API design and developer experience.
