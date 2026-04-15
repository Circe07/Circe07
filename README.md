<h1 align="center">Alejandro Perez Abreu</h1>
<h3 align="center">Ingeniero Backend &bull; Arquitecto de Software &bull; Desarrollo Security-First</h3>

<p align="center">
  <a href="https://www.linkedin.com/in/alejandroperezabreu"><img src="https://img.shields.io/badge/LinkedIn-0A66C2?style=flat&logo=linkedin&logoColor=white" alt="LinkedIn"/></a>
  <a href="mailto:alejandroperezabreu.dev@gmail.com"><img src="https://img.shields.io/badge/Email-D14836?style=flat&logo=gmail&logoColor=white" alt="Email"/></a>
</p>

---

## Stack Principal

| Capa | Tecnologias |
|---|---|
| **Lenguajes** | ![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=flat&logo=typescript&logoColor=white) ![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat&logo=javascript&logoColor=black) ![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white) |
| **Backend** | ![Node.js](https://img.shields.io/badge/Node.js-339933?style=flat&logo=node.js&logoColor=white) ![Express](https://img.shields.io/badge/Express-000000?style=flat&logo=express&logoColor=white) ![Next.js](https://img.shields.io/badge/Next.js-000000?style=flat&logo=next.js&logoColor=white) |
| **Bases de Datos** | ![MySQL](https://img.shields.io/badge/MySQL-4479A1?style=flat&logo=mysql&logoColor=white) ![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=flat&logo=postgresql&logoColor=white) ![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=flat&logo=mongodb&logoColor=white) ![SQLite](https://img.shields.io/badge/SQLite-003B57?style=flat&logo=sqlite&logoColor=white) |
| **Cloud & BaaS** | ![Firebase](https://img.shields.io/badge/Firebase-DD2C00?style=flat&logo=firebase&logoColor=white) ![AWS](https://img.shields.io/badge/AWS-232F3E?style=flat&logo=amazon-web-services&logoColor=white) |
| **ORM / Datos** | ![Prisma](https://img.shields.io/badge/Prisma-2D3748?style=flat&logo=prisma&logoColor=white) |

## Herramientas & DevOps

![Git](https://img.shields.io/badge/Git-F05032?style=flat&logo=git&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat&logo=docker&logoColor=white)
![Postman](https://img.shields.io/badge/Postman-FF6C37?style=flat&logo=postman&logoColor=white)
![pnpm](https://img.shields.io/badge/pnpm-F69220?style=flat&logo=pnpm&logoColor=white)
![Turborepo](https://img.shields.io/badge/Turborepo-EF4444?style=flat&logo=turborepo&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)
![Kali Linux](https://img.shields.io/badge/Kali_Linux-557C94?style=flat&logo=kalilinux&logoColor=white)

---

## Proyectos en los que Lidero el Desarrollo

### [Smart Legal Architecture CRM](https://github.com/Circe07/smart-legal-architecture-crm) &mdash; CRM SaaS con IA

> CRM omnicanal para despachos de Arquitectura Legal, impulsado por **Gemini 3** y un motor RAG local con protocolo Zero-Hallucination.

| Aspecto | Detalle |
|---|---|
| **Problema** | Los profesionales de arquitectura y derecho gestionan consultas de clientes en canales fragmentados (WhatsApp, Email) sin triaje unificado, provocando plazos perdidos y esfuerzo duplicado. |
| **Solucion** | Un backend con IA que ingesta todos los canales, clasifica intenciones y urgencia automaticamente, y escala casos complejos con resumenes enriquecidos. |
| **Stack** | TypeScript, Next.js 16, Prisma, Inngest, Vercel AI SDK, Gemini 3 Flash / 3.1 Pro |
| **Arquitectura** | Monorepo (Turborepo + pnpm Workspaces) con paquetes: `@archi-legal/core`, `@archi-legal/db`, `@archi-legal/domain`, `@archi-legal/ai` |
| **AI Engineering** | Desarrollo frontend asistido por IA (v0 / Claude) para acelerar iteraciones de UI &mdash; flujo de trabajo adoptado en equipos de produccion. |
| **Seguridad** | Validacion de inputs con esquemas Zod, queries parametrizadas via Prisma ORM (prevencion SQL Injection), gestion de secretos basada en `.env.example`, cero credenciales en el repositorio. |

---

### [StartAndConnect](https://github.com/Circe07/Start-Connect) &mdash; Plataforma Social Deportiva (Proyecto en Equipo)

> API RESTful para gestion de comunidades deportivas: usuarios, grupos, publicaciones, chat en tiempo real, geolocalizacion e interacciones sociales.

| Aspecto | Detalle |
|---|---|
| **Problema** | Las comunidades deportivas carecen de una plataforma unica para organizar grupos, descubrir instalaciones cercanas y comunicarse en tiempo real. |
| **Solucion** | API completa con modulos de Auth, Groups, Posts, Comments, Likes, Chat, Maps (geolocalizacion) y Admin &mdash; construida para produccion con suite de testing integral. |
| **Stack** | Node.js, Express, Firebase Cloud Functions, Cloud Firestore |
| **Colaboracion** | Proyecto multi-desarrollador usando Pull Requests, code reviews y flujos basados en ramas. Spec OpenAPI documentada. |
| **Testing** | Pipeline por fases: tests unitarios, tests de contrato, tests E2E, tests de seguridad y smoke tests de rendimiento. |
| **Seguridad** | Verificacion de tokens Firebase Auth, control de acceso basado en roles (Owner/Admin/Member), rate limiting en endpoints de autenticacion, configuracion de CORS allowlist, reglas de seguridad de Firestore. |

**Cobertura de API:** +30 endpoints en 7 modulos (Auth, Users, Contacts, Groups, Centers, Maps, Social).

---

### [Financial Search API](https://github.com/Circe07/financial-search-api) &mdash; Screener Financiero Offline-First

> Motor de busqueda financiera local-first con filtrado avanzado. Los datos se sincronizan desde Alpha Vantage a SQLite para consultas ilimitadas, rapidas y complejas sin limites de API.

| Aspecto | Detalle |
|---|---|
| **Stack** | Node.js, Express, SQLite, Alpha Vantage API |
| **Arquitectura** | Patron Offline-First: sincronizacion periodica a DB local, cero llamadas a APIs externas en tiempo de consulta. |
| **Seguridad** | API key gestionada via variables de entorno, validacion de inputs en todos los parametros de consulta. |

---

## Practicas de Seguridad en Todos los Proyectos

Con formacion en ciberseguridad (OSINT, Kali Linux, scripting en Python), aplico principios de security-by-design en cada backend que construyo:

| Practica | Implementacion |
|---|---|
| **Prevencion de SQL Injection** | Queries parametrizadas via Prisma ORM y prepared statements |
| **Autenticacion** | Firebase Auth con verificacion de tokens JWT, gestion de sesiones |
| **Autorizacion** | Control de acceso basado en roles (RBAC) a nivel de middleware |
| **Validacion de Inputs** | Validacion de esquemas con Zod / Joi antes de cualquier procesamiento |
| **Gestion de Secretos** | Configuracion basada en `.env`, plantillas `.env.example`, cero credenciales commiteadas |
| **Hardening HTTP** | Helmet.js para headers de seguridad, CORS allowlists, rate limiting |
| **Auditoria de Dependencias** | Chequeos regulares con `npm audit` / `pnpm audit` |

---

## Estadisticas de GitHub

<p align="center">
  <img src="https://github-readme-stats.vercel.app/api?username=Circe07&show_icons=true&theme=github_dark&hide_border=true&count_private=true&rank_icon=github&locale=es" alt="Estadisticas GitHub" height="165"/>
  <img src="https://github-readme-stats.vercel.app/api/top-langs/?username=Circe07&layout=compact&theme=github_dark&hide_border=true&langs_count=8&locale=es" alt="Lenguajes mas usados" height="165"/>
</p>

---

<details>
<summary><strong>English Version</strong></summary>

### About Me

Backend Engineer specialized in building robust, scalable, and secure systems. My approach combines solid software architecture with cybersecurity practices applied to every project I develop.

### Featured Projects

- **Smart Legal Architecture CRM** &mdash; AI-powered SaaS CRM (Gemini 3) for architectural law firms. TypeScript monorepo with local RAG and Zero-Hallucination protocol.
- **StartAndConnect** &mdash; REST API for sports communities. Collaborative project with 30+ endpoints, phase-gated testing, and OpenAPI documentation.
- **Financial Search API** &mdash; Offline-first financial search engine with SQLite and advanced filtering.

### Focus Areas

- Software Architecture: design patterns, Service Layer, Clean Architecture
- Security: OSINT, hardening, input validation, RBAC
- AI-Assisted Engineering: leveraging AI tools to accelerate development without sacrificing quality

</details>
