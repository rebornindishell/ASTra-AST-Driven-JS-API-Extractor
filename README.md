# ASTra-AST-Driven-JS-API-Extractor
ASTra is an AST-driven Burp Suite extension and reverse-engineering framework that parses minified client-side JavaScript bundles to extract API routes, POST/PUT payload shapes, BOLA targets, client-side secrets, and feature flags.

Modern Single-Page Applications (React, Next.js, Angular, Vue, SvelteKit, Blazor) hide their server-side attack surface inside minified client bundles and lazy-loaded code chunks. Traditional web crawlers and simple regex link finders miss dynamic routes, generate excessive noise (W3C namespaces, CDN scripts), and fail to infer request payload structures.

ASTra bridges front-end JavaScript analysis directly to server-side vulnerability testing. Operating via an Abstract Syntax Tree (AST) parsing engine and Burp Suite Montoya extension, ASTra passively intercepts script traffic to automatically discover:

API Routes & Verbs: REST endpoints, Angular $stateProvider routes, React/Vue routes, GraphQL operations, and WebSocket channels.
Request Body Reconstruction: Reconstructs JSON payload structures (POST/PUT) from AST object literals.
BOLA / IDOR Attack Matrix: Automatically flags dynamic resource paths ({userId}) and enables 1-click "Send BOLA Pair to Repeater" for instant cross-tenant authorization testing.
Secret & Flag Scanner: Discovers hardcoded API keys, AWS credentials, JWT storage sinks (localStorage), and client-side role guards (isAdmin()).
Zero-Noise Engine: Filters out W3C XML namespaces, CDN script tags, static assets, and code keywords.
OpenAPI 3.0 & Postman Export: Exports the complete discovered attack surface into Swagger JSON or Postman Collections with one click.

AST-driven engine means the extension doesn't just "grep" for words—it reverse-engineers the structural code logic to accurately map API routes, HTTP verbs, payload shapes, and authorization parameters straight from minified bundles.
