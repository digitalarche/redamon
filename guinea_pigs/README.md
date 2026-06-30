# Guinea Pigs

Deliberately vulnerable, self-contained Docker targets for **end-to-end validation**
of RedAmon recon/scan modules against realistic, real-world behaviour (not mocks).

Each subdirectory is one module's validation harness with its own `docker-compose.yml`
and a README mapping every endpoint to the exact pipeline step it exercises.

| Harness | Validates | Run |
|---|---|---|
| [`web-cache-poisoning/`](web-cache-poisoning/) | `recon/cache_scan` (WCP module): cache oracle, cache-buster isolation, reflected + differential confirmation, framework packs, scoring, negative controls | `cd web-cache-poisoning && docker compose up -d --build` |

> ⚠️ These targets are intentionally vulnerable. Run them only on a local/trusted
> Docker host and never expose their ports to an untrusted network.
