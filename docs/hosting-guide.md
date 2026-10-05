# Hosting Guide

## Render Free

- Service type: Web Service (Docker).
- Plan: Free, sleeps after 15 min idle.
- Deploy: push to `main`; `render.yaml` Blueprint auto-deploys.

## HuggingFace Spaces

- Space type: Docker SDK template.
- Free, no credit card, persistent.

## Local-first

```bash
cryptoh watch --source nginx:/var/log/nginx/access.log --model gemma-4
cryptoh serve --port 8000
```
