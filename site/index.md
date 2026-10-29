---
title: Nux Deck
description: A free, self-hosted operations console for Linux hosts and containers.
weight: 1
---

Nux Deck is a self-hosted operations console for DevOps, SRE and platform engineers. Version 0.1 covers:

- Linux hosts and Docker or Podman containers, with inventory, tags and owners.
- Resource metrics and live container and journal logs.
- Uptime checks (HTTP, TCP, DNS, TLS, ping) that run on the server or on an agent.
- Alert rules, silences, maintenance windows and notifications (SMTP, Slack, Teams, Discord, Telegram, webhooks).
- Public status pages.
- Local accounts with TOTP, single sign-on (OIDC), role-based access and an audit log.

Nux Deck ships as two binaries:

- `nuxd` is the server. It serves the web UI and REST API on port 8443 and accepts agents on port 8444.
- `nux` is the host agent, the command-line client, and the `sockguard` proxy.

Agents connect outbound to the server over mutual TLS, so hosts do not need inbound ports.

## Start here

1. [Install the server](install.md).
2. [Enrol your first host](agents.md).
3. [Set up checks and alerts](checks.md) and [alerts](alerts.md).

## Reference

- [Configuration](configuration.md): every `nuxd` setting and environment variable.
- [CLI](cli.md): every `nux` command and exit code.
- [REST API](rest-api.md): authentication, CSRF, pagination and streams.
- [Error codes](reference/error-codes.md).

Licences: the server (`nuxd`, `internal/server`) is AGPL-3.0. The agent, CLI, protocol and `pkg/` are Apache-2.0.
