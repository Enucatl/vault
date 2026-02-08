# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is `vault_secrets` — a Puppet module (Ruby) that integrates HashiCorp Vault with Puppet for secret management, certificate issuance, and PKI operations. It provides Puppet functions, custom resource types/providers, a hiera backend, custom facts, and a Bolt plan for AppRole agent deployment.

## Development Commands

```bash
# Install dependencies
bundle install

# Run unit tests
bundle exec rake parallel_spec

# Run all validation (syntax, lint, style)
bundle exec rake validate lint check rubocop

# Run a single test file
bundle exec rspec spec/unit/provider/vault_cert/vault_cert_spec.rb

# Prepare test fixtures (pulled automatically by spec_helper, but can be done manually)
bundle exec rake spec_prep

# Clean test fixtures
bundle exec rake spec_clean
```

Puppet and Ruby versions can be set via environment variables: `PUPPET_GEM_VERSION`, `FACTER_GEM_VERSION`, `HIERA_GEM_VERSION`.

## Architecture

### Core Vault Client — `lib/puppet_x/vault_secrets/vaultsession.rb`

`VaultSession` is the central class that all functions and providers use to communicate with Vault. It handles:
- HTTP connection management with SSL/TLS (forces TLSv1.2)
- Two auth modes: Puppet certificate-based (`auth_path`) or pre-staged token (`token`/`token_file`)
- Certificate store construction from system bundles or custom CA paths
- K/V secrets engine v1 and v2 response parsing

### Puppet Functions — `lib/puppet/functions/`

| Function | Purpose |
|---|---|
| `vault_hash` | Returns all K/V pairs from a Vault path |
| `vault_key` | Returns a single key's value from a Vault path |
| `vault_cert` | Requests a certificate from Vault PKI engine (server-side) |
| `vault_hiera_hash` | Hiera `data_hash` backend — reads from Vault as a hiera data source |

All functions instantiate `VaultSession` internally. `vault_hiera_hash` supports both `uri` (single) and `uris` (array) options, and can authenticate via token file or Puppet certificates.

### Custom Types and Providers — `lib/puppet/type/` and `lib/puppet/provider/`

- **`vault_cert`** — Manages TLS certificates issued by Vault PKI directly to agents. Private keys never leave the agent. Tracks certificate metadata in `.json` sidecar files. Handles automatic renewal based on `renewal_threshold` days. Autorequires parent directory `File` resources and `User`/`Group` resources.
- **`vault_ssh_cert`** — Manages SSH host certificates signed by Vault's SSH secrets engine. Signs existing public keys on disk.

Both providers use `VaultSession` for Vault API communication during catalog apply.

### Custom Facts — `lib/facter/`

- `vault_cert` — Checks validity and days remaining for all managed certificates
- `vault_cert_dir` — Returns the OS-specific vault certificate directory path

### Manifests — `manifests/`

- `init.pp` — Main class, manages Vault-issued host certificates for the node
- `vault_cert.pp` — Ensures certificate directories exist, supports purging unmanaged certs
- `approle_agent.pp` — Defined type for deploying Vault agents with AppRole auth (systemd-based)

### Bolt Plan — `plans/approle_agent.pp`

Deploys a Vault agent with AppRole authentication to target nodes. Used to bootstrap token-based auth for hiera on Puppet servers without storing secrets in hiera.

### Hiera Data — `data/`

OS-specific configuration (certificate trust commands for RedHat vs Debian families) and default cert request parameters in `common.yaml`.

## Testing

Tests live under `spec/`. The module uses `puppetlabs_spec_helper` with rspec-puppet. Test fixtures (stdlib, systemd) are defined in `.fixtures.yml`. The `hashi_stack` fixture is commented out — some tests may need it re-enabled.

Key test files:
- `spec/unit/provider/vault_cert/vault_cert_spec.rb` — Most comprehensive, tests cert lifecycle
- `spec/unit/type/vault_cert_spec.rb` — Type validation and autorequire behavior
- `spec/unit/provider/vault_ssh_cert/` and `spec/unit/type/vault_ssh_cert_spec.rb` — SSH cert tests
- `spec/defines/approle_agent_spec.rb` — Defined type tests

## Key Patterns

- `VaultSession` is always instantiated with a hash of string keys (not symbols): `'uri'`, `'auth_path'`, `'token'`, `'ca_trust'`, `'timeout'`, `'version'`, `'secure'`, `'fail_hard'`
- Certificate metadata is persisted in JSON sidecar files alongside cert/key files for tracking renewal state
- The module supports both server-side (functions in catalog compilation) and agent-side (deferred functions, types/providers) Vault operations
- Puppet cert auth uses the agent's `hostcert` and `hostprivkey` from Puppet settings
