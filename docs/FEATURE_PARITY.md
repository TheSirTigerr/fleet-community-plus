# Enterprise feature parity roadmap

This document tracks independently implemented equivalents for Fleet Premium capabilities.

## Core platform

- [ ] Fleets / multi-tenancy
- [ ] Advanced RBAC and role scoping
- [ ] Audit logging
- [ ] Fleet-level policies and queries
- [ ] Custom reporting / tables
- [ ] GitOps-managed configuration

## Identity and access

- [ ] SAML/OIDC SSO enhancements
- [ ] Just-in-time user provisioning
- [ ] SCIM provisioning
- [ ] IdP group mapping
- [ ] Conditional access integrations
- [ ] Account/password synchronization where supported by platform APIs

## Device enrollment and setup

- [ ] Zero-touch enrollment workflows
- [ ] Setup experience configuration
- [ ] Bootstrap package handling
- [ ] MDM migration workflows
- [ ] Host naming templates
- [ ] iOS/iPadOS account-driven enrollment
- [ ] Android fully managed enrollment

## MDM and security controls

- [ ] Configuration profiles at fleet/device scope
- [ ] Label/target-based profile assignment
- [ ] Disk encryption enforcement
- [ ] Recovery key escrow
- [ ] Recovery Lock management
- [ ] OS update enforcement
- [ ] Remote lock
- [ ] Remote wipe
- [ ] Certificate distribution and renewal

## Software management

- [ ] Software package deployment
- [ ] Self-service software catalog
- [ ] Setup-experience software
- [ ] Install/uninstall automation
- [ ] Munki integration
- [ ] Private software/update registry support

## Patching and remediation

- [ ] Patch policies
- [ ] Automated remediation
- [ ] Policy-triggered scripts
- [ ] Policy-triggered software installs
- [ ] Continuous policy remediation
- [ ] Maintenance windows

## Vulnerability management

- [ ] CVE enrichment
- [ ] CVSS data
- [ ] CISA KEV enrichment
- [ ] Vulnerability reporting by fleet/device
- [ ] Software-to-vulnerability correlation

## Agent management

- [ ] Agent version control
- [ ] Controlled fleetd rollout
- [ ] Script execution orchestration
- [ ] Reliable result collection/retry

## Implementation phases

1. Import and keep Fleet Community upstream buildable without `ee/`.
2. Add a separate `communityplus` server package and database migrations.
3. Implement fleets, RBAC, audit log, policy automation and software orchestration first.
4. Add MDM/security controls and zero-touch enrollment.
5. Add identity/conditional-access integrations.
6. Add patching, vulnerability enrichment and advanced lifecycle automation.
7. Add compatibility/integration tests against documented Fleet API behavior where useful.

## Current integration gate

- [x] Community+ capability, RBAC, audit and automation domain foundation
- [x] MySQL schema and persistence for audit events and automation rules
- [x] Scope-aware REST handler with API tests
- [x] Clean-room host-identity certificate types and HTTP message-signature verification
- [x] Clean-room DigiCert certificate enrollment and PKCS#12 packaging
- [x] Clean-room NDES, Smallstep and custom SCEP proxy foundation
- [x] Clean-room maintained-app manifest compatibility
- [x] Community+ edition identity and fleetctl compatibility boundary
- [ ] Replace remaining production imports from the removed upstream `ee/` tree
- [x] Mount Community+ routes behind Fleet user authentication
- [ ] Pass a full Fleet server build before advertising any feature as production-ready

A checkbox is only marked complete when the feature is production-usable, has migrations/API coverage, and has automated tests.
