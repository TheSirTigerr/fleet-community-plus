# Community+ server modules

`server/communityplus` contains independently implemented functionality for Fleet Community+.

The code in this directory must not copy Fleet Enterprise Edition (`ee/`) backend implementation. It may integrate with the MIT-licensed Fleet Community types and services that are present in the repository and may implement behavior described by public documentation and APIs.

## Foundation modules

- `features`: feature registry and dependency graph. Community+ capabilities are enabled by implementation state, not by a Fleet Enterprise license key.
- `rbac`: custom-role permissions and fleet-scoped bindings designed to complement Fleet's existing OPA/Rego authorizer.
- `audit`: vendor-neutral audit event and storage sink contract.
- `automation`: validated event-to-action rules for policy remediation, software installation, script execution, and webhooks.

These are foundation contracts. A capability is not considered production-complete until its persistence, API/service integration, authorization, migrations, and end-to-end tests are implemented.
