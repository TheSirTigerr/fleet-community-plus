# Clean-room implementation boundary

This project may use Fleet's MIT-licensed code and public interfaces as a base, but it must not copy or adapt restricted Enterprise Edition backend implementation from upstream `ee/`.

Allowed inputs for replacement features include:

- Fleet's public documentation and published API behavior
- Open standards and vendor documentation for Apple, Microsoft, Google, osquery, Munki, SCEP/ACME, SCIM, SAML/OIDC, etc.
- Independently written tests describing desired externally observable behavior
- MIT-licensed Fleet code and client-side assets where the upstream license permits reuse

Do not:

- remove or bypass Fleet EE license checks to run Fleet EE code without a subscription
- copy restricted EE source into this repository
- port EE functions line-by-line from restricted source
- disguise copied EE implementation behind different names

When implementing a premium-equivalent feature, document the public behavior being targeted and write tests against that behavior before adding the implementation where practical.
