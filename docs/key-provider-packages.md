# Optional Key-Provider Packages

Binding-specific loading guidance for the shared
[key-source configuration](sdk-design/12-configuration-loading.md#operational-key-source-selection).
This defines required behavior, not current SDK implementation coverage.

All bindings accept the same provider names and selection rules. Resolve provider
availability and validate configuration before account discovery, key generation,
or registration mutations. Missing provider support returns `ArgumentError` with
an installation/build remedy, never a fallback to local files. Explicit caller-
injected providers take precedence over configuration-selected factories.

## Go

Use the `database/sql` driver pattern: the optional provider package registers
its factory during `init()`, and the application imports that package, commonly
with a blank import. The registration/factory resolver belongs to SDK setup
composition, not core verification. Configuration selects among linked factories.

Installing a module without importing it does not add support to a binary. A
missing factory error must say to add the provider import/dependency and rebuild.
Switching among already linked providers requires no application-code change;
adding another provider requires a build. Do not require Go runtime plugins.

## TypeScript

Use a fixed provider-name-to-loader mapping with lazy `import()` of known optional
provider packages. Package/build metadata must preserve these optional external
imports; loading the ordinary SDK must not load every cloud SDK. A missing selected
package produces an error naming the package to install. A bundler's omitted
provider is likewise unavailable, not permission to choose another provider.

## Python

Use a fixed provider-name-to-module mapping and `importlib` to load the selected
optional package. Loading the base SDK must not import every cloud dependency.
A missing selected package produces an error naming the package to install.

## Configuration and Key Authority

Configuration chooses a factory and contains non-secret service settings plus
an existing key reference or stable generation locator/algorithm. Cloud access
uses workload credentials or other supported credential references outside shared
configuration. Private keys are generated and used inside the selected provider.

Changing configuration does not import a local key into a cloud service. An
existing identity moves to a newly generated cloud key only through explicit
KEY_ROTATION authorized by the previous key. Recovery retains both provider
references until acceptance/publication is verified and activation is durable.

## Binding Checks

Each binding must exercise missing selected packages/factories, injected-provider
precedence, malformed provider settings, no implicit local fallback, and loading
only the selected provider. Cloud tests must also establish stable key discovery
and the provider's supported signing algorithms; merely resolving a package does
not establish key availability or authorization.
