# Optional Key-Provider Packages

Binding-specific loading for the shared
[key-source contract](sdk-design/12-configuration-loading.md#operational-key-source-selection).
These are design requirements, not implementation coverage. Factories belong to
SDK configuration composition, not core verification.

| Binding | Loading mechanism | Missing-provider remedy |
|---|---|---|
| Go | Provider package registers its factory in `init()`; application imports it, commonly with a blank import, as with `database/sql`. Configuration selects linked factories; no runtime plugins. | Add dependency/import and rebuild. Installing a module alone does not link it; switching among linked providers needs no code change. |
| TypeScript | Fixed name-to-loader mapping with lazy `import()` of known optional packages. Packaging/bundlers preserve selected optional imports. | Install the package and include it in the build; a bundled-out provider is unavailable. |
| Python | Fixed name-to-module mapping using `importlib` for the selected optional package. | Install the named package. |

Loading the base SDK must not load every cloud dependency. Test selected-only
loading and missing packages/factories, alongside
[configuration checks](sdk-design/12-configuration-loading.md#validation-scenarios)
for injection precedence, validation, and no fallback. Cloud checks must also cover
stable existing-key references and supported algorithms; loading a package does not prove
key availability or authorization.
