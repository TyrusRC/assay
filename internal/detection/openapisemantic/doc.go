// Package openapisemantic detects semantic vulnerabilities in OpenAPI-described
// endpoints — bugs the schema itself documents away but the server still
// processes. Unlike pure spec-validation tools, these probes assume the
// declared schema is the contract the client expects, then verify the server
// actually enforces it.
//
// The five probes implemented here target classes of mismatch that bypass
// downstream guards (ORM hydration, role checks, auth-state mutation):
//
//  1. Type coercion bypass — schema says `integer`, server accepts the value
//     as a quoted string. Informational on its own (Low), but a launchpad
//     for #2.
//  2. Type-coerced injection — string-typed payload (e.g. `"1 OR 1=1"`)
//     sneaks through an `integer` field and is reflected/processed by the
//     server. High severity when the response discriminably changes.
//  3. Discriminator confusion — `oneOf`/`anyOf` with a `discriminator` says
//     type=admin allows admin-only fields, type=user does not. We send
//     type=user with the admin-only payload; if accepted, Critical.
//  4. Nullable default leak — `nullable: true` on a sensitive field
//     (`password`) lets a registration accept `null`, and login then works
//     with an empty / null credential. Critical.
//  5. additionalProperties bypass — schema sets `additionalProperties: false`
//     but the server still persists / echoes unknown fields. High,
//     effectively mass-assignment through the published contract.
//
// OWASP mappings applied across findings:
//   - API6:2023 (Mass Assignment) for #3, #5
//   - API3:2023 (Broken Object Property Level) for #2, #3
//   - A04:2025 (Insecure Design) for all findings
//   - CWE-20 (Improper Input Validation) for #1, #2
//   - CWE-915 (Improperly Controlled Modification of Dynamically-Determined
//     Object Attributes) for #3, #5
//
// The package owns a minimal in-tree OpenAPI 3.x parser (see parse.go) to
// avoid pulling external schema dependencies for what is ultimately a
// detector, not a validator.
package openapisemantic
