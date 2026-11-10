# Contributing

Thanks for considering a contribution to `com.touchque:touchque-java` and its
Spring Boot starter, `com.touchque:touchque-spring-boot-starter`.

## Setup

You need JDK 17 or later, Maven and Node.js (the tests start the fake API).

```bash
mvn -B -DskipTests install
```

## Running tests

```bash
mvn -B verify
```

This runs both modules' tests. Some suites run **contract tests** against
`testing/fake-touchque-api.mjs` — a small, dependency-free Node server that
verifies the SDK's HMAC request signatures exactly like the real API does.
These need `node` on `PATH`; without it they fail.

## Making a change

1. If it touches the wire protocol or the step-up contract, update the
   fixtures in `fixtures/` and the fake API in `testing/` first.
2. Add tests. A behavior change without a test won't be merged.
3. Update `CHANGELOG.md` (Keep a Changelog format) under `## [Unreleased]`.
4. Keep code, comments, docs and error messages in English.
5. Keep the build free of warnings: the compiler runs with `-Xlint:all` and
   `-Werror`.
6. Don't add a dependency to `touchque-java` (Jackson is its only one).
   Spring belongs in the starter, and only as an optional dependency.

## Pull requests

- Describe what changed and why, not just what. If it's a breaking change,
  say so explicitly and explain the migration.
- CI must pass.

## Reporting a security issue

Please don't open a public issue — see [SECURITY.md](./SECURITY.md).
