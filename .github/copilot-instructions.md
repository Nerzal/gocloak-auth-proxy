# Project instructions

- Use Go 1.26 or newer. Keep direct dependencies limited to gocloak and
  golang-jwt; prefer the standard library. Transitive SDK dependencies are
  unavoidable.
- Treat authentication, authorization, proxy headers, and network input as security-sensitive.
- Never log credentials, bearer tokens, or secrets. Validate untrusted input and fail closed.
- Follow the Integration Operation Segregation Principle (IOSP): each function
  is either an operation (logic/I/O, no internal domain calls) or integration
  (orchestration only, no logic/transforms).
- Keep request-path allocations and unnecessary network calls low; add and run
  benchmarks for performance-sensitive changes.
- Use `make check` for lint, vulnerability scanning, race tests, benchmarks, and build.
- Preserve the depguard allowlist and CI's govulncheck and gosec gates.
- Keep actions pinned to verified full commit SHAs and check dependency advisories.
- Run the production container as nonroot using the distroless static image.
