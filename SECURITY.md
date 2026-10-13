# Security considerations

- Uses `urllib.request` with certificate verification enabled. Do not bypass TLS validation. For trusted corporate CA use `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE`.
- Credentials are read from environment variables (`ABUSECH_AUTH_KEY`, `VT_API_KEY`), not committed or logged. Rotate credentials previously included in other scripts.
- Network requests are restricted to a fixed provider allowlist with redirect checks. It never visits reported malicious destinations and never uploads files.
- URL and IOC data are untrusted; Excel values are serialized as inline strings, CSV formula-injection prefixes are escaped, reports do not embed IOC links as active clickable relationships.
- External feed listings and IP-in-CIDR containment are not evidence of an organizational breach. Check your monitoring perimeter and indicator freshness before operational actions.
- This code has synthetic, offline regression tests. It is not independently security audited; vendor schemas, quotas, and terms can change.
