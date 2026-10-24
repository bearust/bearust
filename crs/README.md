# OWASP Core Rule Set 4.7.0 (bundled)

Request-phase rules (`REQUEST-9*.conf`), their data files, and
`crs-setup.conf` from <https://github.com/coreruleset/coreruleset> tag
`v4.7.0`, unmodified. Licensed under the Apache License 2.0 (see `LICENSE`).

Bearust embeds these files and evaluates them with its SecLang engine
(`src/seclang`) when OWASP CRS is enabled in the WAF settings. Response-phase
rules are not included because Bearust inspects requests only.

To check engine compatibility against the CRS regression suite, see
`tests/crs_regression.rs`.
