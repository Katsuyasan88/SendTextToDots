# Security policy

SendTextToDots is experimental. No release line is currently promised ongoing security maintenance, and no response or fix deadline is guaranteed. Include the exact commit or version in any report.

## Reporting a vulnerability

**Reporting channel status:** the private reporting channel has not yet been enabled and verified for public use. Adding this file does not enable GitHub private vulnerability reporting. The repository owner must enable and check that channel as part of publication.

When private reporting is enabled, open the repository's [Security advisories](https://github.com/Katsuyasan88/SentTextToDots/security/advisories) and choose **Report a vulnerability**. GitHub describes the process in [Privately reporting a security vulnerability](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately).

If that button is unavailable, ask the maintainers for a private security contact in an issue containing **only the contact request**. Do not include vulnerability details, proof-of-concept code, tokens, keys, real user data, callback URLs or message text in public issues, discussions or pull requests. No alternative e-mail address is currently designated here.

In the private report, include:

- The affected commit or version and component, plus the runtime and operating system when relevant.
- The expected and observed behavior, impact and required access.
- Minimal reproduction steps using synthetic configuration and data. Remove credentials and personal information from attachments and logs.

Test only systems you own or have permission to test. Do not use another person's account, receiving Dots or Cloud resources to reproduce a problem.

## Technical security documentation

Read the [security and data-handling design](docs/SECURITY_EN.md) ([日本語](docs/SECURITY.md)) and [known limitations](docs/LIMITATIONS_EN.md) ([日本語](docs/LIMITATIONS.md)). These describe the service's protections and verification limits; a successful test or repository check is not a guarantee that a deployment is secure.
