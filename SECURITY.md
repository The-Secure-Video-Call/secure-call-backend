# Security Policy

## Reporting a vulnerability

Please report vulnerabilities **privately** using GitHub private vulnerability reporting:
go to the repository's **Security** tab, then **Report a vulnerability**.

Do not open a public issue or pull request for a suspected vulnerability, and do not include
real room links (the part after `#` is a secret) in any report.

We aim to acknowledge reports within a few days and will coordinate disclosure with you.

## Fixing vulnerable dependencies

How quickly a known vulnerability in one of our dependencies (a Python package, a GitHub Action
or a container image) is fixed, counted from when it is published or reported to us:

| Severity | Fixed within |
| --- | --- |
| Critical or high | 7 days |
| Moderate | 30 days |
| Low | the next weekly Dependabot round |

If no fixed version exists yet, we record that in the issue, apply a workaround if there is one,
and update as soon as a fix is released. How we find out:

- **Dependabot security alerts and security updates.** Security updates are proposed at once;
  only routine version updates wait the 7-day cooldown in `.github/dependabot.yml`.
- **`pip-audit --strict` in CI,** which fails every PR while a locked package has a known
  vulnerability.

The web app's policy is the same (`SECURITY.md` in secure-call).
