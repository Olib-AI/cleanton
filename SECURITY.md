# Security policy

## Reporting a vulnerability

Email **security@olib.ai** with:

- A short description of the issue
- Steps to reproduce
- Your platform (`uname -a` and the Cleanton version)
- Whether the issue affects the app, the command-line tool, or both

We acknowledge reports within 2 business days and aim to ship a fix within 14
days for confirmed high-severity issues.

Please do not file a public GitHub issue for security reports.

## Scope

In scope:

- Any path where Cleanton removes or modifies a file the user did not select
- Privilege or sandbox issues in the signed binaries
- Tampering with the update or download path

Out of scope:

- Data loss from items you reviewed and confirmed for removal
- Behavior of third-party tools whose caches Cleanton cleans

## Credit

We do not run a paid bounty program, but we will credit researchers (with
permission) in the release notes for the version that contains the fix.
