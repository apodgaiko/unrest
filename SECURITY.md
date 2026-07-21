# Security Policy

## Reporting a vulnerability

Do not report security vulnerabilities through public GitHub issues. Use
[GitHub private vulnerability reporting](https://github.com/apodgaiko/unrest/security/advisories/new)
so the report can be investigated before disclosure.

## Scope

Unrest runs coding agents that can execute commands and modify files in the
workspace selected for a mission. Reports of particular interest include:

- escapes from configured workspace or declared artifact roots;
- prompt injection that expands authority beyond the mission;
- unsafe ACP subprocess input, output, or permission handling;
- exposure of secrets through generated configuration or durable state;
- terminal-review access outside its declared read-only surface.

Include the Unrest version, operating system, host/provider, reproduction steps,
and the smallest safe diagnostic output needed to demonstrate the issue. Remove
credentials, private prompts, and unrelated mission data.

## Supported versions

Security fixes are applied to the latest release on `main`.
