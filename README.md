# @lhi/tdd-audit

Anti-Gravity Skill for TDD Remediation. This package securely patches code vulnerabilities by utilizing a Test-Driven Remediation (Red-Green-Refactor) protocol.

## Installation

You can install this skill globally so that it is available to the Anti-Gravity agent across all of your projects:

```bash
npx @lhi/tdd-audit
```

Or run it directly if you have cloned the repository:

```bash
node index.js
```

### Local Installation

If you prefer to install the skill and its workflow strictly to your current workspace instead of globally, use the `--local` flag:

```bash
npx @lhi/tdd-audit --local
# or
node index.js --local
```

This will create an `.agents` folder in your current directory. 

*Note: Regardless of whether you install globally or locally, the boilerplate security tests will always be scaffolded into your current project's directory at `__tests__/security`.*

## Usage

Once installed, you can trigger the autonomous audit in your Anti-Gravity chat using the provided slash command:

```text
/tdd-audit
```

This will instruct the agent to:
1. Explore the designated structure to find any vulnerabilities.
2. Exploit the vulnerability with a failing test (Red).
3. Patch the flaw to make the test pass (Green).
4. Ensure no regressions occur (Refactor).

## License

MIT
