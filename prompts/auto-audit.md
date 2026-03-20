# TDD Remediation: Auto-Audit Mode

When invoked in Auto-Audit mode, you must proactively secure the user's entire repository without waiting for explicit files to be provided.

## Phase 0: Discovery
1. **Explore the Architecture**: Use your `list_dir` and `view_file` tools to understand the project structure. Look for directories named `controllers`, `routes`, `api`, `services`, or `models`.
2. **Search for Anti-Patterns**: Use your `grep_search` tool to look for common vulnerabilities:
   - *SQL Injection*: Search for raw query strings, e.g., `` `SELECT * FROM users WHERE id = ${req.body.id}` ``
   - *IDOR*: Search for direct lookups without tenant or user ID checks.
   - *XSS*: Search for raw HTML rendering `innerHTML`, `dangerouslySetInnerHTML`, or similar sinks.
3. **Present Findings**: Provide a list of identified vulnerabilities to the user before proceeding.

## Phase 1 to 3: Remediation Engine
For each vulnerability approved for fixing, you must rigorously apply the RED-GREEN-REFACTOR protocol:
1. **[RED](./red-phase.md)**: Write the exploit test in `__tests__/security/` and run it to prove the vulnerability exists.
2. **[GREEN](./green-phase.md)**: Write the patch and run the tests to prove the exploit is blocked.
3. **[REFACTOR](./refactor-phase.md)**: Ensure standard functionality is maintained and existing tests pass.

Do not move to the next vulnerability until the current one is fully remediated and tested.
