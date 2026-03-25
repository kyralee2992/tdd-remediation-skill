# Scanner Architecture

`lib/scanner.js` is the core engine behind `npx @lhi/tdd-audit --scan` and the auto-audit skill. It is a pure Node.js module with no runtime dependencies — only `fs` and `path`.

---

## Entry points

| Export | Purpose |
|---|---|
| `quickScan(projectDir)` | Walk all source files and return a findings array |
| `scanPromptFiles(projectDir)` | Walk all `.md` prompt/skill files and check for prompt-specific patterns |
| `scanAppConfig(projectDir)` | Check `app.json` / `app.config.*` for embedded secrets |
| `scanAndroidManifest(projectDir)` | Check `AndroidManifest.xml` for `android:debuggable="true"` |
| `printFindings(findings, exempted)` | Format and print a findings report to stdout |
| `detectFramework(dir)` | Detect the test framework (`jest`, `vitest`, `mocha`, `pytest`, `go`, `flutter`) |
| `detectAppFramework(dir)` | Detect the UI framework (`nextjs`, `expo`, `react-native`, `react`, `flutter`) |
| `detectTestBaseDir(dir, framework)` | Locate the test root (`__tests__`, `tests`, `test`, `spec`) |

---

## How `quickScan` works

```
projectDir
  └─ walkFiles()          — yields .js/.ts/.jsx/.tsx/.mjs/.py/.go/.dart files
       └─ for each file:
            1. Read file content (read-first, check length after — no TOCTOU)
            2. Skip if content.length > 512 KB
            3. Skip if file contains null bytes (binary guard)
            4. For each line × each VULN_PATTERN:
                 – If pattern matches, push finding with severity / name / file / line / snippet
                 – inTestFile: true if path is under a test directory
                 – likelyFalsePositive: true if inTestFile && pattern.skipInTests
  └─ scanAppConfig()      — checks app.json / app.config.* for secret patterns
  └─ scanAndroidManifest() — checks android:debuggable
  └─ scanPromptFiles()    — walks .md files in prompt directories
```

All four result sets are merged into one array and returned to the caller.

---

## File walking

### `walkFiles(dir)`

Yields scannable source files (`SCAN_EXTENSIONS`). Skips:

- **`SKIP_DIRS`**: `node_modules`, `.git`, `dist`, `build`, `.next`, `out`, `__pycache__`, `venv`, `.venv`, `vendor`, `.expo`, `.dart_tool`, `.pub-cache`
- **Symlinks** — never followed, preventing escape from the project root on shared/M-series filesystems

### `walkMdFiles(dir)`

Same skip rules, yields `.md` files only. Used by `scanPromptFiles`.

---

## Scanned extensions

`.js` `.ts` `.jsx` `.tsx` `.mjs` `.py` `.go` `.dart`

YAML, JSON, XML, and shell files are not scanned by the code scanner. CI workflow files (`.yml`) are scanned separately when explicitly passed to the ASI08/ASI09 grep patterns during an agent-driven audit.

---

## Test file detection

`isTestFile(filePath, projectDir)` returns `true` for any file that matches:

| Pattern | Example |
|---|---|
| `*.test.js` / `*.spec.ts` | `auth.test.ts` |
| `*_test.dart` | `login_test.dart` |
| Path contains `__tests__/` or `tests/` | `__tests__/unit/scanner.test.js` |
| Path contains `spec/` | `spec/api/users_spec.rb` |
| Filename starts with `test_` | `test_helpers.js` |

Findings in test files are always reported (they may contain real vulnerabilities), but:
- They carry `inTestFile: true` in the finding object
- If the matched pattern has `skipInTests: true`, `likelyFalsePositive` is set to `true` and the finding is separated into a secondary "verify manually" section of the report

---

## Prompt file detection

`isPromptFile(filePath, projectDir)` returns `true` for:

| Condition | Example |
|---|---|
| Filename is in `PROMPT_FILE_NAMES` | `CLAUDE.md`, `SKILL.md`, `.cursorrules`, `.clinerules` |
| First path segment is in `PROMPT_DIRS` | `prompts/`, `skills/`, `.claude/`, `workflows/` |

### `audit_status: safe` exemption

If a prompt file's YAML frontmatter contains `audit_status: safe`, it is skipped entirely. The relative path is collected into an `exempted` array and displayed at the bottom of the `printFindings` report so you can verify exemptions are intentional.

```markdown
---
name: my-prompt
audit_status: safe
---
```

This mechanism allows prompt authors to document intentional examples of vulnerable patterns (e.g., showing what `csurf` looks like before migration) without generating false positives on every scan.

### Backtick suppression

Matches inside a properly closed backtick code span on the same line are suppressed. This prevents table rows like:

```markdown
| `"command": "npx"` in MCP config | HIGH | ...
```

from triggering the `Unpinned npx MCP Server` pattern.

The rule: suppress when there is an **odd** number of backticks before the match AND at least one closing backtick after it on the same line.

---

## Finding object schema

```javascript
{
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
  name: string,           // pattern display name, e.g. "SQL Injection"
  file: string,           // relative path from projectDir
  line: number,           // 1-indexed line number
  snippet: string,        // first 80 chars of the matched line (trimmed)
  inTestFile: boolean,
  likelyFalsePositive: boolean,
}
```

---

## Adding a new pattern

All vulnerability patterns live in the `VULN_PATTERNS` array in `lib/scanner.js`. Each entry is:

```javascript
{
  name: 'Display Name',    // shown in the report
  severity: 'HIGH',        // CRITICAL | HIGH | MEDIUM | LOW
  pattern: /regex/i,       // matched against each line of each file
  skipInTests: true,       // optional — mark likelyFalsePositive when matched in test files
}
```

Prompt-specific patterns live in `PROMPT_PATTERNS`:

```javascript
{
  name: 'Display Name',
  severity: 'HIGH',
  pattern: /regex/,
  skipCommentLine: true,   // optional — suppress matches on lines starting with // or #
}
```

After adding a pattern, add a corresponding unit test in `__tests__/unit/scanner.test.js` with both a true-positive and a false-positive case.
