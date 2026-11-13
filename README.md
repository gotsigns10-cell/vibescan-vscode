# VibeScan for VS Code

Scan your AI-generated code for the **VibeScan Top 10** vulnerabilities directly in VS Code.

## Features

- **Scan Workspace** - Scan your entire project for security issues
- **Scan File** - Scan the current file instantly
- **Inline Diagnostics** - See issues highlighted in your code
- **Results Panel** - View all findings organized by severity
- **Scan on Save** - Automatically scan files when you save (optional)

## Installation

1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X)
3. Search for "VibeScan"
4. Click Install

Or install from command line:
```bash
code --install-extension universoul.vibescan
```

## Usage

### Scan Workspace
- Open Command Palette (Ctrl+Shift+P)
- Type "VibeScan: Scan Workspace"
- Wait for results

### Scan Current File
- Right-click in editor
- Select "VibeScan: Scan Current File"

### View Results
- Click the shield icon in the activity bar
- See findings organized by severity
- Click a finding to jump to the code

## Configuration

| Setting | Description | Default |
|---------|-------------|---------|
| `vibescan.apiKey` | API key for private repos | - |
| `vibescan.apiUrl` | VibeScan API endpoint | https://scan.digisigns.link |
| `vibescan.scanOnSave` | Auto-scan on file save | false |
| `vibescan.severityThreshold` | Minimum severity to show | medium |

## VibeScan Top 10

The scanner checks for:

1. **VS-001** Hardcoded Secrets
2. **VS-002** Missing Authorization/BOLA
3. **VS-003** AI Prompt Injection
4. **VS-004** Dependency Confusion
5. **VS-005** Exposed Debug Endpoints
6. **VS-006** Insecure Direct Object Reference
7. **VS-007** Mass Assignment
8. **VS-008** Broken Rate Limiting
9. **VS-009** Unsafe Deserialization
10. **VS-010** Missing Input Validation

## License

MIT - Universoul LLC
