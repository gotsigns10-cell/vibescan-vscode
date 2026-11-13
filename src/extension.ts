import * as vscode from 'vscode';
import * as https from 'https';
import * as path from 'path';

const VIBESCAN_TOP10 = [
  { id: 'VS-001', name: 'Hardcoded Secrets', severity: 'critical' },
  { id: 'VS-002', name: 'Missing Authorization/BOLA', severity: 'critical' },
  { id: 'VS-003', name: 'AI Prompt Injection', severity: 'high' },
  { id: 'VS-004', name: 'Dependency Confusion', severity: 'high' },
  { id: 'VS-005', name: 'Exposed Debug Endpoints', severity: 'high' },
  { id: 'VS-006', name: 'Insecure Direct Object Reference', severity: 'high' },
  { id: 'VS-007', name: 'Mass Assignment', severity: 'medium' },
  { id: 'VS-008', name: 'Broken Rate Limiting', severity: 'medium' },
  { id: 'VS-009', name: 'Unsafe Deserialization', severity: 'high' },
  { id: 'VS-010', name: 'Missing Input Validation', severity: 'medium' }
];

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;
let resultsProvider: ResultsTreeProvider;

export function activate(context: vscode.ExtensionContext) {
  console.log('VibeScan extension activated');

  // Create diagnostics collection for inline errors
  diagnosticCollection = vscode.languages.createDiagnosticCollection('vibescan');
  context.subscriptions.push(diagnosticCollection);

  // Create status bar item
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBarItem.command = 'vibescan.showResults';
  statusBarItem.text = '$(shield) VibeScan';
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // Create results tree provider
  resultsProvider = new ResultsTreeProvider();
  vscode.window.registerTreeDataProvider('vibescanResults', resultsProvider);

  // Register Top 10 tree provider
  const top10Provider = new Top10TreeProvider();
  vscode.window.registerTreeDataProvider('vibescanTop10', top10Provider);

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand('vibescan.scanWorkspace', scanWorkspace),
    vscode.commands.registerCommand('vibescan.scanFile', scanCurrentFile),
    vscode.commands.registerCommand('vibescan.showResults', showResults)
  );

  // Scan on save if enabled
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((document) => {
      const config = vscode.workspace.getConfiguration('vibescan');
      if (config.get('scanOnSave')) {
        scanFile(document.uri);
      }
    })
  );
}

async function scanWorkspace() {
  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
  if (!workspaceFolder) {
    vscode.window.showErrorMessage('No workspace folder open');
    return;
  }

  statusBarItem.text = '$(sync~spin) Scanning...';

  try {
    const config = vscode.workspace.getConfiguration('vibescan');
    const apiUrl = config.get<string>('apiUrl') || 'https://scan.digisigns.link';
    const apiKey = config.get<string>('apiKey') || '';

    // Get git remote URL if available
    let repoUrl = '';
    try {
      const gitExtension = vscode.extensions.getExtension('vscode.git')?.exports;
      const api = gitExtension?.getAPI(1);
      const repo = api?.repositories[0];
      repoUrl = repo?.state?.remotes[0]?.fetchUrl || '';
    } catch {
      // Git not available
    }

    // If no git remote, scan local files
    if (!repoUrl) {
      await scanLocalFiles(workspaceFolder.uri);
      return;
    }

    // Start remote scan
    const result = await apiCall(apiUrl, 'POST', '/vibescan/scan', {
      url: repoUrl,
      apiKey
    });

    if (!result.scanId) {
      throw new Error('Failed to start scan');
    }

    // Poll for completion
    let report;
    for (let i = 0; i < 60; i++) {
      await sleep(5000);
      const status = await apiCall(apiUrl, 'GET', `/vibescan/status/${result.scanId}`);

      if (status.status === 'completed') {
        report = await apiCall(apiUrl, 'GET', `/vibescan/report/${result.scanId}`);
        break;
      } else if (status.status === 'failed') {
        throw new Error(status.error || 'Scan failed');
      }

      statusBarItem.text = `$(sync~spin) Scanning... ${status.progress || 0}%`;
    }

    if (!report) {
      throw new Error('Scan timed out');
    }

    // Update UI with results
    updateResults(report);

  } catch (error: any) {
    vscode.window.showErrorMessage(`VibeScan error: ${error.message}`);
    statusBarItem.text = '$(shield) VibeScan';
  }
}

async function scanCurrentFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showErrorMessage('No file open');
    return;
  }

  await scanFile(editor.document.uri);
}

async function scanFile(uri: vscode.Uri) {
  statusBarItem.text = '$(sync~spin) Scanning...';

  try {
    const document = await vscode.workspace.openTextDocument(uri);
    const code = document.getText();
    const filename = path.basename(uri.fsPath);

    const config = vscode.workspace.getConfiguration('vibescan');
    const apiUrl = config.get<string>('apiUrl') || 'https://scan.digisigns.link';
    const apiKey = config.get<string>('apiKey') || '';

    const result = await apiCall(apiUrl, 'POST', '/vibescan/scan', {
      code,
      filename,
      apiKey
    });

    if (!result.scanId) {
      throw new Error('Failed to start scan');
    }

    // Poll for completion
    let report;
    for (let i = 0; i < 30; i++) {
      await sleep(2000);
      const status = await apiCall(apiUrl, 'GET', `/vibescan/status/${result.scanId}`);

      if (status.status === 'completed') {
        report = await apiCall(apiUrl, 'GET', `/vibescan/report/${result.scanId}`);
        break;
      } else if (status.status === 'failed') {
        throw new Error(status.error || 'Scan failed');
      }
    }

    if (!report) {
      throw new Error('Scan timed out');
    }

    // Show inline diagnostics
    showDiagnostics(uri, report);
    updateResults(report);

  } catch (error: any) {
    vscode.window.showErrorMessage(`VibeScan error: ${error.message}`);
    statusBarItem.text = '$(shield) VibeScan';
  }
}

async function scanLocalFiles(folderUri: vscode.Uri) {
  // Scan common vulnerability patterns locally
  const findings: any[] = [];
  const files = await vscode.workspace.findFiles('**/*.{js,ts,jsx,tsx,py,java,go,rb}', '**/node_modules/**');

  for (const file of files.slice(0, 50)) { // Limit to 50 files
    const document = await vscode.workspace.openTextDocument(file);
    const content = document.getText();
    const localFindings = scanContentLocally(content, file.fsPath);
    findings.push(...localFindings);
  }

  // Create a local report
  const report = {
    vibeScore: Math.max(0, 100 - findings.length * 5),
    grade: getGrade(100 - findings.length * 5),
    summary: {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length
    },
    findings
  };

  updateResults(report);
}

function scanContentLocally(content: string, filepath: string): any[] {
  const findings: any[] = [];
  const lines = content.split('\n');

  lines.forEach((line, index) => {
    // VS-001: Hardcoded secrets
    if (/(?:api[_-]?key|secret|password|token)\s*[:=]\s*['"][^'"]{8,}['"]/i.test(line)) {
      findings.push({
        id: 'VS-001',
        name: 'Hardcoded Secret',
        severity: 'critical',
        file: filepath,
        line: index + 1,
        message: 'Potential hardcoded secret detected'
      });
    }

    // VS-005: Debug endpoints
    if (/(?:\/debug|\/test|console\.log|debugger)/i.test(line)) {
      findings.push({
        id: 'VS-005',
        name: 'Debug Code',
        severity: 'medium',
        file: filepath,
        line: index + 1,
        message: 'Debug code or endpoint detected'
      });
    }

    // VS-010: Missing input validation (simplified)
    if (/req\.(?:body|query|params)\.[a-z]+/i.test(line) && !/(?:validate|sanitize|escape)/i.test(line)) {
      findings.push({
        id: 'VS-010',
        name: 'Missing Input Validation',
        severity: 'medium',
        file: filepath,
        line: index + 1,
        message: 'User input used without apparent validation'
      });
    }
  });

  return findings;
}

function showDiagnostics(uri: vscode.Uri, report: any) {
  const diagnostics: vscode.Diagnostic[] = [];
  const config = vscode.workspace.getConfiguration('vibescan');
  const threshold = config.get<string>('severityThreshold') || 'medium';
  const severityOrder = ['low', 'medium', 'high', 'critical'];
  const thresholdIndex = severityOrder.indexOf(threshold);

  for (const finding of report.findings || []) {
    const severityIndex = severityOrder.indexOf(finding.severity);
    if (severityIndex < thresholdIndex) continue;

    const line = (finding.line || 1) - 1;
    const range = new vscode.Range(line, 0, line, 1000);

    const severity = finding.severity === 'critical' || finding.severity === 'high'
      ? vscode.DiagnosticSeverity.Error
      : finding.severity === 'medium'
        ? vscode.DiagnosticSeverity.Warning
        : vscode.DiagnosticSeverity.Information;

    const diagnostic = new vscode.Diagnostic(
      range,
      `[${finding.id}] ${finding.message}`,
      severity
    );
    diagnostic.source = 'VibeScan';
    diagnostic.code = finding.id;
    diagnostics.push(diagnostic);
  }

  diagnosticCollection.set(uri, diagnostics);
}

function updateResults(report: any) {
  // Update status bar
  const emoji = report.grade === 'A' || report.grade === 'B' ? '✓' :
                report.grade === 'C' ? '!' : '✗';
  statusBarItem.text = `$(shield) ${emoji} ${report.vibeScore}/100`;

  // Update tree view
  resultsProvider.update(report);

  // Show notification
  const totalIssues = report.summary.critical + report.summary.high +
                      report.summary.medium + report.summary.low;

  if (totalIssues === 0) {
    vscode.window.showInformationMessage(`VibeScan: Score ${report.vibeScore}/100 - No issues found!`);
  } else {
    vscode.window.showWarningMessage(
      `VibeScan: Score ${report.vibeScore}/100 - Found ${totalIssues} issues ` +
      `(${report.summary.critical} critical, ${report.summary.high} high)`
    );
  }
}

function showResults() {
  vscode.commands.executeCommand('vibescanResults.focus');
}

function getGrade(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

function apiCall(baseUrl: string, method: string, path: string, body?: any): Promise<any> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, baseUrl);
    const options = {
      method,
      hostname: url.hostname,
      path: url.pathname,
      headers: { 'Content-Type': 'application/json' }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          reject(new Error(`Invalid response: ${data}`));
        }
      });
    });

    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Tree data providers
class ResultsTreeProvider implements vscode.TreeDataProvider<ResultItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<ResultItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
  private report: any = null;

  update(report: any) {
    this.report = report;
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: ResultItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: ResultItem): ResultItem[] {
    if (!this.report) {
      return [new ResultItem('No scan results', '', vscode.TreeItemCollapsibleState.None)];
    }

    if (!element) {
      // Root level - show summary
      return [
        new ResultItem(`Score: ${this.report.vibeScore}/100 (${this.report.grade})`, 'score', vscode.TreeItemCollapsibleState.None),
        new ResultItem(`Critical: ${this.report.summary.critical}`, 'critical', vscode.TreeItemCollapsibleState.Collapsed),
        new ResultItem(`High: ${this.report.summary.high}`, 'high', vscode.TreeItemCollapsibleState.Collapsed),
        new ResultItem(`Medium: ${this.report.summary.medium}`, 'medium', vscode.TreeItemCollapsibleState.Collapsed),
        new ResultItem(`Low: ${this.report.summary.low}`, 'low', vscode.TreeItemCollapsibleState.Collapsed)
      ];
    }

    // Show findings for severity
    const findings = (this.report.findings || []).filter((f: any) => f.severity === element.contextValue);
    return findings.map((f: any) => {
      const item = new ResultItem(`${f.id}: ${f.message}`, f.id, vscode.TreeItemCollapsibleState.None);
      if (f.file && f.line) {
        item.command = {
          command: 'vscode.open',
          arguments: [vscode.Uri.file(f.file), { selection: new vscode.Range(f.line - 1, 0, f.line - 1, 0) }],
          title: 'Go to finding'
        };
      }
      return item;
    });
  }
}

class Top10TreeProvider implements vscode.TreeDataProvider<ResultItem> {
  getTreeItem(element: ResultItem): vscode.TreeItem {
    return element;
  }

  getChildren(): ResultItem[] {
    return VIBESCAN_TOP10.map(v => {
      const icon = v.severity === 'critical' ? '🔴' : v.severity === 'high' ? '🟠' : '🟡';
      return new ResultItem(`${icon} ${v.id}: ${v.name}`, v.id, vscode.TreeItemCollapsibleState.None);
    });
  }
}

class ResultItem extends vscode.TreeItem {
  constructor(
    label: string,
    public readonly contextValue: string,
    collapsibleState: vscode.TreeItemCollapsibleState
  ) {
    super(label, collapsibleState);
  }
}

export function deactivate() {
  diagnosticCollection?.dispose();
  statusBarItem?.dispose();
}
