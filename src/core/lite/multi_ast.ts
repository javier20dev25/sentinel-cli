export interface MultiLangFinding {
  type: string;
  subcode: string;
  language: 'python' | 'go' | 'rust';
  file: string;
  line: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  riskScore: number;
  title: string;
  description: string;
  snippet: string;
  evidence?: string;
}

export interface MultiLangResult {
  findings: MultiLangFinding[];
  language: string;
  fileCount: number;
}

interface Rule {
  regex: RegExp;
  subcode: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  riskScore: number;
  title: string;
  description: string;
}

const PYTHON_RULES: Rule[] = [
  { regex: /\beval\s*\(|\bexec\s*\(/, subcode: 'PY-EVAL', severity: 'CRITICAL', riskScore: 80, title: 'Dynamic code execution', description: 'Python eval() or exec() detected — arbitrary code execution risk.' },
  { regex: /subprocess\.(?:call|Popen)\s*\(|os\.system\s*\(|os\.popen\s*\(/, subcode: 'PY-SUBPROCESS', severity: 'HIGH', riskScore: 60, title: 'Subprocess execution', description: 'Subprocess or OS command execution detected.' },
  { regex: /pickle\.loads?\s*\(/, subcode: 'PY-PICKLE', severity: 'HIGH', riskScore: 55, title: 'Unsafe deserialization', description: 'Python pickle deserialization detected — remote code execution risk.' },
  { regex: /requests\.get\s*\(|urllib\.request\.urlopen\s*\(/, subcode: 'PY-REQUEST', severity: 'MEDIUM', riskScore: 30, title: 'External request', description: 'Python external HTTP request detected.' },
  { regex: /(?:base64|b64decode).*(?:exec|eval)|(?:exec|eval).*(?:base64|b64decode)/i, subcode: 'PY-BASE64-EXEC', severity: 'CRITICAL', riskScore: 85, title: 'Obfuscated execution', description: 'Base64 decode combined with code execution — obfuscated payload.' },
  { regex: /import\s+from\s+['"][^'"]*['"]\s*\+/, subcode: 'PY-IMPORT-FROM', severity: 'MEDIUM', riskScore: 25, title: 'Dynamic import', description: 'String-built import detected — potential dependency confusion.' },
];

const GO_RULES: Rule[] = [
  { regex: /exec\.Command\s*\(/, subcode: 'GO-EXEC', severity: 'HIGH', riskScore: 60, title: 'Command execution', description: 'Go exec.Command() detected — arbitrary command execution.' },
  { regex: /os\.StartProcess/, subcode: 'GO-OS-EXEC', severity: 'HIGH', riskScore: 55, title: 'OS process execution', description: 'Go os.StartProcess detected — process creation.' },
  { regex: /net\.Dial\s*\(/, subcode: 'GO-NET', severity: 'MEDIUM', riskScore: 30, title: 'Network connection', description: 'Go net.Dial() detected — external network connection.' },
  { regex: /base64.*(?:exec|Command)|(?:exec|Command).*base64/i, subcode: 'GO-BASE64-DECODE', severity: 'CRITICAL', riskScore: 85, title: 'Obfuscated execution', description: 'Base64 decode combined with command execution — obfuscated payload.' },
  { regex: /import\s+["']unsafe["']/, subcode: 'GO-UNSAFE', severity: 'MEDIUM', riskScore: 35, title: 'Unsafe package import', description: 'Go unsafe package imported — type safety bypass.' },
];

const RUST_RULES: Rule[] = [
  { regex: /Command::new\s*\(/, subcode: 'RS-COMMAND', severity: 'HIGH', riskScore: 60, title: 'Command execution', description: 'Rust Command::new() detected — arbitrary command execution.' },
  { regex: /std::process::Command/, subcode: 'RS-PROCESS', severity: 'HIGH', riskScore: 55, title: 'Process execution', description: 'Rust std::process::Command detected — process execution capability.' },
  { regex: /TcpStream::connect\s*\(/, subcode: 'RS-NET', severity: 'MEDIUM', riskScore: 30, title: 'Network connection', description: 'Rust TcpStream::connect() detected — external network connection.' },
  { regex: /unsafe\s*\{/, subcode: 'RS-UNSAFE', severity: 'MEDIUM', riskScore: 40, title: 'Unsafe block', description: 'Rust unsafe block detected — memory safety bypass.' },
  { regex: /base64.*(?:Command|exec)|(?:Command|exec).*base64/i, subcode: 'RS-BASE64-EXEC', severity: 'CRITICAL', riskScore: 85, title: 'Obfuscated execution', description: 'Base64 decode combined with command execution — obfuscated payload.' },
];

function detectLanguage(file: string): 'python' | 'go' | 'rust' | null {
  if (file.endsWith('.py')) return 'python';
  if (file.endsWith('.go')) return 'go';
  if (file.endsWith('.rs')) return 'rust';
  return null;
}

export function scanMultiLang(file: string, content: string): MultiLangFinding[] {
  const lang = detectLanguage(file);
  if (!lang) return [];

  const findings: MultiLangFinding[] = [];
  const rules: Rule[] =
    lang === 'python' ? PYTHON_RULES :
    lang === 'go' ? GO_RULES :
    RUST_RULES;

  const lines = content.split('\n');
  lines.forEach((line, idx) => {
    const lineNumber = idx + 1;
    for (const rule of rules) {
      if (rule.regex.test(line)) {
        findings.push({
          type: rule.subcode,
          subcode: rule.subcode,
          language: lang,
          file,
          line: lineNumber,
          severity: rule.severity,
          riskScore: rule.riskScore,
          title: rule.title,
          description: rule.description,
          snippet: line.substring(0, 150).trim(),
        });
      }
    }
  });

  return findings;
}
