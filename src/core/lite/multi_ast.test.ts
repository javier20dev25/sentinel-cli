import { describe, it, expect } from 'vitest';
import { scanMultiLang, MultiLangFinding } from './multi_ast';

describe('scanMultiLang', () => {
  describe('Python detection', () => {
    it('detects PY-EVAL eval() call', () => {
      const content = 'result = eval(user_input)\n';
      const findings = scanMultiLang('test.py', content);
      expect(findings.some(f => f.subcode === 'PY-EVAL')).toBe(true);
      const evalFinding = findings.find(f => f.subcode === 'PY-EVAL')!;
      expect(evalFinding.severity).toBe('CRITICAL');
      expect(evalFinding.riskScore).toBe(80);
      expect(evalFinding.language).toBe('python');
      expect(evalFinding.line).toBe(1);
    });

    it('detects PY-SUBPROCESS subprocess.call()', () => {
      const content = 'subprocess.call(["ls", "-la"])\n';
      const findings = scanMultiLang('test.py', content);
      expect(findings.some(f => f.subcode === 'PY-SUBPROCESS')).toBe(true);
      const spFinding = findings.find(f => f.subcode === 'PY-SUBPROCESS')!;
      expect(spFinding.severity).toBe('HIGH');
      expect(spFinding.riskScore).toBe(60);
    });

    it('detects PY-PICKLE pickle.loads()', () => {
      const content = 'data = pickle.loads(serialized)\n';
      const findings = scanMultiLang('test.py', content);
      expect(findings.some(f => f.subcode === 'PY-PICKLE')).toBe(true);
    });

    it('detects PY-REQUEST requests.get()', () => {
      const content = 'response = requests.get("https://example.com")\n';
      const findings = scanMultiLang('test.py', content);
      expect(findings.some(f => f.subcode === 'PY-REQUEST')).toBe(true);
    });

    it('detects PY-BASE64-EXEC obfuscated pattern', () => {
      const content = 'exec(base64.b64decode(payload))\n';
      const findings = scanMultiLang('test.py', content);
      expect(findings.some(f => f.subcode === 'PY-BASE64-EXEC')).toBe(true);
    });

    it('detects PY-IMPORT-FROM string building', () => {
      const content = 'import from "lib" + version + ".so"\n';
      const findings = scanMultiLang('test.py', content);
      expect(findings.some(f => f.subcode === 'PY-IMPORT-FROM')).toBe(true);
    });

    it('returns empty for safe Python code', () => {
      const content = 'import sys\nprint("hello")\nx = 1 + 2\n';
      const findings = scanMultiLang('test.py', content);
      expect(findings).toHaveLength(0);
    });
  });

  describe('Go detection', () => {
    it('detects GO-EXEC exec.Command()', () => {
      const content = 'cmd := exec.Command("ls", "-la")\n';
      const findings = scanMultiLang('test.go', content);
      expect(findings.some(f => f.subcode === 'GO-EXEC')).toBe(true);
      const goFinding = findings.find(f => f.subcode === 'GO-EXEC')!;
      expect(goFinding.severity).toBe('HIGH');
      expect(goFinding.riskScore).toBe(60);
      expect(goFinding.language).toBe('go');
    });

    it('detects GO-OS-EXEC os.StartProcess', () => {
      const content = 'attr := &os.ProcAttr{}; pid, err := os.StartProcess("ls", []string{"-la"}, attr)\n';
      const findings = scanMultiLang('test.go', content);
      expect(findings.some(f => f.subcode === 'GO-OS-EXEC')).toBe(true);
    });

    it('detects GO-NET net.Dial()', () => {
      const content = 'conn, err := net.Dial("tcp", "example.com:80")\n';
      const findings = scanMultiLang('test.go', content);
      expect(findings.some(f => f.subcode === 'GO-NET')).toBe(true);
    });

    it('detects GO-UNSAFE import unsafe', () => {
      const content = 'import "unsafe"\n';
      const findings = scanMultiLang('test.go', content);
      expect(findings.some(f => f.subcode === 'GO-UNSAFE')).toBe(true);
    });

    it('detects GO-BASE64-DECODE obfuscated pattern', () => {
      const content = 'cmd := exec.Command(string(base64.StdEncoding.DecodeString(encoded)))\n';
      const findings = scanMultiLang('test.go', content);
      expect(findings.some(f => f.subcode === 'GO-BASE64-DECODE')).toBe(true);
    });

    it('returns empty for safe Go code', () => {
      const content = 'package main\nimport "fmt"\nfunc main() { fmt.Println("hello") }\n';
      const findings = scanMultiLang('test.go', content);
      expect(findings).toHaveLength(0);
    });
  });

  describe('Rust detection', () => {
    it('detects RS-COMMAND Command::new()', () => {
      const content = 'let output = Command::new("ls").arg("-la").output()?;\n';
      const findings = scanMultiLang('test.rs', content);
      expect(findings.some(f => f.subcode === 'RS-COMMAND')).toBe(true);
      const rsFinding = findings.find(f => f.subcode === 'RS-COMMAND')!;
      expect(rsFinding.severity).toBe('HIGH');
      expect(rsFinding.riskScore).toBe(60);
      expect(rsFinding.language).toBe('rust');
    });

    it('detects RS-PROCESS std::process::Command', () => {
      const content = 'use std::process::Command;\n';
      const findings = scanMultiLang('test.rs', content);
      expect(findings.some(f => f.subcode === 'RS-PROCESS')).toBe(true);
    });

    it('detects RS-NET TcpStream::connect()', () => {
      const content = 'let stream = TcpStream::connect("example.com:80")?;\n';
      const findings = scanMultiLang('test.rs', content);
      expect(findings.some(f => f.subcode === 'RS-NET')).toBe(true);
    });

    it('detects RS-UNSAFE unsafe block', () => {
      const content = 'unsafe { let x = *ptr; }\n';
      const findings = scanMultiLang('test.rs', content);
      expect(findings.some(f => f.subcode === 'RS-UNSAFE')).toBe(true);
      const unsafeFinding = findings.find(f => f.subcode === 'RS-UNSAFE')!;
      expect(unsafeFinding.severity).toBe('MEDIUM');
      expect(unsafeFinding.riskScore).toBe(40);
    });

    it('detects RS-BASE64-EXEC obfuscated pattern', () => {
      const content = 'Command::new(String::from_utf8(base64::decode(encoded)))\n';
      const findings = scanMultiLang('test.rs', content);
      expect(findings.some(f => f.subcode === 'RS-BASE64-EXEC')).toBe(true);
    });
  });

  describe('Language detection', () => {
    it('detects .py extension as python', () => {
      const content = 'eval("test")\n';
      const findings = scanMultiLang('foo.py', content);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].language).toBe('python');
    });

    it('detects .go extension as go', () => {
      const content = 'exec.Command("ls")\n';
      const findings = scanMultiLang('foo.go', content);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].language).toBe('go');
    });

    it('detects .rs extension as rust', () => {
      const content = 'Command::new("ls")\n';
      const findings = scanMultiLang('foo.rs', content);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].language).toBe('rust');
    });

    it('returns empty for unsupported extension', () => {
      const findings = scanMultiLang('foo.js', 'eval("test")');
      expect(findings).toHaveLength(0);
    });

    it('returns empty for files with no extension', () => {
      const findings = scanMultiLang('Makefile', 'eval("test")');
      expect(findings).toHaveLength(0);
    });
  });

  describe('Finding fields', () => {
    it('includes file, line, snippet in finding', () => {
      const content = 'result = eval(user_input)\n';
      const findings = scanMultiLang('/path/to/test.py', content);
      expect(findings[0].file).toBe('/path/to/test.py');
      expect(findings[0].line).toBe(1);
      expect(findings[0].snippet).toContain('eval');
    });

    it('reports correct line numbers', () => {
      const content = 'import sys\nresult = eval(user_input)\nprint("done")\n';
      const findings = scanMultiLang('test.py', content);
      const evalF = findings.find(f => f.subcode === 'PY-EVAL');
      expect(evalF).toBeDefined();
      expect(evalF!.line).toBe(2);
    });
  });
});
