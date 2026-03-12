// Switch Configuration Parser & Security Analyzer
class SwitchParser {
  constructor(fileContent, vendor = 'cisco', model = 'all') {
    this.content = fileContent;
    this.lines = fileContent.split(/\r?\n/);
    this.vendor = vendor.toLowerCase();
    this.model = model.toLowerCase();
    this.results = [];
  }

  // Basic block detection for common switch vendors
  extractBlock(cliPath) {
    if (!cliPath) return this.lines;

    // Cisco/HPE style: Sections often start with a command and end with '!'
    // This is a simplified version. For nested blocks, we'd need more logic.
    let inBlock = false;
    const blockLines = [];
    
    // Exact match or starts with
    const startRegex = new RegExp(`^${cliPath}(\\s+|$)`, 'i');

    for (let line of this.lines) {
      const t = line.trim();
      if (startRegex.test(t)) {
        inBlock = true;
        blockLines.push(t);
        continue;
      }
      if (inBlock) {
        if (t === '!' || t === 'exit' || t === 'quit' || (t.length > 0 && !line.startsWith(' '))) {
          // End of block (simplified: if next line doesn't start with space, it's a new section in some formats)
          // For Cisco, '!' is the safest.
          if (t === '!') {
            inBlock = false;
            break; 
          }
          // If it's another top-level command, block ended
          if (!line.startsWith(' ') && t.length > 0) {
            inBlock = false;
            break;
          }
        }
        blockLines.push(t);
      }
    }
    return blockLines.length > 0 ? blockLines : null;
  }

  evaluate(rule, configLines) {
    const { eval_path, eval_type, eval_expected, default_val } = rule;
    
    // Find the specific line that matches the leaf of eval_path or the cli_path
    // If eval_path is "management.telnet", we look for "telnet" inside the "management" block
    const leaf = eval_path.split('.').pop();
    const leafRegex = new RegExp(`^(${leaf}|set\\s+${leaf}|${leaf}\\s+)(\\s+(.+))?`, 'i');
    
    let foundLine = null;
    let actualValue = null;

    for (const line of configLines) {
      const t = line.trim();
      const m = t.match(leafRegex);
      if (m) {
        foundLine = t;
        // m[3] is the value part
        actualValue = m[3] ? m[3].trim().replace(/["']/g, '') : '';
        break;
      }
    }

    if (foundLine === null) {
      // If not found, use default value if exists
      actualValue = default_val;
    }

    let pass = false;
    const expected = String(eval_expected);
    const actual = String(actualValue || '');

    switch (eval_type) {
      case 'equal':
        pass = actual.toLowerCase() === expected.toLowerCase();
        break;
      case 'contains':
        pass = actual.toLowerCase().includes(expected.toLowerCase());
        break;
      case 'not_contains':
        pass = !actual.toLowerCase().includes(expected.toLowerCase());
        break;
      case 'max_num':
        pass = parseFloat(actual) <= parseFloat(expected);
        break;
      case 'min_num':
        pass = parseFloat(actual) >= parseFloat(expected);
        break;
      case 'regex':
        try {
          const re = new RegExp(expected, 'i');
          pass = re.test(actual) || re.test(foundLine || '');
        } catch (e) { pass = false; }
        break;
      case 'exists':
        pass = foundLine !== null;
        break;
      default:
        pass = false;
    }

    return {
      pass,
      actualValue: actualValue || (foundLine ? 'found' : 'not found'),
      foundLine
    };
  }

  analyze(rules) {
    const findings = [];
    let passedCount = 0;
    let failedCount = 0;

    for (const rule of rules) {
      // If rule is for a specific vendor/model and doesn't match ours, skip
      // (Though the SQL usually filters this, we double check)
      if (rule.switch_vendor && rule.switch_vendor !== 'cisco' && rule.switch_vendor !== this.vendor) continue;

      const blockLines = this.extractBlock(rule.cli_path) || this.lines;
      const { pass, actualValue, foundLine } = this.evaluate(rule, blockLines);

      if (pass) passedCount++; else failedCount++;

      findings.push({
        rule_id: rule.id,
        name: rule.name,
        category: rule.category,
        severity: rule.severity,
        passed: pass,
        check_logic: rule.check_logic,
        remediation: rule.remediation,
        details: rule.recommendation_details,
        actual_value: actualValue,
        expected_value: rule.eval_expected,
        found_line: foundLine,
        cli_path: rule.cli_path
      });
    }

    return {
      findings,
      summary: {
        total_rules: rules.length,
        passed: passedCount,
        failed: failedCount,
        score: rules.length > 0 ? Math.round((passedCount / rules.length) * 100) : 100
      }
    };
  }

  getDeviceInfo() {
    let hostname = 'Switch-Device';
    let version = 'Unknown';
    let model = this.model || 'Generic Switch';

    for (const line of this.lines) {
      const t = line.trim();
      if (t.toLowerCase().startsWith('hostname ')) {
        hostname = t.split(/\s+/)[1].replace(/"/g, '');
      }
      if (t.toLowerCase().includes('version ') && version === 'Unknown') {
        const m = t.match(/version\s+([\d\.]+)/i);
        if (m) version = m[1];
      }
    }

    return {
      device_name: hostname,
      model: model,
      version: version,
      vendor: this.vendor
    };
  }
}

module.exports = SwitchParser;
