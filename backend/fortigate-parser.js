// FortiGate Configuration Parser & Security Analyzer - Professional Version
class FortiGateParser {
  constructor(fileContent) {
    this.content = fileContent;
    this.lines = fileContent.split('\n');
    this.parsedItems = [];
    this.systemConfigs = {};
  }

  parse() {
    this.parseDeviceInfo();
    this.parseSystemConfigs();
    this.parseFirewallPolicies();
    this.parseInterfaces();
    this.parseVDOM();
    this.parseIPsec();
    this.parseAddresses();
    this.parseDHCPServers();
    return this.parsedItems;
  }

  parseAddresses() {
    let inBlock = false;
    let currentAddr = null;
    for (let line of this.lines) {
      const t = line.trim();
      if (t === 'config firewall address') { inBlock = true; continue; }
      if (inBlock) {
        if (t === 'end') { inBlock = false; continue; }
        const m = t.match(/^edit\s+"?([^"\s]+)"?/i);
        if (m) {
          currentAddr = { name: m[1], type: 'ipmask', subnet: '' };
          this.addItem('firewall_address', m[1], 'address', 'defined', currentAddr);
        } else if (currentAddr && t.startsWith('set ')) {
          const sm = t.match(/^set\s+(\S+)\s+(.+)/i);
          if (sm) {
            const key = sm[1];
            const val = sm[2].replace(/"/g, '');
            currentAddr[key] = val;
            const item = this.parsedItems[this.parsedItems.length - 1];
            if (item && item.item_type === 'firewall_address') item.raw_data = JSON.stringify(currentAddr);
          }
        }
      }
    }
  }

  parseDHCPServers() {
    let inBlock = false;
    let inRangeBlock = false;
    let currentDhcp = null;
    let currentRange = null;
    for (let line of this.lines) {
      const t = line.trim();
      if (t === 'config system dhcp server') { inBlock = true; continue; }
      if (inBlock) {
        if (t === 'end' && !inRangeBlock) { inBlock = false; continue; }
        if (t === 'config ip-range') { inRangeBlock = true; continue; }
        if (t === 'end' && inRangeBlock) { inRangeBlock = false; currentRange = null; continue; }

        const m = t.match(/^edit\s+["']?(\d+)["']?/i);
        if (m && !inRangeBlock) {
          currentDhcp = { id: m[1], interface: '', start_ip: '', end_ip: '' };
          this.addItem('dhcp_server', m[1], 'server', 'defined', currentDhcp);
        } else if (m && inRangeBlock) {
          currentRange = {};
        } else if (currentDhcp && t.startsWith('set ')) {
          const sm = t.match(/^set\s+(\S+)\s+(.+)/i);
          if (sm) {
            const key = sm[1];
            const val = sm[2].replace(/["']/g, '');
            if (inRangeBlock && currentRange) {
              if (key === 'start-ip') currentDhcp.start_ip = val;
              if (key === 'end-ip') currentDhcp.end_ip = val;
            } else {
              currentDhcp[key] = val;
            }
            const lastItem = this.parsedItems[this.parsedItems.length - 1];
            if (lastItem && lastItem.item_type === 'dhcp_server') lastItem.raw_data = JSON.stringify(currentDhcp);
          }
        }
      }
    }
  }

  ipToLong(ip) {
    if (!ip || typeof ip !== 'string') return 0;
    const parts = ip.split('.');
    if (parts.length !== 4) return 0;
    return ((((((+parts[0]) << 8) | (+parts[1])) << 8) | (+parts[2])) << 8) | (+parts[3]) >>> 0;
  }

  analyzeIPs() {
    const addresses = this.parsedItems.filter(i => i.item_type === 'firewall_address').map(i => JSON.parse(i.raw_data));
    const dhcpServers = this.parsedItems.filter(i => i.item_type === 'dhcp_server').map(i => JSON.parse(i.raw_data));
    const policies = this.parsedItems.filter(i => i.item_type === 'firewall_policy').map(i => JSON.parse(i.raw_data));

    const usedAddresses = new Set();
    policies.forEach(p => {
      const src = Array.isArray(p.config?.srcaddr) ? p.config.srcaddr : [p.config?.srcaddr];
      const dst = Array.isArray(p.config?.dstaddr) ? p.config.dstaddr : [p.config?.dstaddr];
      [...src, ...dst].forEach(a => { if (a) usedAddresses.add(a); });
    });

    const ranges = addresses.filter(a => a.type === 'iprange');
    
    const ipList = addresses.map(addr => {
      const isUsed = usedAddresses.has(addr.name);
      let type = addr.type === 'iprange' ? 'Range' : 'Statik';
      let status = 'Boşta';
      let rangeName = '';
      let isInRange = false;

      if (type === 'Statik' && addr.subnet) {
        const ipVal = this.ipToLong(addr.subnet.split('/')[0]);
        ranges.forEach(r => {
          if (r.name === addr.name) return;
          const start = this.ipToLong(r['start-ip']);
          const end = this.ipToLong(r['end-ip']);
          if (ipVal >= start && ipVal <= end) { isInRange = true; rangeName = r.name; }
        });
        dhcpServers.forEach(d => {
          if (d.start_ip && d.end_ip) {
            const start = this.ipToLong(d.start_ip);
            const end = this.ipToLong(d.end_ip);
            if (ipVal >= start && ipVal <= end) { isInRange = true; rangeName = `DHCP (${d.interface})`; }
          }
        });
      }

      if (isUsed) status = 'Kullanılıyor';
      else if (isInRange || type === 'Range') status = 'Şüpheli';

      return {
        name: addr.name, ip: addr.subnet || (addr['start-ip'] ? `${addr['start-ip']}-${addr['end-ip']}` : 'N/A'),
        type: type, status: status, is_used: isUsed, range_name: rangeName
      };
    });

    dhcpServers.forEach(dhcp => {
      if (dhcp.start_ip && dhcp.end_ip) {
        ipList.push({
          name: `DHCP Havuzu (${dhcp.interface})`,
          ip: `${dhcp.start_ip}-${dhcp.end_ip}`,
          type: 'DHCP', status: 'Kullanılıyor', is_used: true, interface: dhcp.interface
        });
      }
    });

    const metadataRanges = [
      ...ranges.map(r => ({ name: r.name, start: r['start-ip'], end: r['end-ip'], type: 'Range' })),
      ...dhcpServers.filter(d => d.start_ip && d.end_ip).map(d => ({ 
        name: d.interface, start: d.start_ip, end: d.end_ip, type: 'DHCP'
      }))
    ];

    return {
      total: ipList.length, used: ipList.filter(i => i.is_used).length,
      unused: ipList.filter(i => i.status !== 'Kullanılıyor').length,
      list: ipList, ranges: metadataRanges
    };
  }

  getSummary() {
    const summary = { device_name: 'Unknown', model: 'FortiGate', version: 'v7.2.4', total_vdom: 0, total_interface: 0, total_rules: 0, total_ipsec: 0 };
    const vdomNames = new Set(); const interfaceNames = new Set(); const ipsecNames = new Set();
    this.parsedItems.forEach(item => {
      if (item.item_type === 'device_info') {
        if (item.item_name === 'hostname') summary.device_name = item.config_value;
        if (item.item_name === 'model') summary.model = item.config_value;
        if (item.item_name === 'version') summary.version = item.config_value;
      }
      if (item.item_type === 'vdom') vdomNames.add(item.item_name);
      if (item.item_type === 'interface') interfaceNames.add(item.item_name);
      if (item.item_type === 'firewall_policy') summary.total_rules++;
      if (item.item_type === 'ipsec_phase1') ipsecNames.add(item.item_name);
    });
    summary.total_vdom = vdomNames.size || 1; summary.total_interface = interfaceNames.size; summary.total_ipsec = ipsecNames.size;
    return summary;
  }

  parseSystemConfigs() {
    let currentBlock = null;
    const blockMap = {
      'config system global': 'system_global', 'config user password-policy': 'password_policy',
      'config log syslogd setting': 'syslog_setting', 'config system ntp': 'ntp_setting',
      'config system settings': 'system_settings', 'config system dns': 'system_dns',
      'config system ha': 'system_ha', 'config vpn ssl settings': 'vpn_ssl_settings',
      'config system fortiguard': 'system_fortiguard', 'config vpn ipsec phase1-interface': 'vpn_ipsec_p1',
      'config vpn ipsec phase2-interface': 'vpn_ipsec_p2', 'config system admin': 'system_admin',
      'config system snmp sysinfo': 'system_snmp', 'config system snmp user': 'snmp_user',
      'config log disk setting': 'log_disk', 'config log fortianalyzer setting': 'log_fortianalyzer',
      'config log memory setting': 'log_memory', 'config log setting': 'log_setting',
      'config router bgp': 'router_bgp', 'config router ospf': 'router_ospf',
      'config firewall ssl setting': 'firewall_ssl_setting', 'config system console': 'system_console'
    };
    for (let line of this.lines) {
      const t = line.trim();
      if (blockMap[t]) currentBlock = blockMap[t];
      else if (t === 'end') currentBlock = null;
      if (currentBlock && t.startsWith('set ')) {
        const m = t.match(/^set\s+(\S+)\s+(.+)/i);
        if (m) {
          const key = m[1]; const val = m[2].replace(/"/g, '').trim();
          if (!this.systemConfigs[currentBlock]) this.systemConfigs[currentBlock] = {};
          if (this.systemConfigs[currentBlock][key] === undefined) this.systemConfigs[currentBlock][key] = val;
          else if (Array.isArray(this.systemConfigs[currentBlock][key])) {
            if (!this.systemConfigs[currentBlock][key].includes(val)) this.systemConfigs[currentBlock][key].push(val);
          } else if (this.systemConfigs[currentBlock][key] !== val) this.systemConfigs[currentBlock][key] = [this.systemConfigs[currentBlock][key], val];
        }
      }
    }
  }

  getPolicyServiceMatch(config = {}) {
    const serviceType = String(config['internet-service'] || '').toLowerCase() === 'enable' ? 'internet-service' : 'service';
    if (serviceType === 'internet-service') {
      const internetServiceKeys = ['internet-service-name', 'internet-service-id', 'internet-service-custom'];
      const values = internetServiceKeys.flatMap((key) => {
        const rawValue = config[key]; if (!rawValue) return [];
        return Array.isArray(rawValue) ? rawValue : [rawValue];
      });
      return { type: 'Internet Service', values: values.length > 0 ? values : ['Enabled'] };
    }
    const rawService = config.service;
    return { type: 'Firewall Service', values: Array.isArray(rawService) ? rawService : [rawService || 'any'] };
  }

  analyzePolicies(kbData = null) {
    const policies = this.parsedItems.filter(i => i.item_type === 'firewall_policy').map(p => JSON.parse(p.raw_data));
    const interfaces = this.parsedItems.filter(i => i.item_type === 'interface' && i.raw_data).map(i => JSON.parse(i.raw_data));
    const security_findings = []; const profile_findings = []; const shadow_findings = []; const manual_review_controls = [];
    const scores = { stig: { total: 0, passed: 0 }, cis: { total: 0, passed: 0 }, bp: { total: 0, passed: 0 } };
    const compliance_findings = [];
    const prefixAliases = { system_interface: 'interface', log_disk_setting: 'log_disk', log_syslogd: 'syslog_setting' };
    const isMissingValue = (value) => value === undefined || value === null || value === '' || (Array.isArray(value) && value.length === 0);
    const asArray = (value) => Array.isArray(value) ? value : (isMissingValue(value) ? [] : String(value).split(/\s+/).filter(Boolean));
    const formatActualValue = (value) => Array.isArray(value) ? value.join(', ') : (value ?? 'Belirtilmemiş');
    const evaluateRuleValue = (rule, actualVal, existsOverride = null) => {
      switch (rule.eval_type) {
        case 'max_num': return parseInt(actualVal, 10) > rule.eval_expected;
        case 'min_num': return parseInt(actualVal, 10) < rule.eval_expected;
        case 'equal': return Array.isArray(actualVal) ? !actualVal.includes(rule.eval_expected) : actualVal !== rule.eval_expected;
        case 'not_equal': return Array.isArray(actualVal) ? actualVal.includes(rule.eval_expected) : actualVal === rule.eval_expected;
        case 'in_array': return Array.isArray(actualVal) ? !actualVal.some((item) => rule.eval_expected.includes(item)) : !rule.eval_expected.includes(actualVal);
        case 'not_in_array': return Array.isArray(actualVal) ? actualVal.some((item) => rule.eval_expected.includes(item)) : rule.eval_expected.includes(actualVal);
        case 'not_contains': { const values = asArray(actualVal); return values.some((item) => String(item).toLowerCase().includes(String(rule.eval_expected).toLowerCase())); }
        case 'exists': return !(existsOverride ?? !isMissingValue(actualVal));
        default: return false;
      }
    };
    const evaluateCollectionRule = (rule, collection, valueResolver, labelResolver) => {
      const violations = [];
      collection.forEach((item) => {
        const actualVal = valueResolver(item);
        if (evaluateRuleValue(rule, actualVal, !isMissingValue(actualVal))) violations.push(`${labelResolver(item)}: ${formatActualValue(actualVal)}`);
      });
      return violations;
    };
    if (kbData) {
      kbData.forEach(rule => {
        const pathParts = rule.eval_path.split('.'); const rawPrefix = pathParts[0]; const prefix = prefixAliases[rawPrefix] || rawPrefix; const key = pathParts[1];
        const scoreCategory = rule.category === 'STIG' ? 'stig' : (rule.category === 'CIS' ? 'cis' : (rule.category === 'BP' ? 'bp' : null));
        if (rule.validation_status === 'needs_review') { manual_review_controls.push(rule); return; }
        let isViolated = false; let valToUse = rule.default_val;
        if (scoreCategory) scores[scoreCategory].total++;
        if (prefix === 'firewall_policy') {
          const violations = evaluateCollectionRule(rule, policies, (policy) => policy.config ? policy.config[key] : undefined, (policy) => `Policy ${policy.id}`);
          isViolated = violations.length > 0; if (isViolated) valToUse = violations.join(' | ');
        } else if (prefix === 'interface') {
          const violations = evaluateCollectionRule(rule, interfaces, (iface) => iface.config ? iface.config[key] : undefined, (iface) => `Interface ${iface.name}`);
          isViolated = violations.length > 0; if (isViolated) valToUse = violations.join(' | ');
        } else {
          const block = this.systemConfigs[prefix] || {}; const actualVal = block[key]; valToUse = actualVal !== undefined ? actualVal : rule.default_val;
          isViolated = evaluateRuleValue(rule, valToUse, !isMissingValue(actualVal));
        }
        if (isViolated) {
          let fullRemediation = rule.remediation;
          if (rule.cli_path) {
            if (prefix === 'firewall_policy') fullRemediation = `config firewall policy\n    edit <ID>\n        ${rule.remediation}\n    next\nend`;
            else if (prefix === 'interface') fullRemediation = `config system interface\n    edit <NAME>\n        ${rule.remediation}\n    next\nend`;
            else fullRemediation = `config ${rule.cli_path}\n    ${rule.remediation}\nend`;
          }
          compliance_findings.push({ ...rule, actual_value: valToUse || 'Belirtilmemiş', remediation: fullRemediation });
        } else if (scoreCategory) scores[scoreCategory].passed++;
      });
    }
    const calcScore = (cat) => scores[cat].total > 0 ? Math.round((scores[cat].passed / scores[cat].total) * 100) : 100;
    const vdomGroups = {}; policies.forEach(p => { if (!vdomGroups[p.vdom]) vdomGroups[p.vdom] = []; vdomGroups[p.vdom].push(p); });
    Object.keys(vdomGroups).forEach(vdom => {
      const vdomPolicies = vdomGroups[vdom];
      for (let i = 0; i < vdomPolicies.length; i++) {
        const current = vdomPolicies[i]; const cConfig = current.config || {};
        if (!['accept', 'deny'].includes((cConfig.action || '').toLowerCase())) continue;
        for (let j = 0; j < i; j++) {
          const previous = vdomPolicies[j]; const pConfig = previous.config || {};
          if (this.isShadowed(pConfig, cConfig)) {
            const formatData = (cfg) => {
              const serviceMatch = this.getPolicyServiceMatch(cfg);
              return {
                srcaddr: Array.isArray(cfg.srcaddr) ? cfg.srcaddr : [cfg.srcaddr || 'any'],
                dstaddr: Array.isArray(cfg.dstaddr) ? cfg.dstaddr : [cfg.dstaddr || 'any'],
                service: serviceMatch.values, service_type: serviceMatch.type, srcintf: cfg.srcintf || 'any', dstintf: cfg.dstintf || 'any'
              };
            };
            shadow_findings.push({
              category: 'shadow', policy_id: current.id, vdom: current.vdom, name: cConfig.name || `Policy #${current.id}`, shadowed_by: previous.id,
              shadow_name: pConfig.name || `Policy #${previous.id}`, details: `Bu kural, ID: ${previous.id} tarafından tamamen kapsanıyor.`,
              shadowed_data: formatData(cConfig), shadowing_data: formatData(pConfig)
            });
            break;
          }
        }
      }
    });
    policies.forEach(policy => {
      const securityRisks = []; const profileRisks = []; const config = policy.config || {};
      const srcAddr = Array.isArray(config.srcaddr) ? config.srcaddr : [config.srcaddr || ''];
      const dstAddr = Array.isArray(config.dstaddr) ? config.dstaddr : [config.dstaddr || ''];
      const srcintf = config.srcintf || ''; const dstintf = config.dstintf || '';
      const service = Array.isArray(config.service) ? config.service : [config.service || ''];
      const allAnyItems = [];
      if (srcintf && (srcintf.toLowerCase() === 'all' || srcintf.toLowerCase() === 'any')) allAnyItems.push(`Kaynak Interface: "${srcintf}"`);
      if (dstintf && (dstintf.toLowerCase() === 'all' || dstintf.toLowerCase() === 'any')) allAnyItems.push(`Hedef Interface: "${dstintf}"`);
      srcAddr.forEach(addr => { if (addr && (addr.toLowerCase() === 'all' || addr.toLowerCase() === 'any')) allAnyItems.push('Kaynak Adres: ' + addr); });
      dstAddr.forEach(addr => { if (addr && (addr.toLowerCase() === 'all' || addr.toLowerCase() === 'any')) allAnyItems.push('Hedef Adres: ' + addr); });
      service.forEach(svc => { if (svc && (svc.toLowerCase() === 'all' || svc.toLowerCase() === 'any')) allAnyItems.push('Hizmet: ' + svc); });
      if (allAnyItems.length > 0) securityRisks.push({ title: 'Aşırı Geniş Erişim Kuralı (All/Any)', impact: `Policy'de çok geniş erişim tanımlanmış: ${allAnyItems.join(', ')}.`, steps: [`Bu policy'deki ${allAnyItems[0]}'i spesifik değerlerle değiştirin.`] });
      const policyData = { srcintf: config.srcintf || 'any', dstintf: config.dstintf || 'any', srcaddr: srcAddr, dstaddr: dstAddr, service: service };
      if ((config.action || '').toLowerCase() === 'accept') {
        const missing = [];
        if (!config['ips-sensor'] || config['ips-sensor'] === 'no-ips') missing.push('IPS (Saldırı Önleme)');
        if (!config['av-profile'] || config['av-profile'] === 'no-av') missing.push('AntiVirus');
        if (!config['webfilter-profile'] || config['webfilter-profile'] === 'no-filter') missing.push('Web Filtre');
        if (missing.length > 0) profileRisks.push({ title: 'Kritik Güvenlik Servisleri Eksik', impact: `Bu kuralda ${missing.join(', ')} denetimi yapılmıyor.`, steps: [`Policy ID: ${policy.id} için eksik profilleri aktif edin.`] });
      }
      if (securityRisks.length > 0) security_findings.push({ policy_id: policy.id, vdom: policy.vdom, risks: securityRisks, name: config.name || `Policy #${policy.id}`, policy_data: policyData });
      if (profileRisks.length > 0) profile_findings.push({ 
        policy_id: policy.id, vdom: policy.vdom, name: config.name || `Policy #${policy.id}`, risks: profileRisks, policy_data: policyData,
        profiles: { ips: config['ips-sensor'] || 'no-ips', av: config['av-profile'] || 'no-av', webfilter: config['webfilter-profile'] || 'no-filter', appctrl: config['application-list'] || 'no-appctrl', ssl: config['ssl-ssh-profile'] || 'no-inspection' }
      });
    });
    const totalPoliciesCount = policies.length;
    const allAnyScore = totalPoliciesCount > 0 ? Math.round(((totalPoliciesCount - security_findings.length) / totalPoliciesCount) * 100) : 100;
    const l7Score = totalPoliciesCount > 0 ? Math.round(((totalPoliciesCount - profile_findings.length) / totalPoliciesCount) * 100) : 100;
    const shadowScore = totalPoliciesCount > 0 ? Math.round(((totalPoliciesCount - shadow_findings.length) / totalPoliciesCount) * 100) : 100;
    const interfaceInteractions = {};
    policies.forEach(p => {
      const sources = Array.isArray(p.config?.srcintf) ? p.config.srcintf : [p.config?.srcintf || 'any'];
      const destinations = Array.isArray(p.config?.dstintf) ? p.config.dstintf : [p.config?.dstintf || 'any'];
      sources.forEach(s => { destinations.forEach(d => {
        const key = `${s} -> ${d}`; if (!interfaceInteractions[key]) interfaceInteractions[key] = { src: s, dst: d, count: 0 }; interfaceInteractions[key].count++;
      }); });
    });
    const sortedInteractions = Object.values(interfaceInteractions).sort((a, b) => b.count - a.count);
    return { 
      stig_score: calcScore('stig'), cis_score: calcScore('cis'), bp_score: calcScore('bp'),
      all_any_score: allAnyScore, l7_score: l7Score, shadow_score: shadowScore,
      total_policies: totalPoliciesCount, security_risks: security_findings, profile_risks: profile_findings, 
      shadow_risks: shadow_findings, compliance_risks: compliance_findings,
      manual_review_controls: manual_review_controls, interface_interactions: sortedInteractions,
      ip_analysis: this.analyzeIPs()
    };
  }

  isShadowed(prev, curr) {
    const checkSubset = (pArr, cArr) => {
      if (!pArr || !cArr) return false;
      const p = (Array.isArray(pArr) ? pArr : [pArr]).map(x => x.toLowerCase().replace(/"/g, ''));
      const c = (Array.isArray(cArr) ? cArr : [cArr]).map(x => x.toLowerCase().replace(/"/g, ''));
      if (p.includes('all') || p.includes('any')) return true;
      return c.every(item => p.includes(item));
    };
    const prevService = this.getPolicyServiceMatch(prev); const currService = this.getPolicyServiceMatch(curr);
    if (prevService.type !== currService.type) return false;
    return checkSubset(prev.srcintf, curr.srcintf) && checkSubset(prev.dstintf, curr.dstintf) && checkSubset(prev.srcaddr, curr.srcaddr) && checkSubset(prev.dstaddr, curr.dstaddr) && checkSubset(prevService.values, currService.values);
  }

  addItem(type, name, key, value, rawData = null) {
    this.parsedItems.push({ item_type: type, item_name: name, config_key: key, config_value: value, raw_data: rawData ? JSON.stringify(rawData) : null, parse_order: this.parsedItems.length + 1 });
  }

  parseFirewallPolicies() {
    let inPolicyBlock = false; let currentPolicy = null; let currentVdom = 'root'; let blockDepth = 0;
    for (let i = 0; i < this.lines.length; i++) {
      const line = this.lines[i].trim();
      if (line.startsWith('edit ') && !inPolicyBlock) {
        const vMatch = line.match(/^edit\s+"?([^"\s]+)"?/i);
        if (vMatch && this.lines[i-1]?.includes('config vdom')) currentVdom = vMatch[1];
      }
      if (line === 'config firewall policy') { inPolicyBlock = true; blockDepth = 0; continue; }
      if (inPolicyBlock) {
        if (line.startsWith('config ')) blockDepth++;
        if (line === 'end') {
          if (blockDepth > 0) blockDepth--;
          else { if (currentPolicy) this.addItem('firewall_policy', `Policy ${currentPolicy.id}`, `policy_${currentVdom}_${currentPolicy.id}`, 'Parsed', currentPolicy); currentPolicy = null; inPolicyBlock = false; continue; }
        }
        const editMatch = line.match(/^edit\s+(\d+)/i);
        if (editMatch && blockDepth === 0) { if (currentPolicy) this.addItem('firewall_policy', `Policy ${currentPolicy.id}`, `policy_${currentVdom}_${currentPolicy.id}`, 'Parsed', currentPolicy); currentPolicy = { id: editMatch[1], vdom: currentVdom, config: {} }; }
        else if (line === 'next' && currentPolicy && blockDepth === 0) { this.addItem('firewall_policy', `Policy ${currentPolicy.id}`, `policy_${currentVdom}_${currentPolicy.id}`, 'Parsed', currentPolicy); currentPolicy = null; }
        else if (currentPolicy && blockDepth === 0 && line.match(/^set\s+(\S+)\s+(.+)/i)) {
          const m = line.match(/^set\s+(\S+)\s+(.+)/i); const key = m[1]; let val = m[2].trim();
          if (['srcaddr', 'dstaddr', 'service', 'internet-service-name', 'internet-service-id', 'internet-service-custom'].includes(key)) {
            const matches = []; const quoteRegex = /"([^"]+)"/g; let match;
            while ((match = quoteRegex.exec(val)) !== null) matches.push(match[1]);
            currentPolicy.config[key] = matches.length > 0 ? matches : [val.replace(/"/g, '')];
          } else { currentPolicy.config[key] = val.replace(/"/g, ''); }
        }
      }
    }
  }

  parseDeviceInfo() { for (let line of this.lines) { const hMatch = line.match(/set\s+hostname\s+"?([^"\s]+)"?/i); if (hMatch) this.addItem('device_info', 'hostname', 'hostname', hMatch[1]); } }

  parseInterfaces() {
    let inBlock = false; let currentInterface = null;
    this.lines.forEach(line => {
      const t = line.trim(); if (t === 'config system interface') { inBlock = true; return; } if (!inBlock) return;
      if (t === 'end') { if (currentInterface) this.addItem('interface', currentInterface.name, 'interface', 'configured', currentInterface); currentInterface = null; inBlock = false; return; }
      const editMatch = t.match(/^edit\s+"?([^"\s]+)"?/i); if (editMatch) { if (currentInterface) this.addItem('interface', currentInterface.name, 'interface', 'configured', currentInterface); currentInterface = { name: editMatch[1], config: {} }; return; }
      if (t === 'next') { if (currentInterface) this.addItem('interface', currentInterface.name, 'interface', 'configured', currentInterface); currentInterface = null; return; }
      if (currentInterface && t.startsWith('set ')) {
        const match = t.match(/^set\s+(\S+)\s+(.+)/i); if (!match) return; const key = match[1]; const rawValue = match[2].trim(); const quotedValues = rawValue.match(/"([^"]+)"/g);
        currentInterface.config[key] = quotedValues ? quotedValues.map((value) => value.replace(/"/g, '')) : rawValue.replace(/"/g, '');
      }
    });
  }

  parseVDOM() { this.addItem('vdom', 'root', 'vdom', 'active'); }
  parseIPsec() {
    let inBlock = false;
    this.lines.forEach(line => {
      const t = line.trim(); if (t.match(/config\s+vpn\s+ipsec\s+phase1/i)) inBlock = true;
      else if (t === 'end' && inBlock) inBlock = false;
      else if (inBlock && t.match(/^edit\s+"?([^"\s]+)"?/i)) this.addItem('ipsec_phase1', t.match(/^edit\s+"?([^"\s]+)"?/i)[1], 'phase1', 'configured');
    });
  }
}
module.exports = FortiGateParser;
