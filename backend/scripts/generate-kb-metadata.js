const fs = require('fs');
const path = require('path');

const kbPath = path.join(__dirname, '..', 'data', 'security_kb.json');
const outPath = path.join(__dirname, '..', 'data', 'security_kb_metadata.json');
const kb = JSON.parse(fs.readFileSync(kbPath, 'utf8'));

const categoryUrls = {
  STIG: ['https://www.cyber.mil/stigs/downloads/'],
  CIS: ['https://www.cisecurity.org/benchmark/fortinet'],
  BP: ['https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide'],
  NIST: ['https://www.nist.gov/cyberframework'],
  ISO27001: ['https://www.iso.org/isoiec-27001-information-security.html'],
  PCIDSS: ['https://www.pcisecuritystandards.org/standards/pci-dss/'],
  HIPAA: ['https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html'],
  SOX: ['https://www.sec.gov/about/laws/soa2002.pdf']
};

const docUrls = {
  idleTimeout: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/215451/setting-the-idle-timeout-time',
  passwordPolicy: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/364729/password-policy',
  passwordPolicyConfig: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/313307/setting-the-password-policy',
  adminLockout: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/279661/configuring-the-maximum-log-in-attempts-and-lockout-period',
  admins: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/183365/administrators',
  adminOptions: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/14906/administrator-account-options',
  mfa: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/419391/applying-multi-factor-authentication',
  trustedHosts: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/14906/administrator-account-options',
  interfaceAccess: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/325005/interface-access',
  interfaces: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/154471/interfaces',
  ntp: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/512210/setting-the-system-time',
  tls: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/45329/tls-configuration',
  snmp: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/62595/snmp',
  snmpV3: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/457149/snmp-v3-users',
  snmpV2: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/547825/snmp-v1-v2c-communities',
  fortiguard: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/42459/fortiguard',
  fortiguardUpdates: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/547335/automatic-updates',
  fortiguardConnectivity: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/703926/verifying-connectivity-to-fortiguard',
  syslog: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/250999/log-settings-and-targets',
  fortianalyzer: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/235849/logging-to-fortianalyzer',
  logging: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/738890/log-and-report',
  firewallPolicy: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/656084/firewall-policy',
  addressObjects: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/214805/address-objects',
  ips: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/583477/configuring-an-ips-sensor',
  antivirus: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/922423/configuring-an-antivirus-profile',
  webfilter: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/833698/web-filter',
  appControl: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/836937/configuring-an-application-sensor',
  sslInspection: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/709167/configuring-an-ssl-ssh-inspection-profile',
  sslVpnBestPractices: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/869159/ssl-vpn-best-practices',
  sslVpnWebMode: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/100733/ssl-vpn-web-mode',
  sslVpnDtls: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/774877/dtls-support',
  ipsec: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/762500/general-ipsec-vpn-configuration',
  bgp: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/216371/bgp-neighbor-password',
  ospf: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/425672/ospfv3-neighbor-authentication',
  ha: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/666376/high-availability',
  haMgmt: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/313152/out-of-band-management-with-reserved-management-interfaces',
  vdom: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/109991/virtual-domains',
  dns: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/780581/dns',
  dnsDot: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/42181/dns-over-tls-and-https',
  securityRating: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/292634/security-rating',
  configurationBackups: 'https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/702257/configuration-backups'
};

function unique(items) {
  return [...new Set(items.filter(Boolean))];
}

function getTopicUrls(rule) {
  const text = [rule.cli_path, rule.eval_path, rule.name, rule.remediation].join(' ').toLowerCase();
  const urls = [];

  if (text.includes('admintimeout') || text.includes('session-timeout')) urls.push(docUrls.idleTimeout);
  if (text.includes('password-policy') || text.includes('minimum-length') || text.includes('min-upper-case') || text.includes('expire-days') || text.includes('reuse-password')) urls.push(docUrls.passwordPolicy, docUrls.passwordPolicyConfig);
  if (text.includes('lockout')) urls.push(docUrls.adminLockout);
  if (text.includes('system admin') || text.includes('trusthost') || text.includes('two-factor') || text.includes('administrator')) urls.push(docUrls.admins, docUrls.adminOptions);
  if (text.includes('two-factor') || text.includes('mfa')) urls.push(docUrls.mfa);
  if (text.includes('interface') || text.includes('allowaccess') || text.includes('vlan')) urls.push(docUrls.interfaces, docUrls.interfaceAccess);
  if (text.includes('ntp')) urls.push(docUrls.ntp);
  if (text.includes('tls') || text.includes('crypto') || text.includes('hsts') || text.includes('certificate')) urls.push(docUrls.tls);
  if (text.includes('snmp')) urls.push(docUrls.snmp);
  if (text.includes('snmp user') || text.includes('auth-proto') || text.includes('priv-proto')) urls.push(docUrls.snmpV3);
  if (text.includes('snmp sysinfo') || text.includes('v1/v2c')) urls.push(docUrls.snmpV2);
  if (text.includes('fortiguard') || text.includes('ips-status') || text.includes('antivirus-status') || text.includes('botnet') || text.includes('sandbox') || text.includes('threat-weight')) urls.push(docUrls.fortiguard, docUrls.fortiguardUpdates, docUrls.fortiguardConnectivity);
  if (text.includes('syslog') || text.includes('log ') || text.includes('fortianalyzer')) urls.push(docUrls.logging, docUrls.syslog);
  if (text.includes('fortianalyzer')) urls.push(docUrls.fortianalyzer);
  if (text.includes('firewall policy') || text.includes('default-policy-log') || text.includes('policy')) urls.push(docUrls.firewallPolicy);
  if (text.includes('firewall address') || text.includes('srcaddr') || text.includes('dstaddr') || text.includes('zone-id')) urls.push(docUrls.addressObjects);
  if (text.includes('ips')) urls.push(docUrls.ips);
  if (text.includes('antivirus') || text.includes('av-profile')) urls.push(docUrls.antivirus);
  if (text.includes('webfilter')) urls.push(docUrls.webfilter);
  if (text.includes('appctrl') || text.includes('application')) urls.push(docUrls.appControl);
  if (text.includes('ssl-ssh-profile') || text.includes('deep-inspection') || text.includes('inspection')) urls.push(docUrls.sslInspection);
  if (text.includes('ssl-vpn') || text.includes('vpn ssl settings') || text.includes('web-mode')) urls.push(docUrls.sslVpnBestPractices, docUrls.sslVpnWebMode);
  if (text.includes('dtls')) urls.push(docUrls.sslVpnDtls);
  if (text.includes('ipsec') || text.includes('vpn ipsec')) urls.push(docUrls.ipsec);
  if (text.includes('router_bgp') || text.includes('bgp')) urls.push(docUrls.bgp);
  if (text.includes('router_ospf') || text.includes('ospf')) urls.push(docUrls.ospf);
  if (text.includes('system ha')) urls.push(docUrls.ha, docUrls.haMgmt);
  if (text.includes('vdom')) urls.push(docUrls.vdom);
  if (text.includes('system dns') || text.includes('dns')) urls.push(docUrls.dns);
  if (text.includes('dns-over-tls')) urls.push(docUrls.dnsDot);
  if (text.includes('backup') || text.includes('pcfg-password-enc')) urls.push(docUrls.configurationBackups);

  return unique(urls);
}

function getSeverityRisk(rule) {
  const severityMap = {
    CRITICAL: 'Bu eksiklik doğrudan yetkisiz erişim, denetim kaybı veya kritik servislerin istismar edilmesi riskini artırır.',
    HIGH: 'Bu eksiklik saldırı yüzeyini anlamlı şekilde büyütür ve güvenlik olaylarının etkisini artırabilir.',
    MEDIUM: 'Bu eksiklik sertleştirme seviyesini düşürür ve bir saldırganın hareket alanını genişletebilir.',
    LOW: 'Bu eksiklik tek başına kritik olmayabilir ancak savunma derinliğini zayıflatır.'
  };
  return severityMap[rule.severity] || severityMap.MEDIUM;
}

function getEvalDescription(rule) {
  const expected = Array.isArray(rule.eval_expected) ? rule.eval_expected.join(', ') : rule.eval_expected;
  switch (rule.eval_type) {
    case 'max_num': return `Denetim mantigi: ${rule.eval_path} degeri ${expected} veya altinda olmalidir.`;
    case 'min_num': return `Denetim mantigi: ${rule.eval_path} degeri en az ${expected} olmalidir.`;
    case 'equal': return `Denetim mantigi: ${rule.eval_path} degeri tam olarak ${expected} olmalidir.`;
    case 'not_equal': return `Denetim mantigi: ${rule.eval_path} degeri ${expected} olmamalidir.`;
    case 'in_array': return `Denetim mantigi: ${rule.eval_path} degeri su degerlerden biri olmalidir: ${expected}.`;
    case 'not_in_array': return `Denetim mantigi: ${rule.eval_path} degeri su degerlerden biri olmamalidir: ${expected}.`;
    case 'not_contains': return `Denetim mantigi: ${rule.eval_path} icinde ${expected} gecmemelidir.`;
    case 'exists': return `Denetim mantigi: ${rule.eval_path} alani tanimli olmalidir.`;
    default: return `Denetim mantigi: ${rule.eval_path} alani beklenen degere gore dogrulanir.`;
  }
}

function getRemediationDetails(rule) {
  return [
    `Ilgili blok: ${rule.cli_path}.`,
    'Degisiklikten once running-config yedegi alin ve degisikligi degisiklik yonetimi kaydi ile uygulayin.',
    `Onerilen CLI komutu: ${rule.remediation}.`,
    'Degisiklikten sonra ilgili ayarin show/get ciktilari ve test loglari ile dogrulama yapin.'
  ];
}

function getValidationStatus(rule) {
  const supportedPrefixes = new Set([
    'system_global',
    'system_settings',
    'system_admin',
    'firewall_policy',
    'system_fortiguard',
    'password_policy',
    'interface',
    'syslog_setting',
    'vpn_ssl_settings',
    'ntp_setting',
    'system_ha',
    'log_disk',
    'system_dns',
    'snmp_user',
    'system_snmp',
    'log_fortianalyzer',
    'router_bgp',
    'router_ospf',
    'firewall_ssl_setting',
    'log_memory',
    'log_setting'
  ]);
  const prefixAliases = {
    system_interface: 'interface',
    log_disk_setting: 'log_disk',
    log_syslogd: 'syslog_setting'
  };
  const prefix = prefixAliases[rule.eval_path.split('.')[0]] || rule.eval_path.split('.')[0];

  if (!supportedPrefixes.has(prefix)) return 'needs_review';
  if (['NIST', 'ISO27001', 'PCIDSS', 'HIPAA', 'SOX'].includes(rule.category)) return 'needs_review';
  if (['CIS-1.1.4'].includes(rule.id)) return 'needs_review';
  return 'mapped';
}

function getQualityNotes(rule) {
  const notes = [];
  if (rule.id === 'V-236601') {
    notes.push('Antivirus guncelleme kontrolu antivirus-status alanina gore normalize edildi; cihaz surumune gore son bir kez dogrulanmasi tavsiye edilir.');
  }
  if (rule.id === 'CIS-1.1.4') {
    notes.push('Bu kontrol FortiGate uzerinde dogrudan SSH key zorunlulugu yerine yonetici erisim tasarimi ile ele alinabilir; access-profile alani tek basina yeterli olmayabilir.');
  }
  if (rule.id === 'V-236574-3') {
    notes.push('Orijinal ad alaninda bozuk karakter vardi; metadata tarafinda okunabilir aciklama ile destekleniyor.');
  }
  if (['NIST', 'ISO27001', 'PCIDSS', 'HIPAA', 'SOX'].includes(rule.category)) {
    notes.push('Bu kontrol daha cok yonetisim veya surec gereksinimini temsil eder. Dogrudan native FortiOS anahtari yerine harici kanit, entegrasyon veya operasyonel prosedur gerekebilir.');
  }
  if (['PCIDSS'].includes(rule.category) && getValidationStatus(rule) === 'needs_review') {
    notes.push('Bu PCI-DSS kontrolu teknik olarak desteklenmeyen bir eval_path kullandigi icin otomatik skorlamadan dislandi; kanit bazli manuel kontrol gerekir.');
  }
  return notes;
}

function getDisplayName(rule) {
  if (rule.id === 'V-236574-3') return 'Log Warning Threshold';
  return rule.name;
}

const metadata = kb.map((rule) => ({
  id: rule.id,
  name: getDisplayName(rule),
  issue_description: `${rule.name} kontrolu icin beklenen durum saglanmazsa: ${getSeverityRisk(rule)}`,
  verification_note: getEvalDescription(rule),
  recommendation_details: getRemediationDetails(rule),
  reference_urls: unique([...(categoryUrls[rule.category] || []), ...getTopicUrls(rule)]),
  validation_status: getValidationStatus(rule),
  quality_notes: getQualityNotes(rule)
}));

fs.writeFileSync(outPath, JSON.stringify(metadata, null, 2) + '\n');
console.log(`metadata written: ${outPath} (${metadata.length} records)`);
