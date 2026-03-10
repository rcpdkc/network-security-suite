import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { BrowserRouter as Router, Routes, Route, Link, useParams, useNavigate } from 'react-router-dom';
import { Shield, Home, Upload, Activity, AlertTriangle, Zap, CheckCircle2, FileJson, ArrowLeft, ArrowRight, Printer, Info, BarChart3, Clock, Database, ChevronRight, Terminal, Search, Lock, Cpu, Monitor } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Settings as SettingsIcon, Key, FileText, Plus, Save, Trash2, Edit, Globe, Server, FileCheck, Bell, RefreshCw, ChevronDown, ChevronUp, LinkIcon, X } from 'lucide-react';
import './App.css';
import DebugMenu from './DebugMenu';

const uuidv4 = () => {
  return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
    (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
  );
};

const SYNC_INTERVAL_OPTIONS = [
  { value: 5, label: '5 dakika' },
  { value: 15, label: '15 dakika' },
  { value: 30, label: '30 dakika' },
  { value: 60, label: '1 saat' },
  { value: 180, label: '3 saat' },
  { value: 360, label: '6 saat' },
  { value: 720, label: '12 saat' },
  { value: 1440, label: '24 saat' }
];

// --- CVE Tracking View ---
const CVEView = ({ API_URL, onMarkRead }) => {
  const [cves, setCves] = useState([]);
  const [loading, setLoading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [intervalMinutes, setIntervalMinutes] = useState(60);
  const [savingInterval, setSavingInterval] = useState(false);
  const [expandedCveId, setExpandedCveId] = useState(null);

  const fetchCVEs = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_URL}/cve?limit=300`);
      setCves(res.data);
      onMarkRead(); // Açtığımızda hepsini okundu işaretle
    } catch (e) { console.error(e); }
    setLoading(false);
  };

  const fetchSyncConfig = async () => {
    try {
      const res = await axios.get(`${API_URL}/cve/sync-config`);
      setIntervalMinutes(Number(res.data?.interval_minutes || 60));
    } catch (e) { console.error(e); }
  };

  const saveSyncInterval = async (newValue) => {
    setSavingInterval(true);
    try {
      await axios.post(`${API_URL}/cve/sync-config`, { interval_minutes: Number(newValue) });
      setIntervalMinutes(Number(newValue));
    } catch (e) {
      console.error(e);
      alert('Senkron suresi kaydedilemedi!');
    } finally {
      setSavingInterval(false);
    }
  };

  const handleSync = async () => {
    setSyncing(true);
    try {
      const syncRes = await axios.post(`${API_URL}/cve/sync`);
      await fetchCVEs();
      alert(`Tarama tamamlandi. ${syncRes.data?.newCount || 0} yeni kayit eklendi.`);
    } catch (e) { alert('Tarama hatası!'); }
    setSyncing(false);
  };

  useEffect(() => {
    fetchCVEs();
    fetchSyncConfig();
  }, []);

  return (
    <div className="cve-view fade-in">
      <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'30px'}}>
        <div>
          <h3 style={{fontSize:'1.25rem', fontWeight:'800'}}>Fortinet PSIRT & CVE Takibi</h3>
          <p style={{fontSize:'13px', color:'#64748b'}}>Kayitlar veritabaninda saklanir, internet olmasa bile son cekilen CVE verileri goruntulenir.</p>
          <div style={{display:'flex', alignItems:'center', gap:'10px', marginTop:'10px'}}>
            <label style={{fontSize:'12px', color:'#64748b', fontWeight:'700'}}>Otomatik Tarama Suresi</label>
            <select
              value={intervalMinutes}
              onChange={(e) => saveSyncInterval(e.target.value)}
              disabled={savingInterval}
              style={{padding:'8px 10px', borderRadius:'8px', border:'1px solid #e2e8f0', background:'white'}}
            >
              {SYNC_INTERVAL_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </div>
        </div>
        <button 
          onClick={handleSync} 
          disabled={syncing}
          style={{background:'var(--primary)', color:'white', border:'none', padding:'12px 25px', borderRadius:'12px', fontWeight:'700', cursor:'pointer', display:'flex', alignItems:'center', gap:'10px'}}
        >
          <RefreshCw size={18} className={syncing ? 'spin' : ''} /> {syncing ? 'Taraniyor...' : 'Simdi Tara'}
        </button>
      </div>

      <div style={{display:'grid', gap:'15px'}}>
        {cves.map((c) => {
          const isExpanded = expandedCveId === c.id;
          return (
            <div key={c.id} style={{background:'white', padding:'25px', borderRadius:'20px', border:`1px solid ${c.is_new ? 'var(--primary)' : '#e2e8f0'}`, boxShadow:'0 4px 6px -1px rgba(0,0,0,0.05)', position:'relative', cursor:'pointer'}} onClick={() => setExpandedCveId(isExpanded ? null : c.id)}>
              {c.is_new && <span style={{position:'absolute', top:'-10px', right:'20px', background:'var(--primary)', color:'white', fontSize:'10px', fontWeight:'800', padding:'4px 12px', borderRadius:'20px', boxShadow:'0 4px 10px rgba(99,102,241,0.4)'}}>YENI</span>}
              <div style={{display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:'15px'}}>
                <div style={{display:'flex', alignItems:'center', gap:'12px'}}>
                  <span style={{background: c.severity==='CRITICAL'?'#fee2e2':c.severity==='HIGH'?'#ffedd5':'#f1f5f9', color: c.severity==='CRITICAL'?'#ef4444':c.severity==='HIGH'?'#f59e0b':'#64748b', padding:'4px 12px', borderRadius:'8px', fontSize:'11px', fontWeight:'800'}}>{c.severity}</span>
                  <span style={{fontWeight:'800', color:'#1e293b', fontSize:'14px'}}>{c.cve_id}</span>
                  {c.link && (
                    <a 
                      href={c.link} 
                      target="_blank" 
                      rel="noreferrer" 
                      onClick={(e) => e.stopPropagation()}
                      style={{display:'flex', alignItems:'center', color:'var(--primary)', textDecoration:'none', padding:'4px'}}
                      title="CVE kaynağına git"
                    >
                      <LinkIcon size={16}/>
                    </a>
                  )}
                </div>
                <div style={{display:'flex', alignItems:'center', gap:'10px'}}>
                  <span style={{fontSize:'12px', color:'#94a3b8'}}>{new Date(c.published_at).toLocaleDateString('tr-TR')}</span>
                  {c.solution && (isExpanded ? <ChevronUp size={18} color="#64748b"/> : <ChevronDown size={18} color="#64748b"/>)}
                </div>
              </div>
              <h4 style={{fontSize:'16px', fontWeight:'700', color:'#1e293b', marginBottom:'10px'}}>{c.title}</h4>
              <p style={{fontSize:'13px', color:'#64748b', lineHeight:'1.6', marginBottom: c.solution && isExpanded ? '15px' : '0'}}>{c.description}</p>
              
              {c.solution && isExpanded && (
                <div style={{borderTop:'1px solid #e2e8f0', paddingTop:'15px', marginTop:'15px', background:'#f8fafc', padding:'15px', borderRadius:'10px'}}>
                  <div style={{display:'flex', alignItems:'center', gap:'8px', marginBottom:'8px'}}>
                    <CheckCircle2 size={16} color="#10b981"/>
                    <span style={{fontSize:'12px', fontWeight:'800', color:'#1e293b', textTransform:'uppercase', letterSpacing:'0.5px'}}>Çözüm / Öneri</span>
                  </div>
                  <p style={{fontSize:'13px', color:'#475569', lineHeight:'1.6'}}>{c.solution}</p>
                </div>
              )}
            </div>
          );
        })}
        {cves.length === 0 && !loading && <div style={{textAlign:'center', padding:'60px', color:'#94a3b8'}}>Henuz bir acik kaydi bulunmuyor.</div>}
      </div>
    </div>
  );
};
// ... (API_URL, APP_VERSION definitions)

// --- Settings View Component ---
const SettingsView = ({ API_URL }) => {
  const [activeTab, setActiveTab] = useState('sshTemplates'); // 'apiTemplates' | 'sshTemplates' | 'snmpTemplates' | 'cveDb' | 'kb' | 'switchKb' | 'ldap' | 'certs'
  const [kbRules, setKbRules] = useState([]);
  const [switchKbRules, setSwitchKbRules] = useState([]);
  const [ldapConfig, setLdapConfig] = useState({ host: '', port: 389, baseDN: '', user: '', pass: '' });
  const [certs, setCerts] = useState([]);
  const [snmpTemplates, setSnmpTemplates] = useState([]);
  const [sshTemplates, setSshTemplates] = useState([]);
  const [apiTemplates, setApiTemplates] = useState([]);
  const [customIcons, setCustomIcons] = useState([]);
  const [loadedTabs, setLoadedTabs] = useState({ customIcons: false, apiTemplates: false, sshTemplates: false, snmpTemplates: false, cveDb: false, kb: false, switchKb: false, ldap: false, certs: false });
  const [editingRule, setEditingRule] = useState(null);
  const [editingSwitchRule, setEditingSwitchRule] = useState(null);
  const [editingSnmpTemplate, setEditingSnmpTemplate] = useState(null);
  const [editingSshTemplate, setEditingSshTemplate] = useState(null);
  const [editingApiTemplate, setEditingApiTemplate] = useState(null);
  const [newIcon, setNewIcon] = useState({ name: '', data: '' });
  const [searchKB, setSearchKB] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [cveSources, setCveSources] = useState([]);
  const [editingSource, setEditingSource] = useState(null);
  const [cveSyncConfig, setCveSyncConfig] = useState({ interval_minutes: 60 });

  const [snmpForm, setSnmpForm] = useState({
    name: '', version: 'v2c', community: 'public',
    security_name: '', security_level: 'noAuthNoPriv',
    auth_protocol: 'SHA', auth_key: '',
    priv_protocol: 'AES', priv_key: ''
  });

  const [sshForm, setSshForm] = useState({
    name: '', username: '', password: '', port: 22
  });

  const [apiForm, setApiForm] = useState({
    name: '', base_url: '', api_key: '', auth_type: 'Bearer'
  });

  const toMultilineText = (value) => {
    if (Array.isArray(value)) return value.join('\n');
    if (typeof value === 'string') return value;
    return '';
  };

  const parseMultilineText = (value) => String(value || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);

  const countListItems = (value) => {
    if (Array.isArray(value)) return value.filter(Boolean).length;
    if (typeof value === 'string') return parseMultilineText(value).length;
    return 0;
  };

  const prepareRuleForEdit = (rule = null) => {
    if (!rule) return null;
    return {
      ...rule,
      recommendation_details: toMultilineText(rule.recommendation_details),
      reference_urls: toMultilineText(rule.reference_urls)
    };
  };

  const fetchKB = async () => {
    try {
      const res = await axios.get(`${API_URL}/security-kb`);
      setKbRules(res.data);
    } catch (e) { console.error(e); }
  };

  const fetchSnmpTemplates = async () => {
    try {
      const res = await axios.get(`${API_URL}/snmp-templates`);
      setSnmpTemplates(res.data);
    } catch (e) { console.error(e); }
  };

  const fetchSshTemplates = async () => {
    try {
      const res = await axios.get(`${API_URL}/ssh-templates`);
      setSshTemplates(res.data);
    } catch (e) { console.error(e); }
  };

  const fetchApiTemplates = async () => {
    try {
      const res = await axios.get(`${API_URL}/api-templates`);
      setApiTemplates(res.data);
    } catch (e) { console.error(e); }
  };

  const handleSaveApiTemplate = async (e) => {
    e.preventDefault();
    try {
      if (editingApiTemplate && editingApiTemplate.id) {
        await axios.put(`${API_URL}/api-templates/${editingApiTemplate.id}`, apiForm);
      } else {
        await axios.post(`${API_URL}/api-templates`, apiForm);
      }
      setEditingApiTemplate(null);
      fetchApiTemplates();
      alert('API Template Kaydedildi');
    } catch (e) { alert('Hata!'); }
  };

  const handleDeleteApiTemplate = async (id) => {
    if (!window.confirm('Template silinsin mi?')) return;
    try {
      await axios.delete(`${API_URL}/api-templates/${id}`);
      fetchApiTemplates();
    } catch (e) { alert('Hata!'); }
  };

  const handleSaveSnmpTemplate = async (e) => {
    e.preventDefault();
    try {
      if (editingSnmpTemplate && editingSnmpTemplate.id) {
        await axios.put(`${API_URL}/snmp-templates/${editingSnmpTemplate.id}`, snmpForm);
      } else {
        await axios.post(`${API_URL}/snmp-templates`, snmpForm);
      }
      setEditingSnmpTemplate(null);
      fetchSnmpTemplates();
      alert('SNMP Template Kaydedildi');
    } catch (e) { alert('Hata!'); }
  };

  const handleDeleteSnmpTemplate = async (id) => {
    if (!window.confirm('Template silinsin mi?')) return;
    try {
      await axios.delete(`${API_URL}/snmp-templates/${id}`);
      fetchSnmpTemplates();
    } catch (e) { alert('Hata!'); }
  };

  const handleSaveSshTemplate = async (e) => {
    e.preventDefault();
    try {
      if (editingSshTemplate && editingSshTemplate.id) {
        await axios.put(`${API_URL}/ssh-templates/${editingSshTemplate.id}`, sshForm);
      } else {
        await axios.post(`${API_URL}/ssh-templates`, sshForm);
      }
      setEditingSshTemplate(null);
      fetchSshTemplates();
      alert('SSH Template Kaydedildi');
    } catch (e) { alert('Hata!'); }
  };

  const handleDeleteSshTemplate = async (id) => {
    if (!window.confirm('Template silinsin mi?')) return;
    try {
      await axios.delete(`${API_URL}/ssh-templates/${id}`);
      fetchSshTemplates();
    } catch (e) { alert('Hata!'); }
  };

  const fetchSwitchKB = async () => {
    try {
      const res = await axios.get(`${API_URL}/switch-security-kb`);
      setSwitchKbRules(res.data);
    } catch (e) { console.error(e); }
  };

  const fetchLdap = async () => {
    try {
      const res = await axios.get(`${API_URL}/settings/ldap`);
      if (res.data.host) setLdapConfig(res.data);
    } catch (e) { console.error(e); }
  };

  const fetchCerts = async () => {
    try {
      const res = await axios.get(`${API_URL}/settings/certs`);
      setCerts(res.data);
    } catch (e) { console.error(e); }
  };

  const fetchCveSources = async () => {
    try {
      const res = await axios.get(`${API_URL}/cve/sources`);
      setCveSources(res.data || []);
    } catch (e) { console.error(e); }
  };

  const fetchCveSyncConfig = async () => {
    try {
      const res = await axios.get(`${API_URL}/cve/sync-config`);
      setCveSyncConfig({ interval_minutes: Number(res.data?.interval_minutes || 60) });
    } catch (e) { console.error(e); }
  };

  useEffect(() => {
    if (activeTab === 'cveDb' && !loadedTabs.cveDb) {
      Promise.all([fetchCveSources(), fetchCveSyncConfig()])
        .finally(() => setLoadedTabs((prev) => ({ ...prev, cveDb: true })));
      return;
    }
    if (activeTab === 'kb' && !loadedTabs.kb) {
      fetchKB().finally(() => setLoadedTabs((prev) => ({ ...prev, kb: true })));
      return;
    }
    if (activeTab === 'switchKb' && !loadedTabs.switchKb) {
      fetchSwitchKB().finally(() => setLoadedTabs((prev) => ({ ...prev, switchKb: true })));
      return;
    }
    if (activeTab === 'ldap' && !loadedTabs.ldap) {
      fetchLdap().finally(() => setLoadedTabs((prev) => ({ ...prev, ldap: true })));
      return;
    }
    if (activeTab === 'certs' && !loadedTabs.certs) {
      fetchCerts().finally(() => setLoadedTabs((prev) => ({ ...prev, certs: true })));
      return;
    }
    if (activeTab === 'snmpTemplates' && !loadedTabs.snmpTemplates) {
      fetchSnmpTemplates().finally(() => setLoadedTabs((prev) => ({ ...prev, snmpTemplates: true })));
      return;
    }
    if (activeTab === 'sshTemplates' && !loadedTabs.sshTemplates) {
      fetchSshTemplates().finally(() => setLoadedTabs((prev) => ({ ...prev, sshTemplates: true })));
      return;
    }
    if (activeTab === 'apiTemplates' && !loadedTabs.apiTemplates) {
      fetchApiTemplates().finally(() => setLoadedTabs((prev) => ({ ...prev, apiTemplates: true })));
      return;
    }
    if (activeTab === 'customIcons' && !loadedTabs.customIcons) {
      const fetchIcons = async () => {
        try {
          const res = await axios.get(`${API_URL}/icons`);
          setCustomIcons(res.data);
        } catch (e) { console.error(e); }
      };
      fetchIcons().finally(() => setLoadedTabs((prev) => ({ ...prev, customIcons: true })));
    }
  }, [activeTab, loadedTabs]);

  const handleSaveLdap = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${API_URL}/settings/ldap`, ldapConfig);
      alert('LDAP Ayarları Kaydedildi');
    } catch (e) { alert('Hata!'); }
  };

  const handleSaveRule = async (e) => {
    e.preventDefault();
    try {
      const payload = {
        ...editingRule,
        recommendation_details: parseMultilineText(editingRule.recommendation_details),
        reference_urls: parseMultilineText(editingRule.reference_urls)
      };
      await axios.post(`${API_URL}/security-kb`, payload);
      setEditingRule(null);
      fetchKB();
      alert('Kural Kaydedildi');
    } catch (e) { alert('Hata!'); }
  };

  const handleDeleteRule = async (id) => {
    if (!window.confirm('Kuralı silmek istediğinize emin misiniz?')) return;
    try {
      await axios.delete(`${API_URL}/security-kb/${id}`);
      fetchKB();
    } catch (e) { alert('Silme hatası!'); }
  };

  const handleSaveSwitchRule = async (e) => {
    e.preventDefault();
    try {
      const payload = {
        ...editingSwitchRule,
        recommendation_details: parseMultilineText(editingSwitchRule.recommendation_details),
        reference_urls: parseMultilineText(editingSwitchRule.reference_urls)
      };
      await axios.post(`${API_URL}/switch-security-kb`, payload);
      setEditingSwitchRule(null);
      fetchSwitchKB();
      alert('Switch kuralı kaydedildi');
    } catch (e) { alert('Hata!'); }
  };

  const handleDeleteSwitchRule = async (id, switchVendor = 'cisco', switchModel = 'all') => {
    if (!window.confirm('Switch kuralını silmek istediğinize emin misiniz?')) return;
    try {
      await axios.delete(`${API_URL}/switch-security-kb/${id}`, { params: { vendor: switchVendor, model: switchModel } });
      fetchSwitchKB();
    } catch (e) { alert('Silme hatası!'); }
  };

  const handleSaveCveSource = async (e) => {
    e.preventDefault();
    try {
      const payload = {
        ...editingSource,
        interval_minutes: undefined
      };
      if (editingSource.id) {
        await axios.put(`${API_URL}/cve/sources/${editingSource.id}`, payload);
      } else {
        await axios.post(`${API_URL}/cve/sources`, payload);
      }
      setEditingSource(null);
      fetchCveSources();
      alert('CVE kaynak kaydi guncellendi.');
    } catch (e) {
      alert('Kaynak kaydi yapilamadi!');
    }
  };

  const handleDeleteCveSource = async (id) => {
    if (!window.confirm('CVE kaynagi silinsin mi?')) return;
    try {
      await axios.delete(`${API_URL}/cve/sources/${id}`);
      fetchCveSources();
    } catch (e) {
      alert('Kaynak silinemedi!');
    }
  };

  const handleSaveCveSyncConfig = async (e) => {
    e.preventDefault();
    try {
      const minutes = Number(cveSyncConfig.interval_minutes || 60);
      await axios.post(`${API_URL}/cve/sync-config`, { interval_minutes: minutes });
      alert('CVE otomatik tarama suresi kaydedildi.');
    } catch (e) {
      alert('Tarama suresi kaydedilemedi!');
    }
  };

  const filteredKB = kbRules.filter(r => {
    const matchesSearch = r.name.toLowerCase().includes(searchKB.toLowerCase()) || r.id.toLowerCase().includes(searchKB.toLowerCase());
    const matchesCat = categoryFilter === 'all' || r.category === categoryFilter;
    return matchesSearch && matchesCat;
  });

  const filteredSwitchKB = switchKbRules.filter(r => {
    const matchesSearch = r.name.toLowerCase().includes(searchKB.toLowerCase()) || r.id.toLowerCase().includes(searchKB.toLowerCase());
    const matchesCat = categoryFilter === 'all' || r.category === categoryFilter;
    return matchesSearch && matchesCat;
  });

  return (
    <div className="settings-view fade-in">
      <div style={{display:'flex', gap:'20px', marginBottom:'30px', borderBottom:'1px solid #e2e8f0', paddingBottom:'15px', flexWrap:'wrap'}}>
        <button onClick={() => setActiveTab('apiTemplates')} style={{padding:'10px 20px', borderRadius:'10px', border:'none', background: activeTab==='apiTemplates'?'var(--primary)':'transparent', color: activeTab==='apiTemplates'?'white':'#64748b', fontWeight:'700', cursor:'pointer', display:'flex', alignItems:'center', gap:'8px'}}><Globe size={18}/> API Templateleri</button>
        <button onClick={() => setActiveTab('sshTemplates')} style={{padding:'10px 20px', borderRadius:'10px', border:'none', background: activeTab==='sshTemplates'?'var(--primary)':'transparent', color: activeTab==='sshTemplates'?'white':'#64748b', fontWeight:'700', cursor:'pointer', display:'flex', alignItems:'center', gap:'8px'}}><Terminal size={18}/> SSH Templateleri</button>
        <button onClick={() => setActiveTab('snmpTemplates')} style={{padding:'10px 20px', borderRadius:'10px', border:'none', background: activeTab==='snmpTemplates'?'var(--primary)':'transparent', color: activeTab==='snmpTemplates'?'white':'#64748b', fontWeight:'700', cursor:'pointer', display:'flex', alignItems:'center', gap:'8px'}}><SettingsIcon size={18}/> SNMP Templateleri</button>
        <button onClick={() => setActiveTab('cveDb')} style={{padding:'10px 20px', borderRadius:'10px', border:'none', background: activeTab==='cveDb'?'var(--primary)':'transparent', color: activeTab==='cveDb'?'white':'#64748b', fontWeight:'700', cursor:'pointer', display:'flex', alignItems:'center', gap:'8px'}}><AlertTriangle size={18}/> CVE Veri Tabanı</button>
        <button onClick={() => setActiveTab('kb')} style={{padding:'10px 20px', borderRadius:'10px', border:'none', background: activeTab==='kb'?'var(--primary)':'transparent', color: activeTab==='kb'?'white':'#64748b', fontWeight:'700', cursor:'pointer', display:'flex', alignItems:'center', gap:'8px'}}><FileCheck size={18}/> Güvenlik Bilgi Tabanı (KB)</button>
        <button onClick={() => setActiveTab('switchKb')} style={{padding:'10px 20px', borderRadius:'10px', border:'none', background: activeTab==='switchKb'?'var(--primary)':'transparent', color: activeTab==='switchKb'?'white':'#64748b', fontWeight:'700', cursor:'pointer', display:'flex', alignItems:'center', gap:'8px'}}><Server size={18}/> Switch Bilgi Tabanı (KB)</button>
        <button onClick={() => setActiveTab('ldap')} style={{padding:'10px 20px', borderRadius:'10px', border:'none', background: activeTab==='ldap'?'var(--primary)':'transparent', color: activeTab==='ldap'?'white':'#64748b', fontWeight:'700', cursor:'pointer', display:'flex', alignItems:'center', gap:'8px'}}><Globe size={18}/> LDAP Bağlantısı</button>
        <button onClick={() => setActiveTab('certs')} style={{padding:'10px 20px', borderRadius:'10px', border:'none', background: activeTab==='certs'?'var(--primary)':'transparent', color: activeTab==='certs'?'white':'#64748b', fontWeight:'700', cursor:'pointer', display:'flex', alignItems:'center', gap:'8px'}}><Key size={18}/> Sertifika Yönetimi</button>
        <button onClick={() => setActiveTab('customIcons')} style={{padding:'10px 20px', borderRadius:'10px', border:'none', background: activeTab==='customIcons'?'var(--primary)':'transparent', color: activeTab==='customIcons'?'white':'#64748b', fontWeight:'700', cursor:'pointer', display:'flex', alignItems:'center', gap:'8px'}}><Activity size={18}/> İkon Yönetimi</button>
      </div>

      {activeTab === 'customIcons' && (
        <div className="icon-manager fade-in">
          <div style={{display:'grid', gridTemplateColumns:'400px 1fr', gap:'30px'}}>
            <div style={{background:'white', padding:'30px', borderRadius:'24px', border:'1px solid #e2e8f0', height:'fit-content'}}>
              <h4 style={{fontSize:'1.1rem', fontWeight:'800', marginBottom:'20px'}}>Yeni İkon Yükle</h4>
              <div style={{display:'grid', gap:'15px'}}>
                <div>
                  <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>İkon Adı</label>
                  <input type="text" value={newIcon.name} onChange={e => setNewIcon({...newIcon, name: e.target.value})} placeholder="Örn: Firewall-Red" style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} />
                </div>
                <div style={{padding:'20px', border:'2px dashed #e2e8f0', borderRadius:'20px', textAlign:'center'}}>
                  <input 
                    type="file" 
                    id="icon-up" 
                    accept="image/*" 
                    style={{display:'none'}} 
                    onChange={async (e) => {
                      const file = e.target.files[0];
                      if (!file) return;
                      const reader = new FileReader();
                      reader.onloadend = () => setNewIcon({...newIcon, data: reader.result});
                      reader.readAsDataURL(file);
                    }}
                  />
                  {newIcon.data ? (
                    <div style={{marginBottom:'15px'}}>
                      <img src={newIcon.data} alt="Preview" style={{width:'64px', height:'64px', objectFit:'contain', borderRadius:'8px'}} />
                    </div>
                  ) : (
                    <Activity size={40} style={{color:'#94a3b8', marginBottom:'10px'}}/>
                  )}
                  <label htmlFor="icon-up" style={{display:'block', background:'#f1f5f9', color:'#475569', padding:'8px 15px', borderRadius:'8px', fontSize:'13px', fontWeight:'700', cursor:'pointer'}}>Dosya Seç</label>
                </div>
                <button 
                  onClick={async () => {
                    if (!newIcon.name || !newIcon.data) return alert('İsim ve görsel gereklidir.');
                    try {
                      await axios.post(`${API_URL}/icons`, newIcon);
                      setNewIcon({ name: '', data: '' });
                      const res = await axios.get(`${API_URL}/icons`);
                      setCustomIcons(res.data);
                      alert('İkon yüklendi.');
                    } catch (e) { alert('Yükleme hatası!'); }

                  }}
                  style={{background:'var(--primary)', color:'white', border:'none', padding:'12px', borderRadius:'12px', fontWeight:'700', cursor:'pointer'}}
                >
                  İkonu Kaydet
                </button>
              </div>
            </div>

            <div style={{background:'white', borderRadius:'24px', border:'1px solid #e2e8f0', padding:'30px'}}>
              <h4 style={{fontSize:'1.1rem', fontWeight:'800', marginBottom:'20px'}}>Yüklü İkonlar</h4>
              <div style={{display:'grid', gridTemplateColumns:'repeat(auto-fill, minmax(120px, 1fr))', gap:'20px'}}>
                {customIcons.map((icon) => (
                  <div key={icon.id} style={{padding:'15px', border:'1px solid #f1f5f9', borderRadius:'15px', textAlign:'center', position:'relative'}} className="icon-card">
                    <img src={icon.data} alt={icon.name} style={{width:'48px', height:'48px', objectFit:'contain', marginBottom:'10px'}} />
                    <div style={{fontSize:'11px', fontWeight:'700', color:'#1e293b', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap'}}>{icon.name}</div>
                    <button 
                      onClick={async () => {
                        if (window.confirm('İkonu silmek istediğinize emin misiniz?')) {
                          await axios.delete(`${API_URL}/icons/${icon.id}`);
                          const res = await axios.get(`${API_URL}/icons`);
                          setCustomIcons(res.data);
                        }
                      }}
                      style={{position:'absolute', top:'-5px', right:'-5px', background:'#fee2e2', color:'#ef4444', border:'none', width:'24px', height:'24px', borderRadius:'50%', cursor:'pointer', display:'flex', alignItems:'center', justifyContent:'center'}}
                    >
                      <Trash2 size={12}/>
                    </button>
                  </div>
                ))}
                {customIcons.length === 0 && <div style={{gridColumn:'1/-1', textAlign:'center', color:'#94a3b8', padding:'40px'}}>Henüz ikon yüklenmedi.</div>}
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'apiTemplates' && (
        <div className="api-manager fade-in">
          <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'25px', gap:'15px'}}>
            <div>
              <h3 style={{margin:0, fontSize:'1.15rem', fontWeight:'800'}}>API Template Yönetimi</h3>
              <p style={{margin:0, fontSize:'13px', color:'#64748b'}}>Cihazlarla API üzerinden haberleşmek için kullanılacak URL ve Key şablonlarını yönetin.</p>
            </div>
            <button 
              onClick={() => {
                setEditingApiTemplate({ id: '' });
                setApiForm({ name: '', base_url: '', api_key: '', auth_type: 'Bearer' });
              }}
              style={{background:'var(--primary)', color:'white', border:'none', padding:'10px 20px', borderRadius:'12px', fontWeight:'700', cursor:'pointer', display:'flex', alignItems:'center', gap:'8px'}}
            >
              <Plus size={18}/> Yeni Template Ekle
            </button>
          </div>

          <div style={{background:'white', borderRadius:'24px', border:'1px solid #e2e8f0', overflow:'hidden', boxShadow:'0 4px 6px -1px rgba(0,0,0,0.05)'}}>
            <table style={{width:'100%', borderCollapse:'collapse'}}>
              <thead style={{background:'#f8fafc', borderBottom:'1px solid #e2e8f0'}}>
                <tr>
                  <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>TEMPLATE ADI</th>
                  <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>BASE URL</th>
                  <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>AUTH TÜRÜ</th>
                  <th style={{padding:'15px 25px', textAlign:'right', fontSize:'12px', color:'#64748b'}}>İŞLEMLER</th>
                </tr>
              </thead>
              <tbody>
                {apiTemplates.map((t) => (
                  <tr key={t.id} style={{borderBottom:'1px solid #f1f5f9'}}>
                    <td style={{padding:'15px 25px'}}><span style={{fontWeight:'700', color:'#1e293b'}}>{t.name}</span></td>
                    <td style={{padding:'15px 25px'}}><span style={{color:'#475569', fontSize:'13px'}}>{t.base_url}</span></td>
                    <td style={{padding:'15px 25px'}}><span style={{background:'#f1f5f9', color:'#475569', padding:'4px 10px', borderRadius:'8px', fontSize:'11px', fontWeight:'800'}}>{t.auth_type}</span></td>
                    <td style={{padding:'15px 25px', textAlign:'right'}}>
                      <button onClick={() => { setEditingApiTemplate(t); setApiForm(t); }} style={{padding:'6px 12px', borderRadius:'8px', border:'1px solid #e2e8f0', background:'white', fontSize:'12px', fontWeight:'700', cursor:'pointer', marginRight:'8px'}}>Düzenle</button>
                      <button onClick={() => handleDeleteApiTemplate(t.id)} style={{padding:'6px 12px', borderRadius:'8px', border:'1px solid #fee2e2', background:'#fef2f2', color:'#ef4444', fontSize:'12px', fontWeight:'700', cursor:'pointer'}}><Trash2 size={14}/></button>
                    </td>
                  </tr>
                ))}
                {apiTemplates.length === 0 && <tr><td colSpan="4" style={{padding:'40px', textAlign:'center', color:'#94a3b8'}}>Henüz bir API template tanımlanmadı.</td></tr>}
              </tbody>
            </table>
          </div>

          {editingApiTemplate && (
            <div className="modal-overlay" style={{position:'fixed', top:0, left:0, right:0, bottom:0, background:'rgba(15,23,42,0.6)', backdropFilter:'blur(4px)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:1000}}>
              <div style={{background:'white', width:'600px', maxWidth:'96vw', borderRadius:'24px', padding:'30px', boxShadow:'0 25px 50px -12px rgba(0,0,0,0.25)'}}>
                <h3 style={{marginBottom:'20px', fontSize:'1.25rem', fontWeight:'800'}}>{editingApiTemplate.id ? 'API Template Düzenle' : 'Yeni API Template'}</h3>
                <form onSubmit={handleSaveApiTemplate} style={{display:'grid', gap:'15px'}}>
                  <div>
                    <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Template Adı</label>
                    <input type="text" value={apiForm.name} onChange={e => setApiForm({...apiForm, name: e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required />
                  </div>
                  <div>
                    <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Base URL</label>
                    <input type="text" value={apiForm.base_url} onChange={e => setApiForm({...apiForm, base_url: e.target.value})} placeholder="https://fortigate.domain.com/api/v2" style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required />
                  </div>
                  <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'15px'}}>
                    <div>
                      <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Auth Türü</label>
                      <select value={apiForm.auth_type} onChange={e => setApiForm({...apiForm, auth_type: e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}}>
                        <option value="Bearer">Bearer Token</option>
                        <option value="ApiKey">API Key (X-API-KEY)</option>
                        <option value="Custom">Custom Header</option>
                      </select>
                    </div>
                    <div>
                      <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>API Key / Token</label>
                      <input type="password" value={apiForm.api_key} onChange={e => setApiForm({...apiForm, api_key: e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required />
                    </div>
                  </div>

                  <div style={{display:'flex', gap:'10px', justifyContent:'flex-end', marginTop:'10px'}}>
                    <button type="button" onClick={() => setEditingApiTemplate(null)} style={{padding:'12px 25px', borderRadius:'12px', border:'1px solid #e2e8f0', background:'white', cursor:'pointer'}}>İptal</button>
                    <button type="submit" style={{padding:'12px 35px', borderRadius:'12px', border:'none', background:'var(--primary)', color:'white', fontWeight:'700', cursor:'pointer'}}>Kaydet</button>
                  </div>
                </form>
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'sshTemplates' && (
        <div className="ssh-manager fade-in">
          <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'25px', gap:'15px'}}>
            <div>
              <h3 style={{margin:0, fontSize:'1.15rem', fontWeight:'800'}}>SSH Template Yönetimi</h3>
              <p style={{margin:0, fontSize:'13px', color:'#64748b'}}>Cihazlara bağlanmak için kullanılacak SSH kullanıcı adı ve şifre şablonlarını yönetin.</p>
            </div>
            <button 
              onClick={() => {
                setEditingSshTemplate({ id: '' });
                setSshForm({ name: '', username: '', password: '', port: 22 });
              }}
              style={{background:'var(--primary)', color:'white', border:'none', padding:'10px 20px', borderRadius:'12px', fontWeight:'700', cursor:'pointer', display:'flex', alignItems:'center', gap:'8px'}}
            >
              <Plus size={18}/> Yeni Template Ekle
            </button>
          </div>

          <div style={{background:'white', borderRadius:'24px', border:'1px solid #e2e8f0', overflow:'hidden', boxShadow:'0 4px 6px -1px rgba(0,0,0,0.05)'}}>
            <table style={{width:'100%', borderCollapse:'collapse'}}>
              <thead style={{background:'#f8fafc', borderBottom:'1px solid #e2e8f0'}}>
                <tr>
                  <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>TEMPLATE ADI</th>
                  <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>KULLANICI ADI</th>
                  <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>PORT</th>
                  <th style={{padding:'15px 25px', textAlign:'right', fontSize:'12px', color:'#64748b'}}>İŞLEMLER</th>
                </tr>
              </thead>
              <tbody>
                {sshTemplates.map((t) => (
                  <tr key={t.id} style={{borderBottom:'1px solid #f1f5f9'}}>
                    <td style={{padding:'15px 25px'}}><span style={{fontWeight:'700', color:'#1e293b'}}>{t.name}</span></td>
                    <td style={{padding:'15px 25px'}}><span style={{color:'#475569', fontSize:'13px'}}>{t.username}</span></td>
                    <td style={{padding:'15px 25px'}}><span style={{color:'#64748b', fontSize:'13px'}}>{t.port}</span></td>
                    <td style={{padding:'15px 25px', textAlign:'right'}}>
                      <button onClick={() => { setEditingSshTemplate(t); setSshForm(t); }} style={{padding:'6px 12px', borderRadius:'8px', border:'1px solid #e2e8f0', background:'white', fontSize:'12px', fontWeight:'700', cursor:'pointer', marginRight:'8px'}}>Düzenle</button>
                      <button onClick={() => handleDeleteSshTemplate(t.id)} style={{padding:'6px 12px', borderRadius:'8px', border:'1px solid #fee2e2', background:'#fef2f2', color:'#ef4444', fontSize:'12px', fontWeight:'700', cursor:'pointer'}}><Trash2 size={14}/></button>
                    </td>
                  </tr>
                ))}
                {sshTemplates.length === 0 && <tr><td colSpan="4" style={{padding:'40px', textAlign:'center', color:'#94a3b8'}}>Henüz bir SSH template tanımlanmadı.</td></tr>}
              </tbody>
            </table>
          </div>

          {editingSshTemplate && (
            <div className="modal-overlay" style={{position:'fixed', top:0, left:0, right:0, bottom:0, background:'rgba(15,23,42,0.6)', backdropFilter:'blur(4px)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:1000}}>
              <div style={{background:'white', width:'500px', maxWidth:'96vw', borderRadius:'24px', padding:'30px', boxShadow:'0 25px 50px -12px rgba(0,0,0,0.25)'}}>
                <h3 style={{marginBottom:'20px', fontSize:'1.25rem', fontWeight:'800'}}>{editingSshTemplate.id ? 'SSH Template Düzenle' : 'Yeni SSH Template'}</h3>
                <form onSubmit={handleSaveSshTemplate} style={{display:'grid', gap:'15px'}}>
                  <div>
                    <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Template Adı</label>
                    <input type="text" value={sshForm.name} onChange={e => setSshForm({...sshForm, name: e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required />
                  </div>
                  <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'15px'}}>
                    <div>
                      <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Kullanıcı Adı</label>
                      <input type="text" value={sshForm.username} onChange={e => setSshForm({...sshForm, username: e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required />
                    </div>
                    <div>
                      <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Port</label>
                      <input type="number" value={sshForm.port} onChange={e => setSshForm({...sshForm, port: e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required />
                    </div>
                  </div>
                  <div>
                    <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Şifre</label>
                    <input type="password" value={sshForm.password} onChange={e => setSshForm({...sshForm, password: e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required />
                  </div>

                  <div style={{display:'flex', gap:'10px', justifyContent:'flex-end', marginTop:'10px'}}>
                    <button type="button" onClick={() => setEditingSshTemplate(null)} style={{padding:'12px 25px', borderRadius:'12px', border:'1px solid #e2e8f0', background:'white', cursor:'pointer'}}>İptal</button>
                    <button type="submit" style={{padding:'12px 35px', borderRadius:'12px', border:'none', background:'var(--primary)', color:'white', fontWeight:'700', cursor:'pointer'}}>Kaydet</button>
                  </div>
                </form>
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'snmpTemplates' && (
        <div className="snmp-manager fade-in">
          <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'25px', gap:'15px'}}>
            <div>
              <h3 style={{margin:0, fontSize:'1.15rem', fontWeight:'800'}}>SNMP Template Yönetimi</h3>
              <p style={{margin:0, fontSize:'13px', color:'#64748b'}}>Cihazları izlemek için kullanılacak SNMP v1, v2c ve v3 şablonlarını yönetin.</p>
            </div>
            <button 
              onClick={() => {
                setEditingSnmpTemplate({ id: '' });
                setSnmpForm({
                  name: '', version: 'v2c', community: 'public',
                  security_name: '', security_level: 'noAuthNoPriv',
                  auth_protocol: 'SHA', auth_key: '',
                  priv_protocol: 'AES', priv_key: ''
                });
              }}
              style={{background:'var(--primary)', color:'white', border:'none', padding:'10px 20px', borderRadius:'12px', fontWeight:'700', cursor:'pointer', display:'flex', alignItems:'center', gap:'8px'}}
            >
              <Plus size={18}/> Yeni Template Ekle
            </button>
          </div>

          <div style={{background:'white', borderRadius:'24px', border:'1px solid #e2e8f0', overflow:'hidden', boxShadow:'0 4px 6px -1px rgba(0,0,0,0.05)'}}>
            <table style={{width:'100%', borderCollapse:'collapse'}}>
              <thead style={{background:'#f8fafc', borderBottom:'1px solid #e2e8f0'}}>
                <tr>
                  <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>TEMPLATE ADI</th>
                  <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>VERSİYON</th>
                  <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>DETAYLAR</th>
                  <th style={{padding:'15px 25px', textAlign:'right', fontSize:'12px', color:'#64748b'}}>İŞLEMLER</th>
                </tr>
              </thead>
              <tbody>
                {snmpTemplates.map((t) => (
                  <tr key={t.id} style={{borderBottom:'1px solid #f1f5f9'}}>
                    <td style={{padding:'15px 25px'}}><span style={{fontWeight:'700', color:'#1e293b'}}>{t.name}</span></td>
                    <td style={{padding:'15px 25px'}}><span style={{background:'#f1f5f9', color:'#475569', padding:'4px 10px', borderRadius:'8px', fontSize:'11px', fontWeight:'800'}}>{t.version}</span></td>
                    <td style={{padding:'15px 25px', fontSize:'12px', color:'#64748b'}}>
                      {t.version === 'v2c' ? `Community: ${t.community}` : `User: ${t.security_name}, Level: ${t.security_level}`}
                    </td>
                    <td style={{padding:'15px 25px', textAlign:'right'}}>
                      <button onClick={() => { setEditingSnmpTemplate(t); setSnmpForm(t); }} style={{padding:'6px 12px', borderRadius:'8px', border:'1px solid #e2e8f0', background:'white', fontSize:'12px', fontWeight:'700', cursor:'pointer', marginRight:'8px'}}>Düzenle</button>
                      <button onClick={() => handleDeleteSnmpTemplate(t.id)} style={{padding:'6px 12px', borderRadius:'8px', border:'1px solid #fee2e2', background:'#fef2f2', color:'#ef4444', fontSize:'12px', fontWeight:'700', cursor:'pointer'}}><Trash2 size={14}/></button>
                    </td>
                  </tr>
                ))}
                {snmpTemplates.length === 0 && <tr><td colSpan="4" style={{padding:'40px', textAlign:'center', color:'#94a3b8'}}>Henüz bir template tanımlanmadı.</td></tr>}
              </tbody>
            </table>
          </div>

          {editingSnmpTemplate && (
            <div className="modal-overlay" style={{position:'fixed', top:0, left:0, right:0, bottom:0, background:'rgba(15,23,42,0.6)', backdropFilter:'blur(4px)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:1000}}>
              <div style={{background:'white', width:'600px', maxWidth:'96vw', borderRadius:'24px', padding:'30px', boxShadow:'0 25px 50px -12px rgba(0,0,0,0.25)'}}>
                <h3 style={{marginBottom:'20px', fontSize:'1.25rem', fontWeight:'800'}}>{editingSnmpTemplate.id ? 'Template Düzenle' : 'Yeni SNMP Template'}</h3>
                <form onSubmit={handleSaveSnmpTemplate} style={{display:'grid', gap:'15px'}}>
                  <div>
                    <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Template Adı</label>
                    <input type="text" value={snmpForm.name} onChange={e => setSnmpForm({...snmpForm, name: e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required />
                  </div>
                  <div>
                    <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>SNMP Versiyon</label>
                    <select value={snmpForm.version} onChange={e => setSnmpForm({...snmpForm, version: e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}}>
                      <option value="v1">SNMP v1</option>
                      <option value="v2c">SNMP v2c</option>
                      <option value="v3">SNMP v3</option>
                    </select>
                  </div>

                  {snmpForm.version !== 'v3' ? (
                    <div>
                      <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Community String</label>
                      <input type="text" value={snmpForm.community} onChange={e => setSnmpForm({...snmpForm, community: e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} placeholder="public" />
                    </div>
                  ) : (
                    <>
                      <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'15px'}}>
                        <div>
                          <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Security Name (User)</label>
                          <input type="text" value={snmpForm.security_name} onChange={e => setSnmpForm({...snmpForm, security_name: e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} />
                        </div>
                        <div>
                          <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Security Level</label>
                          <select value={snmpForm.security_level} onChange={e => setSnmpForm({...snmpForm, security_level: e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}}>
                            <option value="noAuthNoPriv">noAuthNoPriv</option>
                            <option value="authNoPriv">authNoPriv</option>
                            <option value="authPriv">authPriv</option>
                          </select>
                        </div>
                      </div>
                      
                      {snmpForm.security_level !== 'noAuthNoPriv' && (
                        <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'15px'}}>
                          <div>
                            <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Auth Protocol</label>
                            <select value={snmpForm.auth_protocol} onChange={e => setSnmpForm({...snmpForm, auth_protocol: e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}}>
                              <option value="MD5">MD5</option>
                              <option value="SHA">SHA</option>
                              <option value="SHA256">SHA256</option>
                            </select>
                          </div>
                          <div>
                            <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Auth Key</label>
                            <input type="password" value={snmpForm.auth_key} onChange={e => setSnmpForm({...snmpForm, auth_key: e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} />
                          </div>
                        </div>
                      )}

                      {snmpForm.security_level === 'authPriv' && (
                        <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'15px'}}>
                          <div>
                            <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Priv Protocol</label>
                            <select value={snmpForm.priv_protocol} onChange={e => setSnmpForm({...snmpForm, priv_protocol: e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}}>
                              <option value="DES">DES</option>
                              <option value="AES">AES</option>
                              <option value="AES256">AES256</option>
                            </select>
                          </div>
                          <div>
                            <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Priv Key</label>
                            <input type="password" value={snmpForm.priv_key} onChange={e => setSnmpForm({...snmpForm, priv_key: e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} />
                          </div>
                        </div>
                      )}
                    </>
                  )}

                  <div style={{display:'flex', gap:'10px', justifyContent:'flex-end', marginTop:'10px'}}>
                    <button type="button" onClick={() => setEditingSnmpTemplate(null)} style={{padding:'12px 25px', borderRadius:'12px', border:'1px solid #e2e8f0', background:'white', cursor:'pointer'}}>İptal</button>
                    <button type="submit" style={{padding:'12px 35px', borderRadius:'12px', border:'none', background:'var(--primary)', color:'white', fontWeight:'700', cursor:'pointer'}}>Kaydet</button>
                  </div>
                </form>
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'cveDb' && (
        <div style={{display:'grid', gap:'20px'}}>
          <div style={{background:'white', border:'1px solid #e2e8f0', borderRadius:'16px', padding:'20px'}}>
            <h3 style={{margin:'0 0 10px', fontSize:'1.1rem', fontWeight:'800'}}>Otomatik CVE Tarama Ayari</h3>
            <p style={{margin:'0 0 15px', fontSize:'13px', color:'#64748b'}}>Secilen sure backend tarafinda kaydedilir ve internet geldikce otomatik cekim bu aralikta yapilir.</p>
            <form onSubmit={handleSaveCveSyncConfig} style={{display:'flex', gap:'10px', alignItems:'center', flexWrap:'wrap'}}>
              <select
                value={cveSyncConfig.interval_minutes}
                onChange={(e) => setCveSyncConfig({ interval_minutes: Number(e.target.value) })}
                style={{padding:'10px 12px', borderRadius:'10px', border:'1px solid #e2e8f0', background:'white'}}
              >
                {SYNC_INTERVAL_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </select>
              <button type="submit" style={{background:'var(--primary)', color:'white', border:'none', padding:'10px 16px', borderRadius:'10px', fontWeight:'700', cursor:'pointer'}}>Süreyi Kaydet</button>
            </form>
          </div>

          <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', gap:'10px', flexWrap:'wrap'}}>
            <h3 style={{margin:0, fontSize:'1.1rem', fontWeight:'800'}}>CVE Kaynak Listesi</h3>
            <button
              onClick={() => setEditingSource({ name: '', url: '', fetch_method: 'generic_rss', keyword: 'fortinet', enabled: true })}
              style={{background:'var(--primary)', color:'white', border:'none', padding:'10px 16px', borderRadius:'10px', fontWeight:'700', cursor:'pointer', display:'inline-flex', alignItems:'center', gap:'8px'}}
            >
              <Plus size={16} /> Kaynak Ekle
            </button>
          </div>

          <div style={{background:'white', borderRadius:'16px', border:'1px solid #e2e8f0', overflow:'hidden'}}>
            <table style={{width:'100%', borderCollapse:'collapse'}}>
              <thead style={{background:'#f8fafc', borderBottom:'1px solid #e2e8f0'}}>
                <tr>
                  <th style={{padding:'12px 16px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>Kaynak</th>
                  <th style={{padding:'12px 16px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>Veri Cekme Yontemi</th>
                  <th style={{padding:'12px 16px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>Anahtar Kelime</th>
                  <th style={{padding:'12px 16px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>Durum</th>
                  <th style={{padding:'12px 16px', textAlign:'right', fontSize:'12px', color:'#64748b'}}>Islemler</th>
                </tr>
              </thead>
              <tbody>
                {cveSources.map((src) => (
                  <tr key={src.id} style={{borderBottom:'1px solid #f1f5f9'}}>
                    <td style={{padding:'12px 16px'}}>
                      <div style={{fontWeight:'700', color:'#1e293b'}}>{src.name}</div>
                      <div style={{fontSize:'12px', color:'#64748b', maxWidth:'500px', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap'}}>{src.url}</div>
                    </td>
                    <td style={{padding:'12px 16px', fontSize:'12px'}}>{src.fetch_method}</td>
                    <td style={{padding:'12px 16px', fontSize:'12px'}}>{src.keyword || '-'}</td>
                    <td style={{padding:'12px 16px'}}>
                      <span style={{fontSize:'11px', fontWeight:'700', padding:'4px 8px', borderRadius:'999px', background:src.enabled ? '#dcfce7' : '#fee2e2', color:src.enabled ? '#166534' : '#991b1b'}}>{src.enabled ? 'AKTIF' : 'PASIF'}</span>
                    </td>
                    <td style={{padding:'12px 16px', textAlign:'right'}}>
                      <button onClick={() => setEditingSource(src)} style={{padding:'6px 10px', borderRadius:'8px', border:'1px solid #e2e8f0', background:'white', fontSize:'12px', fontWeight:'700', cursor:'pointer', marginRight:'8px'}}>Duzenle</button>
                      <button onClick={() => handleDeleteCveSource(src.id)} style={{padding:'6px 10px', borderRadius:'8px', border:'1px solid #fee2e2', background:'#fef2f2', color:'#ef4444', fontSize:'12px', fontWeight:'700', cursor:'pointer'}}>Sil</button>
                    </td>
                  </tr>
                ))}
                {cveSources.length === 0 && <tr><td colSpan="5" style={{padding:'24px', textAlign:'center', color:'#64748b'}}>Kayitli CVE kaynagi yok.</td></tr>}
              </tbody>
            </table>
          </div>

          {editingSource && (
            <div className="modal-overlay" style={{position:'fixed', top:0, left:0, right:0, bottom:0, background:'rgba(15,23,42,0.6)', backdropFilter:'blur(4px)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:1000}}>
              <div style={{background:'white', width:'700px', maxWidth:'96vw', borderRadius:'20px', padding:'24px'}}>
                <h3 style={{margin:'0 0 16px', fontSize:'1.15rem', fontWeight:'800'}}>{editingSource.id ? 'CVE Kaynagini Duzenle' : 'Yeni CVE Kaynagi Ekle'}</h3>
                <form onSubmit={handleSaveCveSource} style={{display:'grid', gap:'12px'}}>
                  <div><label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Kaynak Adi</label><input type="text" value={editingSource.name || ''} onChange={(e) => setEditingSource({ ...editingSource, name: e.target.value })} style={{width:'100%', padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required /></div>
                  <div><label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Kaynak URL</label><input type="url" value={editingSource.url || ''} onChange={(e) => setEditingSource({ ...editingSource, url: e.target.value })} style={{width:'100%', padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required /></div>
                  <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'10px'}}>
                    <div>
                      <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Veri Cekme Yontemi</label>
                      <select value={editingSource.fetch_method || 'generic_rss'} onChange={(e) => setEditingSource({ ...editingSource, fetch_method: e.target.value })} style={{width:'100%', padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}}>
                        <option value="fortiguard_rss">FortiGuard RSS</option>
                        <option value="nvd_api">NVD API</option>
                        <option value="cisa_kev_json">CISA KEV JSON</option>
                        <option value="zdi_rss">ZDI RSS</option>
                        <option value="generic_rss">Genel RSS</option>
                        <option value="generic_json">Genel JSON API</option>
                      </select>
                    </div>
                    <div><label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Filtre Anahtar Kelime</label><input type="text" value={editingSource.keyword || ''} onChange={(e) => setEditingSource({ ...editingSource, keyword: e.target.value })} style={{width:'100%', padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}} placeholder="fortinet" /></div>
                  </div>
                  <label style={{display:'flex', alignItems:'center', gap:'8px', fontSize:'13px', color:'#334155'}}>
                    <input type="checkbox" checked={editingSource.enabled !== false} onChange={(e) => setEditingSource({ ...editingSource, enabled: e.target.checked })} />
                    Kaynak aktif olsun
                  </label>
                  <div style={{display:'flex', justifyContent:'flex-end', gap:'8px', marginTop:'8px'}}>
                    <button type="button" onClick={() => setEditingSource(null)} style={{padding:'10px 14px', borderRadius:'10px', border:'1px solid #e2e8f0', background:'white', cursor:'pointer'}}>Iptal</button>
                    <button type="submit" style={{padding:'10px 14px', borderRadius:'10px', border:'none', background:'var(--primary)', color:'white', fontWeight:'700', cursor:'pointer'}}>Kaydet</button>
                  </div>
                </form>
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'kb' && (
        <div className="kb-manager">
          <div style={{display:'flex', justifyContent:'space-between', marginBottom:'20px', gap:'15px'}}>
            <div style={{display:'flex', gap:'10px', flex:1}}>
              <div style={{position:'relative', flex:1}}>
                <Search size={18} style={{position:'absolute', left:'12px', top:'50%', transform:'translateY(-50%)', color:'#94a3b8'}}/>
                <input type="text" placeholder="Kural Ara (ID veya İsim)..." value={searchKB} onChange={(e)=>setSearchKB(e.target.value)} style={{width:'100%', padding:'10px 40px', borderRadius:'12px', border:'1px solid #e2e8f0', outline:'none'}} />
              </div>
              <select value={categoryFilter} onChange={(e)=>setCategoryFilter(e.target.value)} style={{padding:'10px', borderRadius:'12px', border:'1px solid #e2e8f0', background:'white'}}>
                <option value="all">Tüm Kategoriler</option>
                <option value="CIS">CIS</option>
                <option value="STIG">STIG</option>
                <option value="BP">Best Practice</option>
              </select>
            </div>
            <button onClick={() => setEditingRule({ id: '', name: '', category: 'BP', severity: 'MEDIUM', check_logic: '', remediation: '', cli_path: '', eval_path: '', eval_type: 'equal', eval_expected: '', recommendation_details: '', reference_urls: '' })} style={{background:'var(--primary)', color:'white', border:'none', padding:'10px 20px', borderRadius:'12px', fontWeight:'700', cursor:'pointer', display:'flex', alignItems:'center', gap:'8px'}}><Plus size={18}/> Yeni Kural Ekle</button>
          </div>

          {editingRule && (
            <div className="modal-overlay" style={{position:'fixed', top:0, left:0, right:0, bottom:0, background:'rgba(15,23,42,0.6)', backdropFilter:'blur(4px)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:1000}}>
              <div style={{background:'white', width:'800px', maxHeight:'90vh', overflowY:'auto', borderRadius:'24px', padding:'30px', boxShadow:'0 25px 50px -12px rgba(0,0,0,0.25)'}}>
                <h3 style={{marginBottom:'20px', fontSize:'1.25rem', fontWeight:'800'}}>{editingRule.created_at ? 'Kuralı Düzenle' : 'Yeni Kural Tanımla'}</h3>
                <form onSubmit={handleSaveRule} style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'20px'}}>
                  <div><label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>KURAL ID</label><input type="text" value={editingRule.id} onChange={e=>setEditingRule({...editingRule, id:e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required /></div>
                  <div><label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>KURAL ADI</label><input type="text" value={editingRule.name} onChange={e=>setEditingRule({...editingRule, name:e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required /></div>
                  <div><label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>KATEGORİ</label><select value={editingRule.category} onChange={e=>setEditingRule({...editingRule, category:e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}}><option value="CIS">CIS</option><option value="STIG">STIG</option><option value="BP">Best Practice</option></select></div>
                  <div><label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>SEVERITY</label><select value={editingRule.severity} onChange={e=>setEditingRule({...editingRule, severity:e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}}><option value="LOW">LOW</option><option value="MEDIUM">MEDIUM</option><option value="HIGH">HIGH</option><option value="CRITICAL">CRITICAL</option></select></div>
                  <div style={{gridColumn:'1/3'}}><label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>KONTROL MANTIĞI (AÇIKLAMA)</label><textarea value={editingRule.check_logic} onChange={e=>setEditingRule({...editingRule, check_logic:e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0', minHeight:'80px'}} /></div>
                  <div style={{gridColumn:'1/3'}}><label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>ÇÖZÜM / REMEDIATION (CLI)</label><textarea value={editingRule.remediation} onChange={e=>setEditingRule({...editingRule, remediation:e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0', minHeight:'80px', fontFamily:'monospace'}} /></div>
                  <div style={{gridColumn:'1/3'}}>
                    <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>FORTINET ÇÖZÜM ADIMLARI (HER SATIR BİR ADIM)</label>
                    <textarea
                      value={editingRule.recommendation_details || ''}
                      onChange={e=>setEditingRule({...editingRule, recommendation_details:e.target.value})}
                      placeholder={'1) FortiGate arayuzunde ilgili menuye gidin\n2) Beklenen ayari aktif edin\n3) Dogrulamayi test edin'}
                      style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0', minHeight:'90px'}}
                    />
                  </div>
                  <div style={{gridColumn:'1/3'}}>
                    <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>REFERANS LINKLERI (HER SATIR BIR URL)</label>
                    <textarea
                      value={editingRule.reference_urls || ''}
                      onChange={e=>setEditingRule({...editingRule, reference_urls:e.target.value})}
                      placeholder={'https://docs.fortinet.com/...\nhttps://www.cisecurity.org/...'}
                      style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0', minHeight:'90px'}}
                    />
                  </div>
                  
                  <div style={{gridColumn:'1/3', background:'#f8fafc', padding:'15px', borderRadius:'15px', border:'1px solid #e2e8f0'}}>
                    <h4 style={{fontSize:'13px', marginBottom:'15px', color:'#1e293b'}}>OTOMATİK ANALİZ PARAMETRELERİ</h4>
                    <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'15px'}}>
                      <div><label style={{fontSize:'11px', color:'#64748b'}}>CLI PATH</label><input type="text" value={editingRule.cli_path} onChange={e=>setEditingRule({...editingRule, cli_path:e.target.value})} placeholder="system global" style={{width:'100%', padding:'10px', borderRadius:'8px', border:'1px solid #e2e8f0'}} /></div>
                      <div><label style={{fontSize:'11px', color:'#64748b'}}>EVAL PATH</label><input type="text" value={editingRule.eval_path} onChange={e=>setEditingRule({...editingRule, eval_path:e.target.value})} placeholder="system_global.admintimeout" style={{width:'100%', padding:'10px', borderRadius:'8px', border:'1px solid #e2e8f0'}} /></div>
                      <div><label style={{fontSize:'11px', color:'#64748b'}}>EVAL TYPE</label><select value={editingRule.eval_type} onChange={e=>setEditingRule({...editingRule, eval_type:e.target.value})} style={{width:'100%', padding:'10px', borderRadius:'8px', border:'1px solid #e2e8f0'}}><option value="equal">Equal</option><option value="max_num">Max Number</option><option value="min_num">Min Number</option><option value="not_contains">Not Contains</option></select></div>
                      <div><label style={{fontSize:'11px', color:'#64748b'}}>EXPECTED VALUE</label><input type="text" value={editingRule.eval_expected} onChange={e=>setEditingRule({...editingRule, eval_expected:e.target.value})} style={{width:'100%', padding:'10px', borderRadius:'8px', border:'1px solid #e2e8f0'}} /></div>
                    </div>
                  </div>

                  <div style={{gridColumn:'1/3', display:'flex', gap:'10px', justifyContent:'flex-end', marginTop:'10px'}}>
                    <button type="button" onClick={()=>setEditingRule(null)} style={{padding:'12px 25px', borderRadius:'12px', border:'1px solid #e2e8f0', background:'white', cursor:'pointer'}}>İptal</button>
                    <button type="submit" style={{padding:'12px 35px', borderRadius:'12px', border:'none', background:'var(--primary)', color:'white', fontWeight:'700', cursor:'pointer'}}>Değişiklikleri Kaydet</button>
                  </div>
                </form>
              </div>
            </div>
          )}

          <div style={{background:'white', borderRadius:'24px', border:'1px solid #e2e8f0', overflow:'hidden'}}>
            <table style={{width:'100%', borderCollapse:'collapse'}}>
              <thead style={{background:'#f8fafc', borderBottom:'1px solid #e2e8f0'}}>
                <tr>
                  <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>KURAL ID</th>
                  <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>KATEGORİ</th>
                  <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>KURAL ADI / AÇIKLAMA</th>
                  <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>SEVERITY</th>
                  <th style={{padding:'15px 25px', textAlign:'right', fontSize:'12px', color:'#64748b'}}>İŞLEMLER</th>
                </tr>
              </thead>
              <tbody>
                {filteredKB.map((r) => (
                  <tr key={r.id} style={{borderBottom:'1px solid #f1f5f9'}}>
                    <td style={{padding:'15px 25px'}}><span style={{fontWeight:'700', color:'#1e293b', fontSize:'13px'}}>{r.id}</span></td>
                    <td style={{padding:'15px 25px'}}><span style={{background: r.category==='STIG'?'#fef2f2':r.category==='CIS'?'#eff6ff':'#f0fdf4', color: r.category==='STIG'?'#ef4444':r.category==='CIS'?'#3b82f6':'#10b981', padding:'2px 8px', borderRadius:'6px', fontSize:'11px', fontWeight:'800'}}>{r.category}</span></td>
                    <td style={{padding:'15px 25px'}}>
                      <div style={{fontWeight:'700', color:'#1e293b', fontSize:'14px', marginBottom:'4px'}}>{r.name}</div>
                      <div style={{fontSize:'12px', color:'#64748b', whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis', maxWidth:'400px'}}>{r.check_logic}</div>
                      <div style={{display:'flex', gap:'8px', marginTop:'8px', flexWrap:'wrap'}}>
                        {countListItems(r.recommendation_details) > 0 && (
                          <span style={{display:'inline-flex', alignItems:'center', gap:'4px', background:'#eff6ff', color:'#1d4ed8', padding:'2px 8px', borderRadius:'999px', fontSize:'11px', fontWeight:'700'}}>
                            <FileText size={12} /> {countListItems(r.recommendation_details)} adim
                          </span>
                        )}
                        {countListItems(r.reference_urls) > 0 && (
                          <span style={{display:'inline-flex', alignItems:'center', gap:'4px', background:'#ecfeff', color:'#0e7490', padding:'2px 8px', borderRadius:'999px', fontSize:'11px', fontWeight:'700'}}>
                            <Globe size={12} /> {countListItems(r.reference_urls)} referans
                          </span>
                        )}
                      </div>
                    </td>
                    <td style={{padding:'15px 25px'}}><span className={`severity-pill sev-${r.severity.toLowerCase()}`} style={{fontSize:'10px', padding:'2px 8px'}}>{r.severity}</span></td>
                    <td style={{padding:'15px 25px', textAlign:'right'}}>
                      <button onClick={()=>setEditingRule(prepareRuleForEdit(r))} style={{padding:'6px 12px', borderRadius:'8px', border:'1px solid #e2e8f0', background:'white', fontSize:'12px', fontWeight:'700', cursor:'pointer', marginRight:'8px'}}>Düzenle</button>
                      <button onClick={()=>handleDeleteRule(r.id)} style={{padding:'6px 12px', borderRadius:'8px', border:'1px solid #fee2e2', background:'#fef2f2', color:'#ef4444', fontSize:'12px', fontWeight:'700', cursor:'pointer'}}><Trash2 size={14}/></button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === 'switchKb' && (
        <div className="kb-manager">
          <div style={{display:'flex', justifyContent:'space-between', marginBottom:'20px', gap:'15px'}}>
            <div style={{display:'flex', gap:'10px', flex:1}}>
              <div style={{position:'relative', flex:1}}>
                <Search size={18} style={{position:'absolute', left:'12px', top:'50%', transform:'translateY(-50%)', color:'#94a3b8'}}/>
                <input type="text" placeholder="Switch Kural Ara (ID veya İsim)..." value={searchKB} onChange={(e)=>setSearchKB(e.target.value)} style={{width:'100%', padding:'10px 40px', borderRadius:'12px', border:'1px solid #e2e8f0', outline:'none'}} />
              </div>
              <select value={categoryFilter} onChange={(e)=>setCategoryFilter(e.target.value)} style={{padding:'10px', borderRadius:'12px', border:'1px solid #e2e8f0', background:'white'}}>
                <option value="all">Tüm Kategoriler</option>
                <option value="CIS">CIS</option>
                <option value="STIG">STIG</option>
                <option value="BP">Best Practice</option>
              </select>
            </div>
            <button onClick={() => setEditingSwitchRule({ id: '', name: '', switch_vendor: 'cisco', switch_model: 'all', category: 'BP', severity: 'MEDIUM', check_logic: '', remediation: '', cli_path: '', eval_path: '', eval_type: 'equal', eval_expected: '', recommendation_details: '', reference_urls: '' })} style={{background:'var(--primary)', color:'white', border:'none', padding:'10px 20px', borderRadius:'12px', fontWeight:'700', cursor:'pointer', display:'flex', alignItems:'center', gap:'8px'}}><Plus size={18}/> Yeni Switch Kuralı</button>
          </div>

          {editingSwitchRule && (
            <div className="modal-overlay" style={{position:'fixed', top:0, left:0, right:0, bottom:0, background:'rgba(15,23,42,0.6)', backdropFilter:'blur(4px)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:1000}}>
              <div style={{background:'white', width:'800px', maxHeight:'90vh', overflowY:'auto', borderRadius:'24px', padding:'30px', boxShadow:'0 25px 50px -12px rgba(0,0,0,0.25)'}}>
                <h3 style={{marginBottom:'20px', fontSize:'1.25rem', fontWeight:'800'}}>{editingSwitchRule.created_at ? 'Switch Kuralını Düzenle' : 'Yeni Switch Kuralı Tanımla'}</h3>
                <form onSubmit={handleSaveSwitchRule} style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'20px'}}>
                  <div><label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>KURAL ID</label><input type="text" value={editingSwitchRule.id} onChange={e=>setEditingSwitchRule({...editingSwitchRule, id:e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required /></div>
                  <div><label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>KURAL ADI</label><input type="text" value={editingSwitchRule.name} onChange={e=>setEditingSwitchRule({...editingSwitchRule, name:e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required /></div>
                  <div><label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>SWITCH VENDOR</label>
                    <select 
                      value={editingSwitchRule.switch_vendor || 'cisco'} 
                      onChange={e=>setEditingSwitchRule({...editingSwitchRule, switch_vendor:e.target.value})} 
                      style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}}
                    >
                      <option value="cisco">Cisco</option>
                      <option value="arista">Arista</option>
                      <option value="huawei">Huawei</option>
                    </select>
                  </div>
                  <div><label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>SWITCH MODEL</label><input type="text" value={editingSwitchRule.switch_model || 'all'} onChange={e=>setEditingSwitchRule({...editingSwitchRule, switch_model:e.target.value})} placeholder="catalyst-9300" style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} /></div>
                  <div><label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>KATEGORİ</label><select value={editingSwitchRule.category} onChange={e=>setEditingSwitchRule({...editingSwitchRule, category:e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}}><option value="CIS">CIS</option><option value="STIG">STIG</option><option value="BP">Best Practice</option></select></div>
                  <div><label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>SEVERITY</label><select value={editingSwitchRule.severity} onChange={e=>setEditingSwitchRule({...editingSwitchRule, severity:e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}}><option value="LOW">LOW</option><option value="MEDIUM">MEDIUM</option><option value="HIGH">HIGH</option><option value="CRITICAL">CRITICAL</option></select></div>
                  <div style={{gridColumn:'1/3'}}><label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>KONTROL MANTIĞI (AÇIKLAMA)</label><textarea value={editingSwitchRule.check_logic} onChange={e=>setEditingSwitchRule({...editingSwitchRule, check_logic:e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0', minHeight:'80px'}} /></div>
                  <div style={{gridColumn:'1/3'}}><label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>ÇÖZÜM / REMEDIATION (CLI)</label><textarea value={editingSwitchRule.remediation} onChange={e=>setEditingSwitchRule({...editingSwitchRule, remediation:e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0', minHeight:'80px', fontFamily:'monospace'}} /></div>
                  <div style={{gridColumn:'1/3'}}>
                    <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>SWITCH ÇÖZÜM ADIMLARI (HER SATIR BİR ADIM)</label>
                    <textarea
                      value={editingSwitchRule.recommendation_details || ''}
                      onChange={e=>setEditingSwitchRule({...editingSwitchRule, recommendation_details:e.target.value})}
                      placeholder={'1) Switch arayuzunde ilgili menuye gidin\n2) Beklenen ayari aktif edin\n3) Dogrulamayi test edin'}
                      style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0', minHeight:'90px'}}
                    />
                  </div>
                  <div style={{gridColumn:'1/3'}}>
                    <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>REFERANS LINKLERI (HER SATIR BIR URL)</label>
                    <textarea
                      value={editingSwitchRule.reference_urls || ''}
                      onChange={e=>setEditingSwitchRule({...editingSwitchRule, reference_urls:e.target.value})}
                      placeholder={'https://docs.vendor.com/...\nhttps://www.cisecurity.org/...'}
                      style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0', minHeight:'90px'}}
                    />
                  </div>

                  <div style={{gridColumn:'1/3', background:'#f8fafc', padding:'15px', borderRadius:'15px', border:'1px solid #e2e8f0'}}>
                    <h4 style={{fontSize:'13px', marginBottom:'15px', color:'#1e293b'}}>OTOMATİK ANALİZ PARAMETRELERİ</h4>
                    <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'15px'}}>
                      <div><label style={{fontSize:'11px', color:'#64748b'}}>CLI PATH</label><input type="text" value={editingSwitchRule.cli_path} onChange={e=>setEditingSwitchRule({...editingSwitchRule, cli_path:e.target.value})} placeholder="management" style={{width:'100%', padding:'10px', borderRadius:'8px', border:'1px solid #e2e8f0'}} /></div>
                      <div><label style={{fontSize:'11px', color:'#64748b'}}>EVAL PATH</label><input type="text" value={editingSwitchRule.eval_path} onChange={e=>setEditingSwitchRule({...editingSwitchRule, eval_path:e.target.value})} placeholder="management.idle-timeout" style={{width:'100%', padding:'10px', borderRadius:'8px', border:'1px solid #e2e8f0'}} /></div>
                      <div><label style={{fontSize:'11px', color:'#64748b'}}>EVAL TYPE</label><select value={editingSwitchRule.eval_type} onChange={e=>setEditingSwitchRule({...editingSwitchRule, eval_type:e.target.value})} style={{width:'100%', padding:'10px', borderRadius:'8px', border:'1px solid #e2e8f0'}}><option value="equal">Equal</option><option value="max_num">Max Number</option><option value="min_num">Min Number</option><option value="not_contains">Not Contains</option></select></div>
                      <div><label style={{fontSize:'11px', color:'#64748b'}}>EXPECTED VALUE</label><input type="text" value={editingSwitchRule.eval_expected} onChange={e=>setEditingSwitchRule({...editingSwitchRule, eval_expected:e.target.value})} style={{width:'100%', padding:'10px', borderRadius:'8px', border:'1px solid #e2e8f0'}} /></div>
                    </div>
                  </div>

                  <div style={{gridColumn:'1/3', display:'flex', gap:'10px', justifyContent:'flex-end', marginTop:'10px'}}>
                    <button type="button" onClick={()=>setEditingSwitchRule(null)} style={{padding:'12px 25px', borderRadius:'12px', border:'1px solid #e2e8f0', background:'white', cursor:'pointer'}}>İptal</button>
                    <button type="submit" style={{padding:'12px 35px', borderRadius:'12px', border:'none', background:'var(--primary)', color:'white', fontWeight:'700', cursor:'pointer'}}>Değişiklikleri Kaydet</button>
                  </div>
                </form>
              </div>
            </div>
          )}

          <div style={{background:'white', borderRadius:'24px', border:'1px solid #e2e8f0', overflow:'hidden'}}>
            <table style={{width:'100%', borderCollapse:'collapse'}}>
              <thead style={{background:'#f8fafc', borderBottom:'1px solid #e2e8f0'}}>
                <tr>
                  <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>KURAL ID</th>
                  <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>KATEGORİ</th>
                  <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>KURAL ADI / AÇIKLAMA</th>
                  <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>SEVERITY</th>
                  <th style={{padding:'15px 25px', textAlign:'right', fontSize:'12px', color:'#64748b'}}>İŞLEMLER</th>
                </tr>
              </thead>
              <tbody>
                {filteredSwitchKB.map((r) => (
                  <tr key={`${r.id}-${r.switch_vendor || 'generic'}-${r.switch_model || 'all'}`} style={{borderBottom:'1px solid #f1f5f9'}}>
                    <td style={{padding:'15px 25px'}}><span style={{fontWeight:'700', color:'#1e293b', fontSize:'13px'}}>{r.id}</span></td>
                    <td style={{padding:'15px 25px'}}><span style={{background: r.category==='STIG'?'#fef2f2':r.category==='CIS'?'#eff6ff':'#f0fdf4', color: r.category==='STIG'?'#ef4444':r.category==='CIS'?'#3b82f6':'#10b981', padding:'2px 8px', borderRadius:'6px', fontSize:'11px', fontWeight:'800'}}>{r.category}</span></td>
                    <td style={{padding:'15px 25px'}}>
                      <div style={{fontWeight:'700', color:'#1e293b', fontSize:'14px', marginBottom:'4px'}}>{r.name}</div>
                      <div style={{fontSize:'12px', color:'#64748b', whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis', maxWidth:'400px'}}>{r.check_logic}</div>
                      <div style={{fontSize:'11px', color:'#475569', marginTop:'6px'}}>Vendor: {r.switch_vendor || 'cisco'} | Model: {r.switch_model || 'all'}</div>
                      <div style={{display:'flex', gap:'8px', marginTop:'8px', flexWrap:'wrap'}}>
                        {countListItems(r.recommendation_details) > 0 && (
                          <span style={{display:'inline-flex', alignItems:'center', gap:'4px', background:'#eff6ff', color:'#1d4ed8', padding:'2px 8px', borderRadius:'999px', fontSize:'11px', fontWeight:'700'}}>
                            <FileText size={12} /> {countListItems(r.recommendation_details)} adim
                          </span>
                        )}
                        {countListItems(r.reference_urls) > 0 && (
                          <span style={{display:'inline-flex', alignItems:'center', gap:'4px', background:'#ecfeff', color:'#0e7490', padding:'2px 8px', borderRadius:'999px', fontSize:'11px', fontWeight:'700'}}>
                            <Globe size={12} /> {countListItems(r.reference_urls)} referans
                          </span>
                        )}
                      </div>
                    </td>
                    <td style={{padding:'15px 25px'}}><span className={`severity-pill sev-${r.severity.toLowerCase()}`} style={{fontSize:'10px', padding:'2px 8px'}}>{r.severity}</span></td>
                    <td style={{padding:'15px 25px', textAlign:'right'}}>
                      <button onClick={()=>setEditingSwitchRule(prepareRuleForEdit(r))} style={{padding:'6px 12px', borderRadius:'8px', border:'1px solid #e2e8f0', background:'white', fontSize:'12px', fontWeight:'700', cursor:'pointer', marginRight:'8px'}}>Düzenle</button>
                      <button onClick={()=>handleDeleteSwitchRule(r.id, r.switch_vendor || 'cisco', r.switch_model || 'all')} style={{padding:'6px 12px', borderRadius:'8px', border:'1px solid #fee2e2', background:'#fef2f2', color:'#ef4444', fontSize:'12px', fontWeight:'700', cursor:'pointer'}}><Trash2 size={14}/></button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === 'ldap' && (
        <div style={{maxWidth:'600px', background:'white', padding:'40px', borderRadius:'24px', border:'1px solid #e2e8f0'}}>
          <div style={{display:'flex', alignItems:'center', gap:'15px', marginBottom:'30px'}}>
            <div style={{background:'#eff6ff', color:'#3b82f6', padding:'12px', borderRadius:'14px'}}><Globe size={24}/></div>
            <div><h3 style={{margin:0, fontSize:'1.25rem', fontWeight:'800'}}>LDAP Ayarları</h3><p style={{margin:0, fontSize:'13px', color:'#64748b'}}>Kullanıcı kimlik doğrulama için AD/LDAP sunucusu bağlayın</p></div>
          </div>
          <form onSubmit={handleSaveLdap} style={{display:'grid', gap:'20px'}}>
            <div><label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Sunucu Adresi (IP/FQDN)</label><input type="text" value={ldapConfig.host} onChange={e=>setLdapConfig({...ldapConfig, host:e.target.value})} placeholder="10.0.0.5" style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} /></div>
            <div><label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Port</label><input type="number" value={ldapConfig.port} onChange={e=>setLdapConfig({...ldapConfig, port:e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} /></div>
            <div><label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Base DN</label><input type="text" value={ldapConfig.baseDN} onChange={e=>setLdapConfig({...ldapConfig, baseDN:e.target.value})} placeholder="DC=nss,DC=local" style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} /></div>
            <div><label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Bind User (DN)</label><input type="text" value={ldapConfig.user} onChange={e=>setLdapConfig({...ldapConfig, user:e.target.value})} placeholder="CN=Admin,OU=Users,DC=nss,DC=local" style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} /></div>
            <div><label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Şifre</label><input type="password" value={ldapConfig.pass} onChange={e=>setLdapConfig({...ldapConfig, pass:e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} /></div>
            <button type="submit" style={{marginTop:'10px', background:'var(--primary)', color:'white', border:'none', padding:'15px', borderRadius:'12px', fontWeight:'700', cursor:'pointer', display:'flex', alignItems:'center', justifyContent:'center', gap:'10px'}}><Save size={18}/> Bağlantıyı Kaydet</button>
          </form>
        </div>
      )}

      {activeTab === 'certs' && (
        <div style={{display:'grid', gridTemplateColumns:'400px 1fr', gap:'30px'}}>
          <div style={{background:'white', padding:'30px', borderRadius:'24px', border:'1px solid #e2e8f0', height:'fit-content'}}>
            <h4 style={{fontSize:'1.1rem', fontWeight:'800', marginBottom:'20px'}}>Sertifika Yükle</h4>
            <div style={{padding:'30px', border:'2px dashed #e2e8f0', borderRadius:'20px', textAlign:'center'}}>
              <Activity size={40} style={{color:'#94a3b8', marginBottom:'15px'}}/>
              <p style={{fontSize:'13px', color:'#64748b', marginBottom:'20px'}}>Sertifika dosyasını (.crt, .pem) sürükleyin veya seçin</p>
              <input type="file" id="cert-up" style={{display:'none'}} />
              <label htmlFor="cert-up" style={{background:'var(--primary)', color:'white', padding:'10px 20px', borderRadius:'10px', fontWeight:'700', cursor:'pointer'}}>Dosya Seç</label>
            </div>
          </div>
          <div style={{background:'white', borderRadius:'24px', border:'1px solid #e2e8f0', padding:'30px'}}>
            <h4 style={{fontSize:'1.1rem', fontWeight:'800', marginBottom:'20px'}}>Yüklü Sertifikalar</h4>
            <div style={{display:'grid', gap:'15px'}}>
              {certs.map((c, i) => (
                <div key={i} style={{padding:'15px', border:'1px solid #f1f5f9', borderRadius:'15px', display:'flex', alignItems:'center', gap:'15px'}}>
                  <div style={{background:'#fef3c7', color:'#d97706', padding:'10px', borderRadius:'12px'}}><Key size={20}/></div>
                  <div style={{flex:1}}>
                    <div style={{fontWeight:'700', color:'#1e293b'}}>{c.name}</div>
                    <div style={{fontSize:'11px', color:'#94a3b8'}}>{c.type} • {new Date(c.uploaded_at).toLocaleDateString()}</div>
                  </div>
                  <button style={{padding:'6px', borderRadius:'8px', border:'1px solid #fee2e2', background:'#fef2f2', color:'#ef4444', cursor:'pointer'}}><Trash2 size={16}/></button>
                </div>
              ))}
              {certs.length === 0 && <div style={{textAlign:'center', color:'#94a3b8', padding:'40px'}}>Henüz sertifika yüklenmedi</div>}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001/api';
const APP_VERSION = 'v1.0.4-stable';

// --- Health Indicators Component ---
const HealthIndicators = () => {
  const [status, setStatus] = useState({ backend: 'checking', db: 'checking' });

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await axios.get(`${API_URL}/health`);
        setStatus({
          backend: res.data.status === 'OK' ? 'online' : 'error',
          db: res.data.database === 'connected' ? 'online' : 'error'
        });
      } catch (err) {
        setStatus({ backend: 'error', db: 'error' });
      }
    };
    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="health-status-container">
      <div className="health-item">
        <div className={`h-dot ${status.backend === 'online' ? 'green' : status.backend === 'checking' ? 'yellow' : 'red'}`}></div>
        <span>Backend: {status.backend === 'online' ? 'Aktif' : status.backend === 'checking' ? 'Bağlanıyor...' : 'Hata'}</span>
      </div>
      <div className="health-item">
        <div className={`h-dot ${status.db === 'online' ? 'green' : status.db === 'checking' ? 'yellow' : 'red'}`}></div>
        <span>Veritabanı: {status.db === 'online' ? 'Bağlı' : status.db === 'checking' ? 'Bağlanıyor...' : 'Hata'}</span>
      </div>
    </div>
  );
};

// --- Loading Component ---
const CircularLoader = ({ progress }) => {
  const radius = 90;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (progress / 100) * circumference;

  return (
    <div className="analysis-overlay fade-in">
      <div className="circular-loader-wrapper">
        <svg width="200" height="200">
          <circle className="circular-bg" cx="100" cy="100" r={radius} />
          <circle 
            className="circular-progress" 
            cx="100" cy="100" r={radius} 
            strokeDasharray={circumference}
            strokeDashoffset={offset}
          />
        </svg>
        <div className="percentage-text">{Math.round(progress)}%</div>
      </div>
      <div className="loader-status">
        <h2>Sistem Analiz Ediliyor</h2>
        <p>{progress < 30 ? 'Dosya ayrıştırılıyor...' : progress < 70 ? 'STIG & CIS kuralları denetleniyor...' : 'Rapor oluşturuluyor...'}</p>
      </div>
    </div>
  );
};

// --- Modern Compliance Card ---
const ComplianceAlert = ({ finding }) => {
  const sevClass = finding.severity?.toLowerCase() === 'high' ? 'sev-high' : 
                   finding.severity?.toLowerCase() === 'medium' ? 'sev-medium' : 'sev-low';
  const recommendationSteps = Array.isArray(finding.recommendation_details)
    ? finding.recommendation_details
    : [];
  const referenceUrls = Array.isArray(finding.reference_urls)
    ? finding.reference_urls
    : [];
  
  return (
    <div className="compliance-card fade-in">
      <div className="card-header-main">
        <div style={{display:'flex', alignItems:'center', gap:'10px'}}>
          <Shield size={18} style={{color: finding.severity?.toLowerCase() === 'high' ? '#ef4444' : '#f59e0b'}}/>
          <span style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>ID: {finding.id}</span>
        </div>
        <span className={`severity-pill ${sevClass}`}>{finding.severity}</span>
      </div>
      <div className="card-content-area">
        <h4 className="finding-name">{finding.name}</h4>
        <div className="grid-details">
          <div className="detail-item">
            <label>Mevcut Durum</label>
            <p style={{color:'#ef4444', fontWeight:'700'}}>{finding.actual_value || 'Hatalı Yapılandırma'}</p>
          </div>
          <div className="detail-item">
            <label>Kontrol Mantığı</label>
            <p>{finding.check_logic}</p>
          </div>
        </div>
        {finding.remediation && (
          <div className="remediation-box">
            <h6><Terminal size={14}/> DÜZELTME KOMUTLARI (CLI)</h6>
            <pre>{finding.remediation}</pre>
          </div>
        )}
        {recommendationSteps.length > 0 && (
          <div className="remediation-box" style={{marginTop:'10px'}}>
            <h6><Info size={14}/> FORTINET COZUM ADIMLARI</h6>
            <ol style={{margin:'8px 0 0 18px', padding:0, display:'grid', gap:'6px'}}>
              {recommendationSteps.map((step, idx) => (
                <li key={`${finding.id}-step-${idx}`} style={{fontSize:'13px', color:'#334155'}}>{step}</li>
              ))}
            </ol>
          </div>
        )}
        {referenceUrls.length > 0 && (
          <div className="remediation-box" style={{marginTop:'10px'}}>
            <h6><FileText size={14}/> REFERANSLAR</h6>
            <div style={{display:'grid', gap:'6px', marginTop:'8px'}}>
              {referenceUrls.map((url, idx) => (
                <a key={`${finding.id}-ref-${idx}`} href={url} target="_blank" rel="noreferrer" style={{fontSize:'12px', color:'#2563eb', textDecoration:'underline'}}>{url}</a>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

const RiskAlert = ({ risk, type }) => {
  const [isOpen, setIsOpen] = useState(false);
  const Icon = type === 'critical' ? Lock : AlertTriangle;
  if (!risk) return null;
  return (
    <div className={`risk-alert ${type} ${isOpen ? 'is-open' : 'is-closed'}`} onClick={(e) => { e.stopPropagation(); setIsOpen(!isOpen); }} style={{cursor: 'pointer', marginBottom: '10px', background:'white', border:'1px solid #e2e8f0', borderRadius:'12px'}}>
      <div className="alert-head" style={{padding:'15px'}}>
         <Icon size={20} />
         <h5 style={{fontSize:'14px', fontWeight:'700'}}>{risk.title || 'Güvenlik Bulgusu'}</h5>
         <div className="alert-actions-meta">
           <span className="sev-tag" style={{fontSize:'10px', padding:'2px 8px'}}>{risk.severity || (type === 'critical' ? 'CRITICAL' : 'HIGH')}</span>
         </div>
      </div>
      {isOpen && (
        <div className="alert-body fade-in" style={{padding:'0 15px 15px', borderTop:'1px solid #f1f5f9', paddingTop:'15px'}}>
          <p className="impact-text" style={{fontSize:'13px'}}><strong>Bulgu:</strong> {risk.impact}</p>
          {risk.steps && <div className="remediation" style={{marginTop:'10px', fontSize:'12px'}}><strong>Çözüm:</strong> {risk.steps[0]}</div>}
        </div>
      )}
    </div>
  );
};

const AnalysisCard = ({ finding }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const data = finding.policy_data || {};
  
  const highlight = (val) => {
    if (!val) return '';
    const v = String(val).toLowerCase();
    return (v === 'all' || v === 'any') ? 'highlight-danger' : '';
  };

  const renderValue = (val) => Array.isArray(val) ? val.map((v, i) => <span key={i} className={`value-tag ${highlight(v)}`}>{v}</span>) : <span className={`value-tag ${highlight(val)}`}>{val}</span>;

  return (
    <div className={`analysis-detail-card ${isExpanded ? 'is-expanded' : ''}`} onClick={() => setIsExpanded(!isExpanded)}>
      <div className="analysis-card-header">
        <div className="policy-meta">
          <span className="policy-id">ID: {finding.policy_id}</span>
          <span className="vdom-tag">{finding.vdom}</span>
          <h4 className="policy-name">{finding.name}</h4>
        </div>
        <div className="expand-icon"><ChevronRight size={20} /></div>
      </div>
      
      {isExpanded && (
        <div className="analysis-card-body fade-in">
          <div className="policy-details-grid">
            <div className="detail-col">
              <label>Kaynak (Source)</label>
              <div className="detail-box">
                <div className="sub-detail"><span>Interface:</span> {renderValue(data.srcintf)}</div>
                <div className="sub-detail"><span>Adresler:</span> <div className="tags-container">{renderValue(data.srcaddr)}</div></div>
              </div>
            </div>
            <div className="detail-col">
              <label>Hedef (Destination)</label>
              <div className="detail-box">
                <div className="sub-detail"><span>Interface:</span> {renderValue(data.dstintf)}</div>
                <div className="sub-detail"><span>Adresler:</span> <div className="tags-container">{renderValue(data.dstaddr)}</div></div>
              </div>
            </div>
            <div className="detail-col full-width">
              <label>Servis & Protokol</label>
              <div className="detail-box">
                <div className="sub-detail"><span>Hizmetler:</span> <div className="tags-container">{renderValue(data.service)}</div></div>
              </div>
            </div>
          </div>
          
          <div className="risks-section">
            <label>Tespit Edilen Riskler</label>
            {finding.risks.map((r, i) => <RiskAlert key={i} risk={r} type="high" />)}
          </div>
        </div>
      )}
    </div>
  );
};

const ProfileDetectionCard = ({ finding }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const profiles = finding.profiles || {};

  const getStatus = (val, type) => {
    const v = String(val).toLowerCase();
    const isMissing = v.includes('no-') || v === 'disable' || v === 'none';
    return {
      label: isMissing ? 'EKSİK' : val,
      className: isMissing ? 'prof-status-missing' : 'prof-status-active',
      isMissing
    };
  };

  const profileTypes = [
    { key: 'ips', label: 'IPS', icon: <Shield size={16}/> },
    { key: 'av', label: 'AntiVirus', icon: <Activity size={16}/> },
    { key: 'webfilter', label: 'Web Filter', icon: <Search size={16}/> },
    { key: 'appctrl', label: 'App Control', icon: <Cpu size={16}/> },
    { key: 'ssl', label: 'SSL Inspection', icon: <Lock size={16}/> }
  ];

  return (
    <div className={`analysis-detail-card ${isExpanded ? 'is-expanded' : ''}`} onClick={() => setIsExpanded(!isExpanded)}>
      <div className="analysis-card-header">
        <div className="policy-meta">
          <span className="policy-id">ID: {finding.policy_id}</span>
          <span className="vdom-tag">{finding.vdom}</span>
          <h4 className="policy-name">{finding.name}</h4>
        </div>
        <div className="expand-icon"><ChevronRight size={20} /></div>
      </div>
      
      <div className="profile-summary-bar" style={{padding:'0 1.5rem 1.25rem', display:'flex', gap:'10px', flexWrap:'wrap'}}>
        {profileTypes.map(pt => {
          const status = getStatus(profiles[pt.key], pt.key);
          return (
            <div key={pt.key} className={`profile-pill-mini ${status.className}`}>
              {pt.icon}
              <span>{pt.label}: {status.label}</span>
            </div>
          );
        })}
      </div>

      {isExpanded && (
        <div className="analysis-card-body fade-in">
          <div className="risks-section" style={{marginTop:0}}>
            <label>Eksik Güvenlik Katmanları</label>
            {finding.risks.map((r, i) => <RiskAlert key={i} risk={r} type="critical" />)}
          </div>
        </div>
      )}
    </div>
  );
};

const InteractionChart = ({ interactions }) => {
  if (!interactions || interactions.length === 0) return null;
  const maxCount = Math.max(...interactions.map(i => i.count));
  
  return (
    <div className="interaction-visualizer">
      <div className="chart-container">
        {interactions.slice(0, 10).map((item, i) => {
          const percentage = (item.count / maxCount) * 100;
          return (
            <div key={i} className="chart-row">
              <div className="row-labels">
                <span className="label-src">{item.src}</span>
                <ArrowRight size={12} className="label-arrow" />
                <span className="label-dst">{item.dst}</span>
              </div>
              <div className="row-bar-wrapper">
                <div className="bar-bg">
                  <div 
                    className="bar-fill" 
                    style={{ 
                      width: `${percentage}%`,
                      background: `linear-gradient(90deg, var(--primary) 0%, ${item.count > 10 ? '#ef4444' : '#818cf8'} 100%)`
                    }}
                  >
                    <span className="bar-count">{item.count}</span>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

// --- Device Tracker View ---
const DeviceTracker = ({ API_URL }) => {
  const [devices, setDevices] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [isTemplateModalOpen, setIsTemplateModalOpen] = useState(false);
  const [isDeviceModalOpen, setIsDeviceModalOpen] = useState(false);
  const [editingTemplate, setEditingTemplate] = useState(null);
  const [editingDevice, setEditingDevice] = useState(null);
  const [isTracking, setIsTracking] = useState(false);

  const [templateForm, setTemplateForm] = useState({
    name: '', version: 'v2c', community: 'public',
    security_name: '', security_level: 'noAuthNoPriv',
    auth_protocol: 'SHA', auth_key: '',
    priv_protocol: 'AES', priv_key: ''
  });

  const [deviceForm, setDeviceForm] = useState({
    ip_address: '', snmp_template_id: '',
    use_manual: false
  });

  const [manualSnmp, setManualSnmp] = useState({
    version: 'v2c', community: 'public',
    security_name: '', security_level: 'noAuthNoPriv',
    auth_protocol: 'SHA', auth_key: '',
    priv_protocol: 'AES', priv_key: ''
  });

  const fetchTemplates = async () => {
    try {
      const res = await axios.get(`${API_URL}/snmp-templates`);
      setTemplates(res.data);
    } catch (e) { console.error(e); }
  };

  const fetchDevices = async () => {
    try {
      const res = await axios.get(`${API_URL}/devices?snmp=true`);
      setDevices(res.data);
    } catch (e) { console.error(e); }
  };

  const startTracking = async () => {
    setIsTracking(true);
    try {
      await axios.get(`${API_URL}/devices/snmp-track`);
      await fetchDevices();
    } catch (e) { console.error(e); }
    finally { setIsTracking(false); }
  };

  useEffect(() => {
    fetchTemplates();
    fetchDevices();
    startTracking();
    const interval = setInterval(startTracking, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleSaveTemplate = async (e) => {
    e.preventDefault();
    try {
      if (editingTemplate) {
        await axios.put(`${API_URL}/snmp-templates/${editingTemplate.id}`, templateForm);
      } else {
        await axios.post(`${API_URL}/snmp-templates`, templateForm);
      }
      setIsTemplateModalOpen(false);
      setEditingTemplate(null);
      fetchTemplates();
    } catch (e) { alert('Hata!'); }
  };

  const handleSaveDevice = async (e) => {
    e.preventDefault();
    const payload = {
      ...deviceForm,
      manual_snmp_config: deviceForm.use_manual ? manualSnmp : null
    };
    try {
      if (editingDevice) {
        await axios.put(`${API_URL}/devices/${editingDevice.id}`, payload);
      } else {
        await axios.post(`${API_URL}/devices`, payload);
      }
      setIsDeviceModalOpen(false);
      setEditingDevice(null);
      fetchDevices();
    } catch (e) {
      const msg = e?.response?.data?.error || 'Cihaz ekleme/guncelleme hatasi!';
      const details = e?.response?.data?.details ? `\n\nDetay: ${e.response.data.details}` : '';
      alert(`${msg}${details}`);
    }
  };

  return (
    <div className="device-tracker-view fade-in">
      <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'30px'}}>
        <div>
          <h3 style={{fontSize:'1.25rem', fontWeight:'800'}}>Cihaz Takip Sistemi</h3>
          <p style={{fontSize:'13px', color:'#64748b'}}>Cihazlarınızı SNMP üzerinden canlı olarak izleyin ve durumlarını takip edin.</p>
        </div>
        <div style={{display:'flex', gap:'10px'}}>
          <button 
            onClick={() => { setEditingTemplate(null); setTemplateForm({ name: '', version: 'v2c', community: 'public', security_name: '', security_level: 'noAuthNoPriv', auth_protocol: 'SHA', auth_key: '', priv_protocol: 'AES', priv_key: '' }); setIsTemplateModalOpen(true); }}
            style={{background:'white', color:'var(--primary)', border:'1px solid var(--primary)', padding:'10px 20px', borderRadius:'12px', fontWeight:'700', cursor:'pointer', display:'flex', alignItems:'center', gap:'8px'}}
          >
            <SettingsIcon size={18} /> SNMP Template Yönetimi
          </button>
          <button 
            onClick={() => { setEditingDevice(null); setDeviceForm({ ip_address: '', snmp_template_id: '', use_manual: false }); setIsDeviceModalOpen(true); }}
            style={{background:'var(--primary)', color:'white', border:'none', padding:'10px 20px', borderRadius:'12px', fontWeight:'700', cursor:'pointer', display:'flex', alignItems:'center', gap:'8px'}}
          >
            <Plus size={18} /> Cihaz Ekle
          </button>
        </div>
      </div>

      <div style={{background:'white', borderRadius:'24px', border:'1px solid #e2e8f0', overflow:'hidden', boxShadow:'0 10px 15px -3px rgba(0,0,0,0.05)'}}>
        <table style={{width:'100%', borderCollapse:'collapse'}}>
          <thead style={{background:'#f8fafc', borderBottom:'1px solid #e2e8f0'}}>
            <tr>
              <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>CIHAZ ADI</th>
              <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>IP ADRESİ</th>
              <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>SNMP TEMPLATE</th>
              <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>SİSTEM ADI (SNMP)</th>
              <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>DURUM</th>
              <th style={{padding:'15px 25px', textAlign:'right', fontSize:'12px', color:'#64748b'}}>İŞLEMLER</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.id} style={{borderBottom:'1px solid #f1f5f9'}}>
                <td style={{padding:'15px 25px'}}><div style={{fontWeight:'700', color:'#1e293b'}}>{d.name}</div></td>
                <td style={{padding:'15px 25px'}}><div style={{fontSize:'13px', color:'#475569'}}>{d.ip_address}</div></td>
                <td style={{padding:'15px 25px'}}><div style={{fontSize:'12px', color:'#64748b'}}>{d.template_name || (d.manual_snmp_config ? 'Manuel SNMP' : '-')}</div></td>
                <td style={{padding:'15px 25px'}}><div style={{fontSize:'12px', color:'#475569'}}>{d.metadata?.sysName || '-'}</div></td>
                <td style={{padding:'15px 25px'}}>
                  <span style={{fontSize:'11px', fontWeight:'700', padding:'4px 10px', borderRadius:'999px', background: d.status==='online' ? '#dcfce7' : '#fee2e2', color: d.status==='online' ? '#166534' : '#991b1b', display:'inline-flex', alignItems:'center', gap:'5px'}}>
                    <div style={{width:'6px', height:'6px', borderRadius:'50%', background: d.status==='online' ? '#10b981' : '#ef4444'}}></div>
                    {d.status === 'online' ? 'Çevrimiçi' : 'Erişilemiyor'}
                  </span>
                </td>
                <td style={{padding:'15px 25px', textAlign:'right'}}>
                   <button onClick={() => { setEditingDevice(d); setDeviceForm({ ip_address: d.ip_address, snmp_template_id: d.snmp_template_id || '', use_manual: !!d.manual_snmp_config }); if(d.manual_snmp_config) setManualSnmp(d.manual_snmp_config); setIsDeviceModalOpen(true); }} style={{padding:'6px 10px', borderRadius:'8px', border:'1px solid #e2e8f0', background:'white', fontSize:'12px', fontWeight:'700', cursor:'pointer', marginRight:'8px'}}>Düzenle</button>
                   <button onClick={async () => { if(window.confirm('Cihazı silmek istediğinize emin misiniz?')) { await axios.delete(`${API_URL}/devices/${d.id}`); fetchDevices(); } }} style={{padding:'6px 10px', borderRadius:'8px', border:'1px solid #fee2e2', background:'#fef2f2', color:'#ef4444', fontSize:'12px', fontWeight:'700', cursor:'pointer'}}><Trash2 size={14}/></button>
                </td>
              </tr>
            ))}
            {devices.length === 0 && <tr><td colSpan="6" style={{padding:'40px', textAlign:'center', color:'#64748b'}}>Henüz bir cihaz eklenmedi.</td></tr>}
          </tbody>
        </table>
      </div>

      {/* Template Modal */}
      {isTemplateModalOpen && (
        <div className="modal-overlay" style={{position:'fixed', top:0, left:0, right:0, bottom:0, background:'rgba(15,23,42,0.6)', backdropFilter:'blur(4px)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:1000}}>
          <div style={{background:'white', width:'900px', maxWidth:'96vw', borderRadius:'24px', padding:'30px', maxHeight:'90vh', overflowY:'auto'}}>
            <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'20px'}}>
              <h3 style={{margin:0, fontSize:'1.25rem', fontWeight:'800'}}>SNMP Template Yönetimi</h3>
              <button onClick={() => setIsTemplateModalOpen(false)} style={{background:'none', border:'none', cursor:'pointer', color:'#64748b'}}><X size={24}/></button>
            </div>
            
            <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'30px'}}>
              {/* Left Side: Template List */}
              <div style={{borderRight:'1px solid #e2e8f0', paddingRight:'30px'}}>
                <h4 style={{fontSize:'14px', fontWeight:'800', color:'#1e293b', marginBottom:'15px'}}>Kayıtlı Templateler</h4>
                <div style={{display:'grid', gap:'10px'}}>
                  {templates.map(t => (
                    <div key={t.id} style={{padding:'12px', borderRadius:'12px', border:'1px solid #e2e8f0', display:'flex', justifyContent:'space-between', alignItems:'center'}}>
                      <div>
                        <div style={{fontWeight:'700', fontSize:'14px'}}>{t.name}</div>
                        <div style={{fontSize:'12px', color:'#64748b'}}>{t.version}</div>
                      </div>
                      <div style={{display:'flex', gap:'5px'}}>
                        <button onClick={() => { setEditingTemplate(t); setTemplateForm(t); }} style={{padding:'5px', borderRadius:'6px', border:'1px solid #e2e8f0', background:'white', cursor:'pointer'}}><SettingsIcon size={14}/></button>
                        <button onClick={async () => { if(window.confirm('Silinsin mi?')) { await axios.delete(`${API_URL}/snmp-templates/${t.id}`); fetchTemplates(); } }} style={{padding:'5px', borderRadius:'6px', border:'1px solid #fee2e2', background:'#fef2f2', color:'#ef4444', cursor:'pointer'}}><Trash2 size={14}/></button>
                      </div>
                    </div>
                  ))}
                  {templates.length === 0 && <p style={{fontSize:'13px', color:'#94a3b8', textAlign:'center'}}>Template yok.</p>}
                </div>
              </div>

              {/* Right Side: Add/Edit Form */}
              <form onSubmit={handleSaveTemplate} style={{display:'grid', gap:'15px'}}>
                <h4 style={{fontSize:'14px', fontWeight:'800', color:'#1e293b', marginBottom:'5px'}}>{editingTemplate ? 'Template Düzenle' : 'Yeni Template Ekle'}</h4>
                <div>
                  <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Template Adı</label>
                  <input type="text" value={templateForm.name} onChange={e => setTemplateForm({...templateForm, name: e.target.value})} style={{width:'100%', padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required />
                </div>
                <div>
                  <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>SNMP Versiyon</label>
                  <select value={templateForm.version} onChange={e => setTemplateForm({...templateForm, version: e.target.value})} style={{width:'100%', padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}}>
                    <option value="v2c">SNMP v2c</option>
                    <option value="v3">SNMP v3</option>
                  </select>
                </div>

                {templateForm.version === 'v2c' ? (
                  <div>
                    <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Community String</label>
                    <input type="text" value={templateForm.community} onChange={e => setTemplateForm({...templateForm, community: e.target.value})} style={{width:'100%', padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}} />
                  </div>
                ) : (
                  <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'10px'}}>
                    <div style={{gridColumn:'1/3'}}>
                      <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Security Name (User)</label>
                      <input type="text" value={templateForm.security_name} onChange={e => setTemplateForm({...templateForm, security_name: e.target.value})} style={{width:'100%', padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}} />
                    </div>
                    <div>
                      <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Security Level</label>
                      <select value={templateForm.security_level} onChange={e => setTemplateForm({...templateForm, security_level: e.target.value})} style={{width:'100%', padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}}>
                        <option value="noAuthNoPriv">noAuthNoPriv</option>
                        <option value="authNoPriv">authNoPriv</option>
                        <option value="authPriv">authPriv</option>
                      </select>
                    </div>
                    {templateForm.security_level !== 'noAuthNoPriv' && (
                      <>
                        <div>
                          <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Auth Protocol</label>
                          <select value={templateForm.auth_protocol} onChange={e => setTemplateForm({...templateForm, auth_protocol: e.target.value})} style={{width:'100%', padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}}>
                            <option value="MD5">MD5</option>
                            <option value="SHA">SHA (SHA1)</option>
                            <option value="SHA224">SHA224</option>
                            <option value="SHA256">SHA256</option>
                            <option value="SHA384">SHA384</option>
                            <option value="SHA512">SHA512</option>
                          </select>
                        </div>
                        <div style={{gridColumn:'1/3'}}>
                          <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Auth Key</label>
                          <input type="password" value={templateForm.auth_key} onChange={e => setTemplateForm({...templateForm, auth_key: e.target.value})} style={{width:'100%', padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}} />
                        </div>
                      </>
                    )}
                    {templateForm.security_level === 'authPriv' && (
                      <>
                        <div>
                          <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Priv Protocol</label>
                          <select value={templateForm.priv_protocol} onChange={e => setTemplateForm({...templateForm, priv_protocol: e.target.value})} style={{width:'100%', padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}}>
                            <option value="DES">DES</option>
                            <option value="AES">AES (AES128)</option>
                            <option value="AES192">AES192</option>
                            <option value="AES256">AES256</option>
                          </select>
                        </div>
                        <div style={{gridColumn:'1/3'}}>
                          <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Priv Key</label>
                          <input type="password" value={templateForm.priv_key} onChange={e => setTemplateForm({...templateForm, priv_key: e.target.value})} style={{width:'100%', padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}} />
                        </div>
                      </>
                    )}
                  </div>
                )}
                <div style={{display:'flex', gap:'10px', marginTop:'10px'}}>
                  <button type="submit" style={{flex:1, background:'var(--primary)', color:'white', border:'none', padding:'12px', borderRadius:'12px', fontWeight:'700', cursor:'pointer'}}>Template Kaydet</button>
                  {editingTemplate && <button type="button" onClick={() => setEditingTemplate(null)} style={{background:'#f1f5f9', color:'#64748b', border:'none', padding:'12px', borderRadius:'12px', fontWeight:'700', cursor:'pointer'}}>Vazgeç</button>}
                  <button type="button" onClick={() => setIsTemplateModalOpen(false)} style={{background:'#f1f5f9', color:'#1e293b', border:'1px solid #e2e8f0', padding:'12px', borderRadius:'12px', fontWeight:'700', cursor:'pointer'}}>Kapat</button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Device Modal */}
      {isDeviceModalOpen && (
        <div className="modal-overlay" style={{position:'fixed', top:0, left:0, right:0, bottom:0, background:'rgba(15,23,42,0.6)', backdropFilter:'blur(4px)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:1000}}>
          <div style={{background:'white', width:'600px', maxWidth:'96vw', borderRadius:'24px', padding:'30px'}}>
            <h3 style={{margin:'0 0 20px', fontSize:'1.25rem', fontWeight:'800'}}>{editingDevice ? 'Cihaz Düzenle' : 'Yeni Cihaz Ekle'}</h3>
            {!editingDevice && <p style={{fontSize:'12px', color:'#64748b', marginTop:'-10px', marginBottom:'16px'}}>Cihaz adı SNMP canlı veriden (sysName) otomatik alınır.</p>}
            <form onSubmit={handleSaveDevice} style={{display:'grid', gap:'15px'}}>
              <div>
                <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>IP Adresi</label>
                <input type="text" value={deviceForm.ip_address} onChange={e => setDeviceForm({...deviceForm, ip_address: e.target.value})} style={{width:'100%', padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}} placeholder="192.168.1.1" required />
              </div>
              
              <div style={{padding:'15px', background:'#f8fafc', borderRadius:'15px', border:'1px solid #e2e8f0'}}>
                <label style={{display:'flex', alignItems:'center', gap:'8px', fontSize:'13px', fontWeight:'700', color:'#1e293b', marginBottom:'10px'}}>
                  <input type="checkbox" checked={deviceForm.use_manual} onChange={e => setDeviceForm({...deviceForm, use_manual: e.target.checked})} />
                  Manuel SNMP Bilgisi Gir
                </label>

                {!deviceForm.use_manual ? (
                  <div>
                    <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>SNMP Template Seçin</label>
                    <select value={deviceForm.snmp_template_id} onChange={e => setDeviceForm({...deviceForm, snmp_template_id: e.target.value})} style={{width:'100%', padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}}>
                      <option value="">Seçiniz...</option>
                      {templates.map(t => <option key={t.id} value={t.id}>{t.name} ({t.version})</option>)}
                    </select>
                  </div>
                ) : (
                  <div style={{display:'grid', gap:'10px'}}>
                    <div style={{display:'flex', gap:'10px'}}>
                      <div style={{flex:1}}>
                        <label style={{fontSize:'11px', fontWeight:'700', color:'#64748b'}}>Versiyon</label>
                        <select value={manualSnmp.version} onChange={e => setManualSnmp({...manualSnmp, version: e.target.value})} style={{width:'100%', padding:'8px', borderRadius:'8px', border:'1px solid #e2e8f0'}}>
                          <option value="v2c">v2c</option>
                          <option value="v3">v3</option>
                        </select>
                      </div>
                      {manualSnmp.version === 'v2c' && (
                        <div style={{flex:2}}>
                          <label style={{fontSize:'11px', fontWeight:'700', color:'#64748b'}}>Community</label>
                          <input type="text" value={manualSnmp.community} onChange={e => setManualSnmp({...manualSnmp, community: e.target.value})} style={{width:'100%', padding:'8px', borderRadius:'8px', border:'1px solid #e2e8f0'}} />
                        </div>
                      )}
                    </div>
                    {manualSnmp.version === 'v3' && (
                      <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'8px'}}>
                        <div style={{gridColumn:'1/3'}}>
                          <label style={{fontSize:'11px', fontWeight:'700', color:'#64748b'}}>User / Security Name</label>
                          <input type="text" value={manualSnmp.security_name} onChange={e => setManualSnmp({...manualSnmp, security_name: e.target.value})} style={{width:'100%', padding:'8px', borderRadius:'8px', border:'1px solid #e2e8f0'}} />
                        </div>
                        <div>
                          <label style={{fontSize:'11px', fontWeight:'700', color:'#64748b'}}>Security Level</label>
                          <select value={manualSnmp.security_level} onChange={e => setManualSnmp({...manualSnmp, security_level: e.target.value})} style={{width:'100%', padding:'8px', borderRadius:'8px', border:'1px solid #e2e8f0'}}>
                            <option value="noAuthNoPriv">noAuthNoPriv</option>
                            <option value="authNoPriv">authNoPriv</option>
                            <option value="authPriv">authPriv</option>
                          </select>
                        </div>
                        
                        {(manualSnmp.security_level === 'authNoPriv' || manualSnmp.security_level === 'authPriv') && (
                          <>
                            <div>
                              <label style={{fontSize:'11px', fontWeight:'700', color:'#64748b'}}>Auth Protocol</label>
                              <select value={manualSnmp.auth_protocol} onChange={e => setManualSnmp({...manualSnmp, auth_protocol: e.target.value})} style={{width:'100%', padding:'8px', borderRadius:'8px', border:'1px solid #e2e8f0'}}>
                                <option value="MD5">MD5</option>
                                <option value="SHA">SHA (SHA1)</option>
                                <option value="SHA224">SHA224</option>
                                <option value="SHA256">SHA256</option>
                                <option value="SHA384">SHA384</option>
                                <option value="SHA512">SHA512</option>
                              </select>
                            </div>
                            <div>
                              <label style={{fontSize:'11px', fontWeight:'700', color:'#64748b'}}>Auth Key</label>
                              <input type="password" value={manualSnmp.auth_key} onChange={e => setManualSnmp({...manualSnmp, auth_key: e.target.value})} style={{width:'100%', padding:'8px', borderRadius:'8px', border:'1px solid #e2e8f0'}} />
                            </div>
                          </>
                        )}

                        {manualSnmp.security_level === 'authPriv' && (
                          <>
                            <div>
                              <label style={{fontSize:'11px', fontWeight:'700', color:'#64748b'}}>Privacy Protocol</label>
                              <select value={manualSnmp.priv_protocol} onChange={e => setManualSnmp({...manualSnmp, priv_protocol: e.target.value})} style={{width:'100%', padding:'8px', borderRadius:'8px', border:'1px solid #e2e8f0'}}>
                                <option value="DES">DES</option>
                                <option value="AES">AES (AES128)</option>
                                <option value="AES192">AES192</option>
                                <option value="AES256">AES256</option>
                              </select>
                            </div>
                            <div>
                              <label style={{fontSize:'11px', fontWeight:'700', color:'#64748b'}}>Privacy Key</label>
                              <input type="password" value={manualSnmp.priv_key} onChange={e => setManualSnmp({...manualSnmp, priv_key: e.target.value})} style={{width:'100%', padding:'8px', borderRadius:'8px', border:'1px solid #e2e8f0'}} />
                            </div>
                          </>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>

              <div style={{display:'flex', justifyContent:'flex-end', gap:'10px', marginTop:'10px'}}>
                <button type="button" onClick={() => setIsDeviceModalOpen(false)} style={{padding:'12px 25px', borderRadius:'12px', border:'1px solid #e2e8f0', background:'white', cursor:'pointer'}}>İptal</button>
                <button type="submit" style={{padding:'12px 35px', borderRadius:'12px', border:'none', background:'var(--primary)', color:'white', fontWeight:'700', cursor:'pointer'}}>Kaydet</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

const DeviceManagementView = ({ API_URL }) => {
  const [devices, setDevices] = useState([]);
  const [snmpTemplates, setSnmpTemplates] = useState([]);
  const [sshTemplates, setSshTemplates] = useState([]);
  const [apiTemplates, setApiTemplates] = useState([]);
  const [loading, setLoading] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [isTestSuccessful, setIsTestSuccessful] = useState(false);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingId, setEditingId] = useState(null);
  
  const [form, setForm] = useState({
    name: '',
    ip_address: '',
    connection_method: 'snmp_ssh', // 'snmp_ssh' | 'api'
    snmp_template_id: '',
    ssh_template_id: '',
    api_template_id: '',
    vdom: 'root'
  });

  const fetchAll = async () => {
    try {
      const [d, snmp, ssh, api] = await Promise.all([
        axios.get(`${API_URL}/devices`),
        axios.get(`${API_URL}/snmp-templates`),
        axios.get(`${API_URL}/ssh-templates`),
        axios.get(`${API_URL}/api-templates`)
      ]);
      setDevices(d.data);
      setSnmpTemplates(snmp.data);
      setSshTemplates(ssh.data);
      setApiTemplates(api.data);
    } catch (e) { console.error(e); }
  };

  useEffect(() => { fetchAll(); }, []);

  const handleTest = async () => {
    setLoading(true);
    setTestResult(null);
    setIsTestSuccessful(false);
    try {
      const res = await axios.post(`${API_URL}/devices/test-connection`, form);
      setTestResult({ success: true, message: res.data.message });
      setIsTestSuccessful(true);
      if (res.data.hostname && !form.name) {
        setForm(prev => ({ ...prev, name: res.data.hostname }));
      }
    } catch (e) {
      setTestResult({ success: false, message: e.response?.data?.error || e.message });
      setIsTestSuccessful(false);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async (e) => {
    e.preventDefault();
    if (!isTestSuccessful) {
      alert('Lütfen önce bağlantı testi yapın ve başarılı olduğundan emin olun.');
      return;
    }
    try {
      if (editingId) {
        await axios.put(`${API_URL}/devices/${editingId}`, form);
        alert('Cihaz başarıyla güncellendi.');
      } else {
        await axios.post(`${API_URL}/devices`, form);
        alert('Cihaz başarıyla eklendi.');
      }
      setIsModalOpen(false);
      setEditingId(null);
      fetchAll();
    } catch (e) {
      alert('Hata: ' + (e.response?.data?.error || e.message));
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Cihazı silmek istediğinize emin misiniz?')) return;
    try {
      await axios.delete(`${API_URL}/devices/${id}`);
      fetchAll();
    } catch (e) { alert('Hata!'); }
  };

  return (
    <div className="device-mgmt-view fade-in">
      <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'25px'}}>
        <div>
          <h2 style={{margin:0, fontSize:'1.5rem', fontWeight:'800', color:'#1e293b'}}>Cihaz Yönetimi</h2>
          <p style={{margin:0, color:'#64748b'}}>Tüm ağ cihazlarını buradan ekleyebilir ve yönetebilirsiniz.</p>
        </div>
        <button 
          onClick={() => {
            setForm({ name: '', ip_address: '', connection_method: 'snmp_ssh', snmp_template_id: '', ssh_template_id: '', api_template_id: '', vdom: 'root' });
            setTestResult(null);
            setEditingId(null);
            setIsTestSuccessful(false);
            setIsModalOpen(true);
          }}
          style={{background:'var(--primary)', color:'white', border:'none', padding:'12px 24px', borderRadius:'14px', fontWeight:'700', cursor:'pointer', display:'flex', alignItems:'center', gap:'10px'}}
        >
          <Plus size={20}/> Yeni Cihaz Ekle
        </button>
      </div>

      <div style={{background:'white', borderRadius:'24px', border:'1px solid #e2e8f0', overflow:'hidden', boxShadow:'0 4px 6px -1px rgba(0,0,0,0.05)'}}>
        <table style={{width:'100%', borderCollapse:'collapse'}}>
          <thead style={{background:'#f8fafc', borderBottom:'1px solid #e2e8f0'}}>
            <tr>
              <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>CİHAZ ADI</th>
              <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>IP ADRESİ</th>
              <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>BAĞLANTI METODU</th>
              <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>TEMPLATELER</th>
              <th style={{padding:'15px 25px', textAlign:'right', fontSize:'12px', color:'#64748b'}}>İŞLEMLER</th>
            </tr>
          </thead>
          <tbody>
            {devices.map(d => (
              <tr key={d.id} style={{borderBottom:'1px solid #f1f5f9'}}>
                <td style={{padding:'15px 25px'}}><span style={{fontWeight:'700', color:'#1e293b'}}>{d.name}</span></td>
                <td style={{padding:'15px 25px'}}><span style={{color:'#475569', fontSize:'13px'}}>{d.ip_address}</span></td>
                <td style={{padding:'15px 25px'}}>
                  <span style={{background:'#f1f5f9', color:'#475569', padding:'4px 10px', borderRadius:'8px', fontSize:'11px', fontWeight:'800'}}>
                    {d.connection_method === 'api' ? 'API (FortiGate)' : 'SNMP + SSH'}
                  </span>
                </td>
                <td style={{padding:'15px 25px', fontSize:'12px', color:'#64748b'}}>
                  {d.connection_method === 'api' 
                    ? `API: ${d.api_template_name || 'N/A'}` 
                    : `SNMP: ${d.snmp_template_name || 'N/A'}, SSH: ${d.ssh_template_name || 'N/A'}`}
                </td>
                <td style={{padding:'15px 25px', textAlign:'right'}}>
                  <button onClick={() => {
                    setForm({
                      name: d.name,
                      ip_address: d.ip_address,
                      connection_method: d.connection_method || 'snmp_ssh',
                      snmp_template_id: d.snmp_template_id || '',
                      ssh_template_id: d.ssh_template_id || '',
                      api_template_id: d.api_template_id || '',
                      vdom: d.vdom || 'root'
                    });
                    setEditingId(d.id);
                    setTestResult(null);
                    setIsTestSuccessful(true); // Allow saving since it's an edit
                    setIsModalOpen(true);
                  }} style={{padding:'8px', borderRadius:'10px', border:'1px solid #e2e8f0', background:'white', cursor:'pointer', marginRight:'8px'}}>Düzenle</button>
                  <button onClick={() => handleDelete(d.id)} style={{padding:'8px', borderRadius:'10px', border:'1px solid #fee2e2', background:'#fef2f2', color:'#ef4444', cursor:'pointer'}}><Trash2 size={16}/></button>
                </td>
              </tr>
            ))}
            {devices.length === 0 && <tr><td colSpan="5" style={{padding:'40px', textAlign:'center', color:'#94a3b8'}}>Henüz bir cihaz eklenmedi.</td></tr>}
          </tbody>
        </table>
      </div>

      {isModalOpen && (
        <div className="modal-overlay" style={{position:'fixed', top:0, left:0, right:0, bottom:0, background:'rgba(15,23,42,0.6)', backdropFilter:'blur(4px)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:1000}}>
          <div style={{background:'white', width:'650px', maxWidth:'96vw', borderRadius:'24px', padding:'35px', boxShadow:'0 25px 50px -12px rgba(0,0,0,0.25)'}}>
            <h3 style={{margin:'0 0 20px', fontSize:'1.25rem', fontWeight:'800'}}>{editingId ? 'Cihaz Düzenle' : 'Yeni Cihaz Ekle'}</h3>
            
            <form onSubmit={handleSave} style={{display:'grid', gap:'20px'}}>
              <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'20px'}}>
                <div>
                  <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>IP ADRESİ</label>
                  <input type="text" value={form.ip_address} onChange={e => setForm({...form, ip_address: e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'12px', border:'1px solid #e2e8f0'}} placeholder="192.168.1.1" required />
                </div>
                <div>
                  <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>CİHAZ ADI (OPSİYONEL)</label>
                  <input type="text" value={form.name} onChange={e => setForm({...form, name: e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'12px', border:'1px solid #e2e8f0'}} placeholder="Cihaz Adı" />
                </div>
              </div>

              <div>
                <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b', marginBottom:'10px', display:'block'}}>BAĞLANTI METODU</label>
                <div style={{display:'flex', gap:'15px'}}>
                  <button type="button" onClick={() => { setForm({...form, connection_method: 'snmp_ssh'}); setIsTestSuccessful(false); }} style={{flex:1, padding:'15px', borderRadius:'15px', border: form.connection_method==='snmp_ssh'?'2px solid var(--primary)':'2px solid #f1f5f9', background: form.connection_method==='snmp_ssh'?'#eff6ff':'white', cursor:'pointer', textAlign:'left'}}>
                    <div style={{fontWeight:'800', fontSize:'14px', color: form.connection_method==='snmp_ssh'?'var(--primary)':'#1e293b'}}>SNMP + SSH</div>
                    <div style={{fontSize:'11px', color:'#64748b', marginTop:'4px'}}>Switch ve Routerlar için ideal</div>
                  </button>
                  <button type="button" onClick={() => { setForm({...form, connection_method: 'api'}); setIsTestSuccessful(false); }} style={{flex:1, padding:'15px', borderRadius:'15px', border: form.connection_method==='api'?'2px solid var(--primary)':'2px solid #f1f5f9', background: form.connection_method==='api'?'#eff6ff':'white', cursor:'pointer', textAlign:'left'}}>
                    <div style={{fontWeight:'800', fontSize:'14px', color: form.connection_method==='api'?'var(--primary)':'#1e293b'}}>API (REST)</div>
                    <div style={{fontSize:'11px', color:'#64748b', marginTop:'4px'}}>FortiGate ve Modern Cihazlar için</div>
                  </button>
                </div>
              </div>

              {form.connection_method === 'api' ? (
                <div style={{display:'grid', gap:'20px'}}>
                  <div>
                    <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>API TEMPLATE</label>
                    <select value={form.api_template_id} onChange={e => { setForm({...form, api_template_id: e.target.value}); setIsTestSuccessful(false); }} style={{width:'100%', padding:'12px', borderRadius:'12px', border:'1px solid #e2e8f0'}} required>
                      <option value="">Seçiniz...</option>
                      {apiTemplates.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
                    </select>
                  </div>
                </div>
              ) : (
                <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'20px'}}>
                  <div>
                    <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>SNMP TEMPLATE</label>
                    <select value={form.snmp_template_id} onChange={e => { setForm({...form, snmp_template_id: e.target.value}); setIsTestSuccessful(false); }} style={{width:'100%', padding:'12px', borderRadius:'12px', border:'1px solid #e2e8f0'}} required>
                      <option value="">Seçiniz...</option>
                      {snmpTemplates.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
                    </select>
                  </div>
                  <div>
                    <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>SSH TEMPLATE</label>
                    <select value={form.ssh_template_id} onChange={e => { setForm({...form, ssh_template_id: e.target.value}); setIsTestSuccessful(false); }} style={{width:'100%', padding:'12px', borderRadius:'12px', border:'1px solid #e2e8f0'}} required>
                      <option value="">Seçiniz...</option>
                      {sshTemplates.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
                    </select>
                  </div>
                </div>
              )}

              <div style={{padding:'20px', borderRadius:'15px', background: testResult ? (testResult.success ? '#f0fdf4' : '#fef2f2') : '#f8fafc', border: testResult ? (testResult.success ? '1px solid #bbf7d0' : '1px solid #fecaca') : '1px solid #e2e8f0'}}>
                <div style={{display:'flex', justifyContent:'space-between', alignItems:'center'}}>
                  <div style={{fontSize:'13px', fontWeight:'700', color: testResult ? (testResult.success ? '#166534' : '#991b1b') : '#64748b'}}>
                    {loading ? 'Bağlantı Test Ediliyor...' : (testResult ? testResult.message : 'Lütfen bağlantıyı test edin')}
                  </div>
                  <button type="button" onClick={handleTest} disabled={loading} style={{background: 'white', border: '1px solid #e2e8f0', padding: '8px 16px', borderRadius: '10px', fontSize: '12px', fontWeight: '800', cursor: 'pointer', display:'flex', alignItems:'center', gap: '6px'}}>
                    <Activity size={14}/> Test Et
                  </button>
                </div>
              </div>

              <div style={{display:'flex', gap:'12px', marginTop:'10px'}}>
                <button type="button" onClick={() => setIsModalOpen(false)} style={{flex:1, padding:'14px', borderRadius:'14px', border:'1px solid #e2e8f0', background:'white', fontWeight:'700', cursor:'pointer'}}>İptal</button>
                <button type="submit" disabled={!isTestSuccessful} style={{flex:1, padding:'14px', borderRadius:'14px', border:'none', background: isTestSuccessful ? 'var(--primary)' : '#cbd5e1', color:'white', fontWeight:'800', cursor: isTestSuccessful ? 'pointer' : 'not-allowed'}}>Cihazı Kaydet</button>
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  );
};

const NetworkScanView = ({ API_URL }) => {
  const [snmpTemplates, setSnmpTemplates] = useState([]);
  const [discovered, setDiscovered] = useState([]);
  const [activeScan, setActiveScan] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [form, setForm] = useState({ ip_range: '', snmp_template_ids: [] });
  const [loading, setLoading] = useState(false);
  const [isDebugMenuOpen, setIsDebugMenuOpen] = useState(false);
  const [scanLogs, setScanLogs] = useState([]);
  const [activeScanId, setActiveScanId] = useState(null);

  const addScanLog = (message, type = 'info', scanId = null) => {
    const scanIdToUse = scanId || activeScanId;
    setScanLogs(prev => [...prev, {
      id: uuidv4(),
      timestamp: new Date().toLocaleTimeString('tr-TR'),
      message,
      type,
      scanId: scanIdToUse
    }]);
  };

  const startScan = (scanName) => {
    const newScanId = uuidv4();
    setActiveScanId(newScanId);
    addScanLog(`${scanName} başlatıldı`, 'info', newScanId);
    return newScanId;
  };

  const stopScan = (scanId) => {
    addScanLog('Tarama durduruldu', 'warning', scanId);
  };

  const completeScan = (scanId) => {
    addScanLog('Tarama tamamlandı', 'success', scanId);
  };

  const clearScanLogs = () => {
    setScanLogs([]);
    setActiveScanId(null);
  };

  const pauseScan = async () => {
    if (!activeScan) return;
    try {
      addScanLog('Tarama duraklat\u0131l\u0131yor...', 'info', activeScanId);
      console.log('Pausing scan:', activeScan.id);
      const response = await axios.post(`${API_URL}/network-scan/pause`, { scan_id: activeScan.id });
      console.log('Pause response:', response.data);
      setActiveScan(prev => ({ ...prev, status: 'paused' }));
      addScanLog('Tarama başarıyla duraklat\u0131ld\u0131', 'warning', activeScanId);
      // Immediate refetch
      await fetchData();
    } catch (e) {
      console.error('Pause error:', e);
      addScanLog(`Hata: Tarama durdurulamad\u0131 - ${e.message}`, 'error', activeScanId);
    }
  };

  const resumeScan = async () => {
    if (!activeScan) return;
    try {
      addScanLog('Tarama devam ettiriliyor...', 'info', activeScanId);
      console.log('Resuming scan:', activeScan.id);
      const response = await axios.post(`${API_URL}/network-scan/resume`, { scan_id: activeScan.id });
      console.log('Resume response:', response.data);
      setActiveScan(prev => ({ ...prev, status: 'scanning' }));
      addScanLog('Tarama başarıyla devam etirildi', 'success', activeScanId);
      // Immediate refetch
      await fetchData();
    } catch (e) {
      console.error('Resume error:', e);
      addScanLog(`Hata: Tarama devam ettirilemedi - ${e.message}`, 'error', activeScanId);
    }
  };

  const cancelScan = async () => {
    if (!activeScan) return;
    try {
      addScanLog('Tarama iptal ediliyor...', 'error', activeScanId);
      console.log('Cancelling scan:', activeScan.id);
      const response = await axios.post(`${API_URL}/network-scan/cancel`, { scan_id: activeScan.id });
      console.log('Cancel response:', response.data);
      setActiveScan(null);
      clearScanLogs();
      addScanLog('Tarama iptal edildi', 'error', activeScanId);
      // Immediate refetch
      await fetchData();
    } catch (e) {
      console.error('Cancel error:', e);
      addScanLog(`Hata: Tarama iptal edilemedi - ${e.message}`, 'error', activeScanId);
    }
  };

  const fetchData = async () => {
    try {
      const [tpls, disc, active, history] = await Promise.all([
        axios.get(`${API_URL}/snmp-templates`),
        axios.get(`${API_URL}/network-scan/discovered`),
        axios.get(`${API_URL}/network-scan/active`),
        axios.get(`${API_URL}/network-scan/history`)
      ]);
      setSnmpTemplates(tpls.data);
      setDiscovered(disc.data);
      if (active.data) {
        console.log('Active scan:', active.data);
      }
      setActiveScan(active.data);
      setScanHistory(history.data || []);
    } catch (e) { 
      console.error('FetchData error:', e.message);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  // Monitor scan completion
  useEffect(() => {
    if (activeScan && activeScanId) {
      if (activeScan.status === 'completed') {
        addScanLog(`Tarama tamamlandı. ${activeScan.progress_current} cihaz bulundu.`, 'success', activeScanId);
      } else if (activeScan.status === 'error') {
        addScanLog('Tarama sırasında hata oluştu', 'error', activeScanId);
      } else if (activeScan.status === 'cancelled') {
        addScanLog('Tarama iptal edildi', 'warning', activeScanId);
      }
    }
  }, [activeScan?.status]);

  const handleStartScan = async (e) => {
    e.preventDefault();
    if (form.snmp_template_ids.length === 0) {
      alert('Lütfen en az bir SNMP template seçin.');
      return;
    }
    const scanId = startScan('Ağ Taraması');
    addScanLog(`IP Aralığı: ${form.ip_range}`, 'info', scanId);
    addScanLog(`Seçili SNMP Templateler: ${form.snmp_template_ids.length} adet`, 'info', scanId);
    setLoading(true);
    try {
      addScanLog('API\'ye tarama isteği gönderiliyor...', 'info', scanId);
      await axios.post(`${API_URL}/network-scan`, form);
      addScanLog('Tarama başarıyla başlatıldı, IP\'ler taranıyor...', 'success', scanId);
      fetchData();
    } catch (e) { 
      addScanLog(`Hata: ${e.message}`, 'error', scanId);
      alert('Tarama başlatılamadı!'); 
    }
    finally { setLoading(false); }
  };

  const handleAddDevice = async (id) => {
    try {
      addScanLog(`Cihaz ekleniyor (ID: ${id})...`, 'info');
      const res = await axios.post(`${API_URL}/network-scan/add-discovered`, { id });
      if (res.data.success) {
        addScanLog('Cihaz başarıyla eklendi', 'success');
        fetchData();
        alert('Cihaz başarıyla eklendi.');
      }
    } catch (e) {
      console.error('Add device error:', e);
      const errorMsg = e.response?.data?.error || 'Cihaz eklenemedi';
      const details = e.response?.data?.details ? ` (${e.response.data.details})` : '';
      const code = e.response?.data?.code ? ` [Hata Kodu: ${e.response.data.code}]` : '';
      addScanLog(`Hata: ${errorMsg}${details}${code}`, 'error');
      alert(`Hata: ${errorMsg}${details}`);
    }
  };
  const toggleTemplate = (id) => {
    setForm(prev => {
      const ids = prev.snmp_template_ids.includes(id)
        ? prev.snmp_template_ids.filter(i => i !== id)
        : [...prev.snmp_template_ids, id];
      return { ...prev, snmp_template_ids: ids };
    });
  };

  return (
    <div className="network-scan-view fade-in" style={{ padding: '20px' }}>
      <div style={{ display: 'grid', gridTemplateColumns: '350px 1fr', gap: '30px' }}>
        {/* Sol Panel: Tarama Kontrolü */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '25px' }}>
          <div style={{ background: 'white', borderRadius: '24px', padding: '30px', border: '1px solid #e2e8f0', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.05)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px' }}>
              <div style={{ background: '#f0f9ff', padding: '10px', borderRadius: '12px', color: '#0369a1' }}>
                <Search size={24} />
              </div>
              <h3 style={{ margin: 0, fontSize: '1.25rem', fontWeight: '800', color: '#1e293b' }}>Yeni Tarama</h3>
            </div>
            
            <form onSubmit={handleStartScan} style={{ display: 'grid', gap: '20px' }}>
              <div>
                <label style={{ fontSize: '12px', fontWeight: '700', color: '#64748b', marginBottom: '8px', display: 'block', textTransform: 'uppercase', letterSpacing: '0.05em' }}>IP Aralığı veya Tekil IP</label>
                <input 
                  type="text" 
                  value={form.ip_range} 
                  onChange={e => setForm({...form, ip_range: e.target.value})} 
                  placeholder="Örn: 192.168.1.1-50" 
                  style={{ width: '100%', padding: '14px', borderRadius: '14px', border: '1px solid #e2e8f0', fontSize: '14px', outline: 'none' }} 
                  required 
                />
              </div>

              <div>
                <label style={{ fontSize: '12px', fontWeight: '700', color: '#64748b', marginBottom: '10px', display: 'block', textTransform: 'uppercase', letterSpacing: '0.05em' }}>SNMP Şablonları</label>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '200px', overflowY: 'auto' }}>
                  {snmpTemplates.map(t => (
                    <label key={t.id} style={{ 
                      display: 'flex', alignItems: 'center', gap: '12px', padding: '12px', borderRadius: '12px', 
                      background: form.snmp_template_ids.includes(t.id) ? '#f0f9ff' : '#f8fafc', 
                      border: form.snmp_template_ids.includes(t.id) ? '1px solid #bae6fd' : '1px solid #e2e8f0', 
                      cursor: 'pointer'
                    }}>
                      <input type="checkbox" checked={form.snmp_template_ids.includes(t.id)} onChange={() => toggleTemplate(t.id)} />
                      <div style={{ display: 'flex', flexDirection: 'column' }}>
                        <span style={{ fontSize: '13px', fontWeight: '700', color: '#1e293b' }}>{t.name}</span>
                        <span style={{ fontSize: '11px', color: '#64748b' }}>{t.version}</span>
                      </div>
                    </label>
                  ))}
                </div>
              </div>

              <div style={{ display: 'flex', gap: '12px' }}>
                <button 
                  type="submit" 
                  disabled={loading || (activeScan && activeScan.status === 'scanning')} 
                  style={{ 
                    flex: 1, background: 'var(--primary)', color: 'white', border: 'none', padding: '16px', borderRadius: '16px', 
                    fontWeight: '800', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '10px',
                    opacity: (loading || (activeScan && activeScan.status === 'scanning')) ? 0.7 : 1
                  }}
                >
                  {(activeScan && activeScan.status === 'scanning') ? 'Tarama Yapılıyor...' : 'Taramayı Başlat'}
                </button>
                
                <button 
                  type="button" 
                  onClick={() => setIsDebugMenuOpen(!isDebugMenuOpen)} 
                  style={{ background: '#f1f5f9', border: '1px solid #e2e8f0', padding: '12px', borderRadius: '16px', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', height: '54px', width: '54px', position: 'relative' }}
                >
                  <Terminal size={22} color="#64748b" />
                  {scanLogs.length > 0 && (
                    <span style={{ position: 'absolute', top: '-6px', right: '-6px', background: '#ef4444', color: 'white', fontSize: '10px', fontWeight: '900', borderRadius: '50%', width: '22px', height: '22px', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '2px solid white' }}>
                      {scanLogs.length}
                    </span>
                  )}
                </button>
              </div>
            </form>

            {activeScan && (activeScan.status === 'scanning' || activeScan.status === 'paused') && (
              <div style={{ marginTop: '25px', padding: '20px', borderRadius: '20px', background: activeScan.status === 'paused' ? '#fffbeb' : '#f0f9ff', border: activeScan.status === 'paused' ? '1px solid #fde68a' : '1px solid #bae6fd' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    <span style={{ fontSize: '11px', fontWeight: '800', color: activeScan.status === 'paused' ? '#92400e' : '#0369a1', textTransform: 'uppercase' }}>
                      {activeScan.status === 'paused' ? 'DURAKLATILDI' : 'TARANIYOR...'}
                    </span>
                    <span style={{ fontSize: '14px', fontWeight: '800', color: '#1e293b', marginTop: '2px' }}>{activeScan.progress_current} / {activeScan.progress_total}</span>
                  </div>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    {activeScan.status === 'scanning' ? (
                      <button onClick={pauseScan} style={{ background: 'white', border: '1px solid #f59e0b', color: '#f59e0b', width: '32px', height: '32px', borderRadius: '8px', cursor: 'pointer' }}><Clock size={16} /></button>
                    ) : (
                      <button onClick={resumeScan} style={{ background: 'white', border: '1px solid #10b981', color: '#10b981', width: '32px', height: '32px', borderRadius: '8px', cursor: 'pointer' }}><RefreshCw size={16} /></button>
                    )}
                    <button onClick={cancelScan} style={{ background: 'white', border: '1px solid #ef4444', color: '#ef4444', width: '32px', height: '32px', borderRadius: '8px', cursor: 'pointer' }}><X size={16} /></button>
                  </div>
                </div>
                <div style={{ height: '10px', background: activeScan.status === 'paused' ? '#fef3c7' : '#e0f2fe', borderRadius: '5px', overflow: 'hidden' }}>
                  <div style={{ height: '100%', background: activeScan.status === 'paused' ? '#f59e0b' : 'var(--primary)', width: `${(activeScan.progress_current / activeScan.progress_total) * 100}%`, transition: 'width 0.4s ease' }}></div>
                </div>
              </div>
            )}
          </div>

          <div style={{ background: 'white', borderRadius: '24px', border: '1px solid #e2e8f0', overflow: 'hidden' }}>
            <div style={{ padding: '20px 25px', borderBottom: '1px solid #e2e8f0', background: '#f8fafc' }}>
              <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: '800', color: '#1e293b' }}>Son Taramalar</h3>
            </div>
            <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
              {scanHistory.map(scan => (
                <div key={scan.id} style={{ padding: '16px 25px', borderBottom: '1px solid #f1f5f9', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <div style={{ fontSize: '12px', fontWeight: '700', color: '#1e293b' }}>{scan.ip_range}</div>
                    <div style={{ fontSize: '10px', color: '#64748b' }}>{new Date(scan.updated_at).toLocaleString('tr-TR')}</div>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '12px', fontWeight: '800', color: scan.status === 'completed' ? '#059669' : '#991b1b' }}>{scan.discovered_count} Bulunan</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Sağ Panel: Bulunan Cihazlar */}
        <div style={{ background: 'white', borderRadius: '24px', border: '1px solid #e2e8f0', overflow: 'hidden', boxShadow: '0 10px 15px -3px rgba(0,0,0,0.05)' }}>
          <div style={{ padding: '25px 30px', borderBottom: '1px solid #e2e8f0', background: '#f8fafc', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ margin: 0, fontSize: '1.25rem', fontWeight: '800', color: '#1e293b' }}>Tespit Edilen Cihazlar</h3>
            <div style={{ background: 'var(--primary)', color: 'white', padding: '6px 14px', borderRadius: '10px', fontSize: '13px', fontWeight: '800' }}>
              {discovered.length} Cihaz Bulundu
            </div>
          </div>
          
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead style={{ background: '#f8fafc', borderBottom: '1px solid #e2e8f0' }}>
                <tr>
                  <th style={{ padding: '18px 30px', textAlign: 'left', fontSize: '12px', color: '#64748b', textTransform: 'uppercase' }}>IP ADRESİ</th>
                  <th style={{ padding: '18px 30px', textAlign: 'left', fontSize: '12px', color: '#64748b', textTransform: 'uppercase' }}>CİHAZ ADI</th>
                  <th style={{ padding: '18px 30px', textAlign: 'left', fontSize: '12px', color: '#64748b', textTransform: 'uppercase' }}>ŞABLON</th>
                  <th style={{ padding: '18px 30px', textAlign: 'center', fontSize: '12px', color: '#64748b', textTransform: 'uppercase' }}>İŞLEM</th>
                </tr>
              </thead>
              <tbody>
                {discovered.map(d => (
                  <tr key={d.id} style={{ borderBottom: '1px solid #f1f5f9' }}>
                    <td style={{ padding: '20px 30px' }}><span style={{ fontWeight: '800', color: '#1e293b' }}>{d.ip_address}</span></td>
                    <td style={{ padding: '20px 30px' }}><span style={{ color: '#475569', fontSize: '14px', fontWeight: '600' }}>{d.hostname}</span></td>
                    <td style={{ padding: '20px 30px' }}>
                      <span style={{ background: '#f1f5f9', color: '#475569', padding: '6px 12px', borderRadius: '10px', fontSize: '12px', fontWeight: '800' }}>
                        {d.template_name}
                      </span>
                    </td>
                    <td style={{ padding: '20px 30px', textAlign: 'center' }}>
                      <button 
                        onClick={() => handleAddDevice(d.id)} 
                        title="Cihazı Envantere Ekle"
                        style={{
                          background: 'white', border: '2px solid var(--primary)', color: 'var(--primary)', 
                          width: '42px', height: '42px', borderRadius: '14px', cursor: 'pointer',
                          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                          transition: 'all 0.2s'
                        }}
                        onMouseEnter={(e) => { e.currentTarget.style.background = 'var(--primary)'; e.currentTarget.style.color = 'white'; }}
                        onMouseLeave={(e) => { e.currentTarget.style.background = 'white'; e.currentTarget.style.color = 'var(--primary)'; }}
                      >
                        <Plus size={24} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
      {isDebugMenuOpen && (
        <DebugMenu
          isOpen={isDebugMenuOpen}
          onClose={() => setIsDebugMenuOpen(false)}
          scanLogs={scanLogs}
          onStopScan={(scanId) => stopScan(scanId)}
          onClearLogs={clearScanLogs}
        />
      )}
    </div>
  );
};

const TopologyView = ({ API_URL }) => {
  const [topologies, setTopologies] = useState([]);
  const [currentTopo, setCurrentTopo] = useState(null); // When null, show list
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [devices, setDevices] = useState([]);
  const [customIcons, setCustomIcons] = useState([]);
  const [tool, setTool] = useState('move'); // 'move', 'device', 'box', 'text', 'cable', 'delete'
  const [isDeviceModalOpen, setIsModalOpen] = useState(false);
  const [isNodeEditModalOpen, setIsNodeEditModalOpen] = useState(false);
  const [editingNode, setEditingNode] = useState(null);
  const [pendingNode, setPendingNode] = useState(null);
  const [cableStart, setCableStart] = useState(null);
  const [draggingNodeId, setDraggingNodeId] = useState(null);
  const [resizingNodeId, setResizingNodeId] = useState(null);
  const [resizeDir, setResizeDir] = useState(null); // 'n', 's', 'e', 'w', 'nw', 'ne', 'sw', 'se'
  const [draggingWaypoint, setDraggingWaypoint] = useState(null); // { edgeId, index }
  const [hoveredNodeId, setHoveredNodeId] = useState(null);
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });
  const [isFullScreen, setIsFullScreen] = useState(false);
  const [transform, setTransform] = useState({ x: 0, y: 0, k: 1 });
  const [isPanning, setIsPanning] = useState(false);
  const [lastMousePos, setLastMousePos] = useState({ x: 0, y: 0 });
  const [contextMenu, setContextMenu] = useState(null);
  const svgRef = useRef(null);

  const startEditNode = (id) => {
    const node = nodes.find(n => n.id === id);
    if (node) {
      setEditingNode(node);
      setIsNodeEditModalOpen(true);
    }
    setContextMenu(null);
  };

  const handleBgMouseDown = (e) => {
    if (e.button === 1 || ((tool === 'move' || tool === 'select') && !draggingNodeId)) {
      setIsPanning(true);
      setLastMousePos({ x: e.clientX, y: e.clientY });
    }
  };

  const onEdgeClick = (id, e) => {
    if (e && e.stopPropagation) e.stopPropagation();
    if (tool === 'delete') {
      setEdges(edges.filter(edge => edge.id !== id));
      return;
    }
    if (tool === 'cable' || tool === 'move' || tool === 'select') {
      const { x, y } = getCoords(e);
      setEdges(edges.map(edge => {
        if (edge.id === id) {
          return { ...edge, waypoints: [...(edge.waypoints || []), { x, y }] };
        }
        return edge;
      }));
    }
  };

  const onWaypointMouseDown = (edgeId, index, e) => {
    if (e && e.stopPropagation) e.stopPropagation();
    setDraggingWaypoint({ edgeId, index });
  };

  useEffect(() => {
    const handleClick = () => setContextMenu(null);
    window.addEventListener('click', handleClick);
    return () => window.removeEventListener('click', handleClick);
  }, []);

  const fetchTopologies = async () => {
    try {
      const res = await axios.get(`${API_URL}/topologies`);
      setTopologies(res.data);
    } catch (e) { console.error(e); }
  };

  const fetchDevices = async () => {
    try {
      const res = await axios.get(`${API_URL}/devices`);
      setDevices(res.data);
    } catch (e) { console.error(e); }
  };

  const fetchIcons = async () => {
    try {
      const res = await axios.get(`${API_URL}/icons`);
      setCustomIcons(res.data);
    } catch (e) { console.error(e); }
  };

  useEffect(() => {
    fetchTopologies();
    fetchDevices();
    fetchIcons();
  }, [API_URL]);

  const handleCreateTopo = async () => {
    const name = prompt('Topoloji adı:');
    if (!name) return;
    try {
      const res = await axios.post(`${API_URL}/topologies`, { name });
      fetchTopologies();
      openTopo(res.data);
    } catch (e) { alert('Hata!'); }
  };

  const handleRenameTopo = async (id, oldName, e) => {
    e.stopPropagation();
    const newName = prompt('Yeni topoloji adı:', oldName);
    if (!newName || newName === oldName) return;
    try {
      await axios.put(`${API_URL}/topologies/${id}`, { name: newName });
      fetchTopologies();
    } catch (e) { alert('Hata!'); }
  };

  const openTopo = async (topo) => {
    try {
      const res = await axios.get(`${API_URL}/topologies/${topo.id}`);
      setCurrentTopo(res.data);
      setNodes(res.data.nodes || []);
      setEdges(res.data.edges || []);
      setTransform({ x: 0, y: 0, k: 1 });
    } catch (e) { alert('Topoloji açılamadı!'); }
  };

  const deleteTopo = async (id, e) => {
    e.stopPropagation();
    if (!window.confirm('Bu topolojiyi silmek istediğinize emin misiniz?')) return;
    try {
      await axios.delete(`${API_URL}/topologies/${id}`);
      fetchTopologies();
    } catch (e) { alert('Hata!'); }
  };

  const handleManualSave = async () => {
    if (!currentTopo) return;
    try {
      await axios.put(`${API_URL}/topologies/${currentTopo.id}`, { nodes, edges });
      alert('Topoloji kaydedildi.');
      fetchTopologies();
    } catch (e) { alert('Kaydetme hatası!'); }
  };

  const getCoords = (e) => {
    const svg = svgRef.current;
    if (!svg) return { x: 0, y: 0 };
    const rect = svg.getBoundingClientRect();
    const clientX = e.clientX !== undefined ? e.clientX : (e.x !== undefined ? e.x : 0);
    const clientY = e.clientY !== undefined ? e.clientY : (e.y !== undefined ? e.y : 0);
    const x = (clientX - rect.left - transform.x) / transform.k;
    const y = (clientY - rect.top - transform.y) / transform.k;
    return { x, y };
  };

  const handleSvgClick = (e) => {
    // If we were resizing, any click should exit resize mode
    if (resizingNodeId) {
      setResizingNodeId(null);
      return;
    }
    
    if (tool === 'move' || tool === 'select' || tool === 'cable' || tool === 'delete' || isPanning || draggingNodeId) return;
    const { x, y } = getCoords(e);

    if (tool === 'device') {
      setPendingNode({ x, y, type: 'device' });
      setIsModalOpen(true);
    } else if (tool === 'box') {
      setNodes([...nodes, { id: uuidv4(), x, y, type: 'box', label: 'Yeni Alan', width: 100, height: 60 }]);
    } else if (tool === 'text') {
      const label = prompt('Yazı girin:');
      if (label) setNodes([...nodes, { id: uuidv4(), x, y, type: 'text', label }]);
    }
  };

  const onNodeClick = (id, e) => {
    e.stopPropagation();
    
    if (resizingNodeId) {
      setResizingNodeId(null);
      return;
    }

    if (tool === 'delete') {
      setNodes(nodes.filter(n => n.id !== id));
      setEdges(edges.filter(edge => edge.from !== id && edge.to !== id));
    } else if (tool === 'cable') {
      setLastMousePos({ x: e.clientX, y: e.clientY });
      if (!cableStart) setCableStart(id);
      else if (cableStart !== id) {
        setEdges([...edges, { id: uuidv4(), from: cableStart, to: id, waypoints: [] }]);
        setCableStart(null);
      }
    }
  };

  const onNodeContextMenu = (id, e) => {
    e.preventDefault();
    e.stopPropagation();
    const node = nodes.find(n => n.id === id);
    setContextMenu({ x: e.clientX, y: e.clientY, nodeId: id, type: 'node', nodeType: node?.type });
  };

  const onEdgeContextMenu = (id, e) => {
    e.preventDefault();
    e.stopPropagation();
    setContextMenu({ x: e.clientX, y: e.clientY, edgeId: id, type: 'edge' });
  };

  const bringToFront = (id) => {
    const node = nodes.find(n => n.id === id);
    if (node) {
      setNodes([...nodes.filter(n => n.id !== id), node]);
    }
    setContextMenu(null);
  };

  const sendToBack = (id) => {
    const node = nodes.find(n => n.id === id);
    if (node) {
      setNodes([node, ...nodes.filter(n => n.id !== id)]);
    }
    setContextMenu(null);
  };

  const deleteNode = (id) => {
    setNodes(nodes.filter(n => n.id !== id));
    setEdges(edges.filter(edge => edge.from !== id && edge.to !== id));
    setContextMenu(null);
  };

  const resetEdge = (id) => {
    setEdges(edges.map(e => e.id === id ? { ...e, waypoints: [] } : e));
    setContextMenu(null);
  };

  const deleteEdge = (id) => {
    setEdges(edges.filter(e => e.id !== id));
    setContextMenu(null);
  };

  const startResize = (id) => {
    setResizingNodeId(id);
    setContextMenu(null);
  };

  const onNodeMouseEnter = (id) => {
    if (cableStart) setHoveredNodeId(id);
  };

  const onNodeMouseLeave = () => {
    setHoveredNodeId(null);
  };

  const onMouseDown = (id, e) => {
    e.stopPropagation();
    if (tool === 'cable') {
      if (!cableStart) setCableStart(id);
      setLastMousePos({ x: e.clientX, y: e.clientY });
      return;
    }
    if (tool !== 'move' && tool !== 'select') return;
    const node = nodes.find(n => n.id === id);
    if (node) {
      const { x, y } = getCoords(e);
      setDragOffset({ x: x - node.x, y: y - node.y });
      setDraggingNodeId(id);
    }
  };

  const handleMouseUp = (e) => {
    if (tool === 'cable' && cableStart && hoveredNodeId && cableStart !== hoveredNodeId) {
      setEdges([...edges, { id: uuidv4(), from: cableStart, to: hoveredNodeId, waypoints: [] }]);
      setCableStart(null);
    } else if (tool !== 'cable') {
      setCableStart(null);
    }
    // Note: if tool is 'cable' but we didn't land on a node, we keep cableStart for click-to-connect mode
    
    setDraggingNodeId(null);
    setDraggingWaypoint(null);
    setResizeDir(null);
    setIsPanning(false);
  };

  const onMouseMove = (e) => {
    setLastMousePos({ x: e.clientX, y: e.clientY });

    if (draggingNodeId) {
      const { x, y } = getCoords(e);
      setNodes(prev => prev.map(n => n.id === draggingNodeId ? { ...n, x: x - dragOffset.x, y: y - dragOffset.y } : n));
      return;
    }

    if (resizingNodeId && resizeDir) {
      const { x, y } = getCoords(e);
      setNodes(prev => prev.map(n => {
        if (n.id !== resizingNodeId) return n;
        
        let newX = n.x;
        let newY = n.y;
        let newW = n.width || 120;
        let newH = n.height || 80;

        if (resizeDir.includes('e')) newW = Math.max(20, x - n.x + (n.width || 120) / 2);
        if (resizeDir.includes('s')) newH = Math.max(20, y - n.y + (n.height || 80) / 2);
        if (resizeDir.includes('w')) {
          const deltaX = x - (n.x - (n.width || 120) / 2);
          newW = Math.max(20, (n.width || 120) - deltaX);
          newX = n.x + deltaX / 2;
        }
        if (resizeDir.includes('n')) {
          const deltaY = y - (n.y - (n.height || 80) / 2);
          newH = Math.max(20, (n.height || 80) - deltaY);
          newY = n.y + deltaY / 2;
        }

        return { ...n, x: newX, y: newY, width: newW, height: newH };
      }));
      return;
    }

    if (draggingWaypoint) {
      const { x, y } = getCoords(e);
      setEdges(prev => prev.map(edge => {
        if (edge.id === draggingWaypoint.edgeId) {
          const newWaypoints = [...(edge.waypoints || [])];
          newWaypoints[draggingWaypoint.index] = { x, y };
          return { ...edge, waypoints: newWaypoints };
        }
        return edge;
      }));
      return;
    }

    if (isPanning) {
      const dx = e.clientX - lastMousePos.x;
      const dy = e.clientY - lastMousePos.y;
      setTransform(prev => ({ ...prev, x: prev.x + dx, y: prev.y + dy }));
      setLastMousePos({ x: e.clientX, y: e.clientY });
    }
  };


  const handleWheel = (e) => {
    e.preventDefault();
    const delta = e.deltaY < 0 ? 1.1 : 0.9;
    const newK = Math.min(Math.max(transform.k * delta, 0.1), 5);
    const rect = svgRef.current.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;
    const newX = mouseX - (mouseX - transform.x) * (newK / transform.k);
    const newY = mouseY - (mouseY - transform.y) * (newK / transform.k);
    setTransform({ x: newX, y: newY, k: newK });
  };

  const updateNodeSettings = (id, updates) => {
    setNodes(nodes.map(n => n.id === id ? { ...n, ...updates } : n));
    setIsNodeEditModalOpen(false);
    setEditingNode(null);
  };

  if (!currentTopo) {
    return (
      <div className="topo-list-view fade-in">
        <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'25px'}}>
          <div>
            <h2 style={{margin:0, fontSize:'1.5rem', fontWeight:'800'}}>Topoloji Yönetimi</h2>
            <p style={{margin:0, color:'#64748b'}}>Ağ yapılarınızı görsel olarak tasarlayın ve yönetin.</p>
          </div>
          <button onClick={handleCreateTopo} style={{background:'var(--primary)', color:'white', border:'none', padding:'12px 24px', borderRadius:'14px', fontWeight:'700', cursor:'pointer', display:'flex', alignItems:'center', gap:'10px'}}><Plus size={20}/> Yeni Topoloji Oluştur</button>
        </div>
        <div style={{display:'grid', gridTemplateColumns:'repeat(auto-fill, minmax(300px, 1fr))', gap:'20px'}}>
          {topologies.map(t => (
            <div key={t.id} onClick={() => openTopo(t)} style={{background:'white', border:'1px solid #e2e8f0', borderRadius:'20px', padding:'20px', cursor:'pointer', transition:'all 0.2s', boxShadow:'0 4px 6px -1px rgba(0,0,0,0.05)'}} onMouseOver={e=>e.currentTarget.style.borderColor='var(--primary)'} onMouseOut={e=>e.currentTarget.style.borderColor='#e2e8f0'}>
              <div style={{display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:'15px'}}>
                <h3 style={{margin:0, fontSize:'1.1rem', fontWeight:'800'}}>{t.name}</h3>
                <div style={{display:'flex', gap:'5px'}}>
                  <button onClick={(e) => handleRenameTopo(t.id, t.name, e)} style={{padding:'6px', borderRadius:'8px', border:'none', background:'#f1f5f9', color:'#475569', cursor:'pointer'}} title="Yeniden Adlandır"><Edit size={16}/></button>
                  <button onClick={(e) => deleteTopo(t.id, e)} style={{padding:'6px', borderRadius:'8px', border:'none', background:'#fef2f2', color:'#ef4444', cursor:'pointer'}} title="Sil"><Trash2 size={16}/></button>
                </div>
              </div>
              <div style={{fontSize:'12px', color:'#64748b'}}>Son Güncelleme: {new Date(t.updated_at).toLocaleString()}</div>
            </div>
          ))}
          {topologies.length === 0 && <div style={{gridColumn:'1/-1', textAlign:'center', padding:'60px', color:'#94a3b8'}}>Henüz bir topoloji oluşturulmadı.</div>}
        </div>
      </div>
    );
  }

  const containerStyle = isFullScreen ? { position:'fixed', top:0, left:0, width:'100vw', height:'100vh', zIndex:2000, background:'#f8fafc', display:'flex', flexDirection:'column' } : { height:'calc(100vh - 180px)', display:'flex', flexDirection:'column' };

  return (
    <div className="topology-editor fade-in" style={containerStyle}>
      <div style={{background:'white', padding:'12px 25px', borderRadius:isFullScreen?0:'20px', border:'1px solid #e2e8f0', marginBottom:isFullScreen?0:'15px', display:'flex', justifyContent:'space-between', alignItems:'center', boxShadow:'0 4px 6px -1px rgba(0,0,0,0.05)', zIndex:10}}>
        <div style={{display:'flex', gap:'8px', alignItems:'center'}}>
          <button onClick={() => setCurrentTopo(null)} style={{marginRight:'10px', padding:'8px', borderRadius:'10px', border:'1px solid #e2e8f0', background:'white', cursor:'pointer'}} title="Geri Dön"><ArrowLeft size={18}/></button>
          <div style={{height:'24px', width:'1px', background:'#e2e8f0', marginRight:'10px'}}></div>
          <button onClick={() => setTool('move')} style={{padding:'8px 12px', borderRadius:'10px', border: tool==='move'?'2px solid var(--primary)':'1px solid #e2e8f0', background: tool==='move'?'#eff6ff':'white', cursor:'pointer', fontWeight:'700'}} title="Sürükleme Modu"><Activity size={16}/> Sürükle</button>
          <button onClick={() => setTool('device')} style={{padding:'8px 12px', borderRadius:'10px', border: tool==='device'?'2px solid var(--primary)':'1px solid #e2e8f0', background: tool==='device'?'#eff6ff':'white', cursor:'pointer', fontWeight:'700'}} title="Cihaz Ekle"><Server size={16}/> Cihaz</button>
          <button onClick={() => setTool('cable')} style={{padding:'8px 12px', borderRadius:'10px', border: tool==='cable'?'2px solid var(--primary)':'1px solid #e2e8f0', background: tool==='cable'?'#eff6ff':'white', cursor:'pointer', fontWeight:'700'}} title="Kablo Çek"><LinkIcon size={16}/> Kablo</button>
          <button onClick={() => setTool('box')} style={{padding:'8px 12px', borderRadius:'10px', border: tool==='box'?'2px solid var(--primary)':'1px solid #e2e8f0', background: tool==='box'?'#eff6ff':'white', cursor:'pointer', fontWeight:'700'}} title="Alan/Kutu"><Plus size={16}/> Kutu</button>
          <button onClick={() => setTool('text')} style={{padding:'8px 12px', borderRadius:'10px', border: tool==='text'?'2px solid var(--primary)':'1px solid #e2e8f0', background: tool==='text'?'#eff6ff':'white', cursor:'pointer', fontWeight:'700'}} title="Yazı"><Plus size={16}/> Yazı</button>
          <button onClick={() => setTool('delete')} style={{padding:'8px 12px', borderRadius:'10px', border: tool==='delete'?'2px solid #ef4444':'1px solid #e2e8f0', background: tool==='delete'?'#fef2f2':'white', cursor:'pointer', fontWeight:'700', color:tool==='delete'?'#ef4444':'#64748b'}} title="Silme Modu"><Trash2 size={16}/> Sil</button>
        </div>
        <div style={{display:'flex', gap:'12px', alignItems:'center'}}>
          <span 
            onClick={() => handleRenameTopo(currentTopo.id, currentTopo.name, { stopPropagation: () => {} })}
            style={{fontSize:'13px', fontWeight:'800', color:'#1e293b', cursor:'pointer', borderBottom:'1px dashed #cbd5e1'}}
            title="Yeniden Adlandır"
          >
            {currentTopo.name}
          </span>
          <div style={{height:'24px', width:'1px', background:'#e2e8f0'}}></div>
          <button onClick={handleManualSave} style={{padding:'8px 20px', borderRadius:'10px', border:'none', background:'var(--primary)', color:'white', cursor:'pointer', fontWeight:'700', display:'flex', alignItems:'center', gap:'8px'}}><Save size={16}/> Kaydet</button>
          <button onClick={() => setIsFullScreen(!isFullScreen)} style={{padding:'8px 12px', borderRadius:'10px', border:'1px solid #e2e8f0', background:'white', cursor:'pointer'}} title="Tam Ekran"><Monitor size={16}/></button>
        </div>
      </div>

      <div style={{flex:1, background:'#f1f5f9', borderRadius:isFullScreen?0:'24px', border:isFullScreen?'none':'2px dashed #e2e8f0', position:'relative', overflow:'hidden'}} onMouseMove={onMouseMove} onMouseUp={handleMouseUp} onMouseDown={handleBgMouseDown} onWheel={handleWheel}>
        <svg ref={svgRef} width="100%" height="100%" onClick={handleSvgClick} style={{cursor: isPanning ? 'grabbing' : (tool==='move'?'default': tool==='delete'?'no-drop' : 'crosshair'), background: 'radial-gradient(#cbd5e1 1px, transparent 1px)', backgroundSize: `${20 * transform.k}px ${20 * transform.k}px`, backgroundPosition: `${transform.x}px ${transform.y}px`}}>
          <g transform={`translate(${transform.x}, ${transform.y}) scale(${transform.k})`}>
            {edges.map(edge => {
              const fromNode = nodes.find(n => n.id === edge.from);
              const toNode = nodes.find(n => n.id === edge.to);
              if (!fromNode || !toNode) return null;
              
              const points = [
                { x: fromNode.x, y: fromNode.y },
                ...(edge.waypoints || []),
                { x: toNode.x, y: toNode.y }
              ];
              
              const polylinePoints = points.map(p => `${p.x},${p.y}`).join(' ');
              
              return (
                <g key={edge.id}>
                  <polyline 
                    points={polylinePoints} 
                    fill="none"
                    stroke={tool==='delete'?'#ef4444':'#94a3b8'} 
                    strokeWidth={10 / transform.k} 
                    strokeOpacity={tool==='delete'?0.5:0} 
                    style={{cursor:tool==='delete'?'pointer':'default', pointerEvents:'stroke'}} 
                    onClick={(e) => onEdgeClick(edge.id, e)}
                    onContextMenu={(e) => onEdgeContextMenu(edge.id, e)}
                  />
                  <polyline 
                    points={polylinePoints} 
                    fill="none"
                    stroke={tool==='delete'?'#ef4444':'#94a3b8'} 
                    strokeWidth={4 / transform.k} 
                    strokeOpacity={tool==='delete'?0.5:1} 
                    pointerEvents="none"
                  />
                  {(tool === 'move' || tool === 'select' || tool === 'cable') && (edge.waypoints || []).map((wp, idx) => (
                    <circle 
                      key={`${edge.id}-wp-${idx}`}
                      cx={wp.x} 
                      cy={wp.y} 
                      r={6 / transform.k} 
                      fill="white" 
                      stroke="var(--primary)" 
                      strokeWidth={2 / transform.k} 
                      style={{cursor:'move'}}
                      onMouseDown={(e) => onWaypointMouseDown(edge.id, idx, e)}
                    />
                  ))}
                </g>
              );
            })}

            {cableStart && (() => {
              const startNode = nodes.find(n => n.id === cableStart);
              if (!startNode) return null;
              const { x, y } = getCoords(lastMousePos); // We need mouse pos in SVG coords
              return (
                <line 
                  x1={startNode.x} y1={startNode.y} 
                  x2={x} y2={y} 
                  stroke="var(--primary)" 
                  strokeWidth={2 / transform.k} 
                  strokeDasharray="5,5" 
                  pointerEvents="none" 
                />
              );
            })()}

            {nodes.map(node => {
              const customIcon = customIcons.find(icon => icon.id === node.customIconId);
              const isSelected = editingNode && editingNode.id === node.id;
              
              return (
                <g key={node.id} transform={`translate(${node.x}, ${node.y})`} onMouseDown={(e) => onMouseDown(node.id, e)} onClick={(e) => onNodeClick(node.id, e)} onContextMenu={(e) => onNodeContextMenu(node.id, e)} style={{cursor: tool==='move'?'move':'pointer', userSelect:'none'}}>
                  {node.type === 'device' && (
                    <>
                      <circle r="35" fill="white" stroke={tool==='delete'?'#ef4444':(isSelected || cableStart===node.id ?'var(--primary)':'#e2e8f0')} strokeWidth={isSelected?3:2} style={{transition:'all 0.2s'}} />
                      {customIcon ? (
                        <image href={customIcon.data} x="-22" y="-22" width="44" height="44" />
                      ) : (
                        <Server size={28} x="-14" y="-14" style={{color:tool==='delete'?'#ef4444':'var(--primary)'}} />
                      )}
                      <text y="50" textAnchor="middle" style={{fontSize:'12px', fontWeight:'800', fill:'#1e293b'}}>{node.overriddenLabel || node.label}</text>
                      {node.overriddenLabel && <text y="64" textAnchor="middle" style={{fontSize:'10px', fill:'#94a3b8', fontWeight:'600'}}>({node.label})</text>}
                    </>
                  )}
                  {node.type === 'box' && (() => {
                    const w = node.width || 120;
                    const h = node.height || 80;
                    const isResizing = resizingNodeId === node.id;
                    const isEditing = editingNode && editingNode.id === node.id;
                    const handleSize = 8 / transform.k;
                    
                    const handles = [
                      { dir: 'nw', x: -w/2, y: -h/2 }, { dir: 'n', x: 0, y: -h/2 }, { dir: 'ne', x: w/2, y: -h/2 },
                      { dir: 'e', x: w/2, y: 0 }, { dir: 'se', x: w/2, y: h/2 }, { dir: 's', x: 0, y: h/2 },
                      { dir: 'sw', x: -w/2, y: h/2 }, { dir: 'w', x: -w/2, y: 0 }
                    ];

                    const labelY = node.labelPosition === 'top' ? -h/2 + 15 : (node.labelPosition === 'bottom' ? h/2 - 10 : 0);
                    const labelWeight = node.labelPosition === 'middle' ? '700' : '800';
                    const labelSize = node.labelPosition === 'middle' ? 13 : 14;

                    return (
                      <>
                        <rect x={-w/2} y={-h/2} width={w} height={h} rx="12" fill="rgba(255,255,255,0.6)" stroke={tool==='delete'?'#ef4444':((isResizing || isEditing)?'var(--primary)':'#e2e8f0')} strokeWidth={(isResizing || isEditing)?2:1} />
                        {node.label && (
                          <text 
                            x="0" 
                            y={labelY} 
                            textAnchor="middle" 
                            dominantBaseline="middle" 
                            style={{
                              fontSize:`${labelSize}px`, 
                              fontWeight:labelWeight, 
                              fill:'#1e293b', 
                              pointerEvents:'none',
                              textShadow: node.labelPosition !== 'middle' ? '0 1px 2px rgba(255,255,255,0.8)' : 'none'
                            }}
                          >
                            {node.label}
                          </text>
                        )}
                        {isResizing && (tool === 'move' || tool === 'select') && handles.map(hd => (
                          <rect 
                            key={hd.dir}
                            x={hd.x - handleSize/2} y={hd.y - handleSize/2} 
                            width={handleSize} height={handleSize} 
                            fill="white" stroke="var(--primary)" strokeWidth={1/transform.k}
                            style={{cursor: `${hd.dir}-resize` }}
                            onMouseDown={(e) => {
                              e.stopPropagation();
                              setResizingNodeId(node.id);
                              setResizeDir(hd.dir);
                            }}
                          />
                        ))}
                      </>
                    );
                  })()}
                  {node.type === 'text' && (
                    <text 
                      textAnchor="middle" 
                      dominantBaseline="middle" 
                      style={{
                        fontSize: `${(node.fontSize || 16)}px`, 
                        fontFamily: node.fontFamily || 'inherit',
                        fontWeight: '900', 
                        fill: tool==='delete' ? '#ef4444' : '#0f172a'
                      }}
                    >
                      {node.label}
                    </text>
                  )}
                </g>
              );
            })}
          </g>
        </svg>
      </div>

      {isDeviceModalOpen && (
        <div className="modal-overlay" style={{position:'fixed', top:0, left:0, right:0, bottom:0, background:'rgba(15,23,42,0.6)', backdropFilter:'blur(4px)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:3000}}>
          <div style={{background:'white', width:'400px', borderRadius:'24px', padding:'30px'}}>
            <h3 style={{marginBottom:'20px'}}>Cihaz Seçin</h3>
            <div style={{maxHeight:'300px', overflowY:'auto', display:'flex', flexDirection:'column', gap:'10px'}}>
              {devices.map(d => (
                <div key={d.id} onClick={() => {
                  setNodes([...nodes, { id: uuidv4(), x: pendingNode.x, y: pendingNode.y, type: 'device', deviceId: d.id, label: d.name, ip: d.ip_address }]);
                  setIsModalOpen(false);
                }} style={{padding:'12px 15px', borderRadius:'12px', border:'1px solid #e2e8f0', cursor:'pointer', display:'flex', justifyContent:'space-between'}}>
                  <span style={{fontWeight:'700'}}>{d.name}</span>
                  <span style={{fontSize:'12px', color:'#64748b'}}>{d.ip_address}</span>
                </div>
              ))}
            </div>
            <button onClick={() => setIsModalOpen(false)} style={{width:'100%', marginTop:'20px', padding:'12px', borderRadius:'12px', border:'1px solid #e2e8f0', background:'white', cursor:'pointer'}}>İptal</button>
          </div>
        </div>
      )}

      {isNodeEditModalOpen && editingNode && (
        <div className="modal-overlay" style={{position:'fixed', top:0, left:0, right:0, bottom:0, background:'rgba(15,23,42,0.6)', backdropFilter:'blur(4px)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:3000}}>
          <div style={{background:'white', width:'450px', borderRadius:'24px', padding:'30px', boxShadow:'0 25px 50px -12px rgba(0,0,0,0.5)'}}>
            <h3 style={{marginBottom:'20px', fontSize:'1.25rem', fontWeight:'800'}}>{editingNode.type === 'text' ? 'Yazı Özellikleri' : (editingNode.type === 'box' ? 'Kutu Özellikleri' : 'Cihaz Özellikleri')}</h3>
            <div style={{display:'grid', gap:'20px'}}>
              <div>
                <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>{editingNode.type === 'text' ? 'Yazı İçeriği' : (editingNode.type === 'box' ? 'Kutu Başlığı' : 'Görünen Ad (Override)')}</label>
                <input 
                  type="text" 
                  value={editingNode.type === 'text' ? (editingNode.label || '') : (editingNode.type === 'box' ? (editingNode.label || '') : (editingNode.overriddenLabel || ''))} 
                  onChange={e => editingNode.type === 'text' || editingNode.type === 'box' ? setEditingNode({...editingNode, label: e.target.value}) : setEditingNode({...editingNode, overriddenLabel: e.target.value})} 
                  placeholder={editingNode.label}
                  style={{width:'100%', padding:'12px', borderRadius:'12px', border:'1px solid #e2e8f0'}} 
                />
                {editingNode.type === 'device' && <p style={{fontSize:'11px', color:'#94a3b8', marginTop:'5px'}}>Gerçek Ad: {editingNode.label}</p>}
              </div>

              {editingNode.type === 'box' && (
                <div>
                  <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Başlık Konumu</label>
                  <div style={{display:'flex', gap:'10px', marginTop:'8px'}}>
                    {[
                      { id: 'top', label: 'Üst' },
                      { id: 'middle', label: 'Orta' },
                      { id: 'bottom', label: 'Alt' }
                    ].map(pos => (
                      <button 
                        key={pos.id}
                        onClick={() => setEditingNode({...editingNode, labelPosition: pos.id})}
                        style={{
                          flex:1, padding:'10px', borderRadius:'10px', border: editingNode.labelPosition === pos.id ? '2px solid var(--primary)' : '1px solid #e2e8f0',
                          background: editingNode.labelPosition === pos.id ? '#eff6ff' : 'white', fontWeight:'700', fontSize:'12px', cursor:'pointer'
                        }}
                      >
                        {pos.label}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {editingNode.type === 'text' && (
                <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'15px'}}>
                  <div>
                    <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Yazı Boyutu (px)</label>
                    <input 
                      type="number" 
                      value={editingNode.fontSize || 16} 
                      onChange={e => setEditingNode({...editingNode, fontSize: parseInt(e.target.value) || 16})} 
                      style={{width:'100%', padding:'12px', borderRadius:'12px', border:'1px solid #e2e8f0'}} 
                    />
                  </div>
                  <div>
                    <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Yazı Tipi</label>
                    <select 
                      value={editingNode.fontFamily || 'inherit'} 
                      onChange={e => setEditingNode({...editingNode, fontFamily: e.target.value})} 
                      style={{width:'100%', padding:'12px', borderRadius:'12px', border:'1px solid #e2e8f0', background:'white'}}
                    >
                      <option value="inherit">Varsayılan</option>
                      <option value="Arial">Arial</option>
                      <option value="Courier New">Courier New</option>
                      <option value="Georgia">Georgia</option>
                      <option value="Times New Roman">Times New Roman</option>
                      <option value="Verdana">Verdana</option>
                    </select>
                  </div>
                </div>
              )}

              {editingNode.type === 'device' && (
                <div>
                  <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b'}}>Özel İkon</label>
                  <div style={{display:'grid', gridTemplateColumns:'repeat(auto-fill, minmax(60px, 1fr))', gap:'10px', marginTop:'10px', maxHeight:'150px', overflowY:'auto', padding:'10px', border:'1px solid #f1f5f9', borderRadius:'12px'}}>
                    <div 
                      onClick={() => setEditingNode({...editingNode, customIconId: null})}
                      style={{padding:'10px', borderRadius:'10px', border: !editingNode.customIconId?'2px solid var(--primary)':'1px solid #e2e8f0', cursor:'pointer', textAlign:'center'}}
                    >
                      <Server size={24} color="#94a3b8" />
                    </div>
                    {customIcons.map(icon => (
                      <div 
                        key={icon.id}
                        onClick={() => setEditingNode({...editingNode, customIconId: icon.id})}
                        style={{padding:'10px', borderRadius:'10px', border: editingNode.customIconId===icon.id?'2px solid var(--primary)':'1px solid #e2e8f0', cursor:'pointer', textAlign:'center'}}
                      >
                        <img src={icon.data} alt={icon.name} style={{width:'32px', height:'32px', objectFit:'contain'}} />
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div style={{display:'flex', gap:'10px', marginTop:'10px'}}>
                <button onClick={() => setIsNodeEditModalOpen(false)} style={{flex:1, padding:'12px', borderRadius:'12px', border:'1px solid #e2e8f0', background:'white', fontWeight:'700', cursor:'pointer'}}>İptal</button>
                <button 
                  onClick={() => {
                    const updates = editingNode.type === 'text' 
                      ? { label: editingNode.label, fontSize: editingNode.fontSize, fontFamily: editingNode.fontFamily }
                      : (editingNode.type === 'box' ? { label: editingNode.label } : { overriddenLabel: editingNode.overriddenLabel, customIconId: editingNode.customIconId });
                    updateNodeSettings(editingNode.id, updates);
                  }} 
                  style={{flex:1, padding:'12px', borderRadius:'12px', border:'none', background:'var(--primary)', color:'white', fontWeight:'700', cursor:'pointer'}}
                >
                  Uygula
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {contextMenu && (
        <div style={{position:'fixed', top:contextMenu.y, left:contextMenu.x, background:'white', border:'1px solid #e2e8f0', borderRadius:'12px', padding:'8px', boxShadow:'0 10px 15px -3px rgba(0,0,0,0.1)', zIndex:4000, minWidth:'180px'}}>
          {contextMenu.type === 'node' ? (
            <>
              <button onClick={() => startEditNode(contextMenu.nodeId)} style={{display:'flex', alignItems:'center', gap:'10px', width:'100%', padding:'10px 15px', border:'none', background:'none', cursor:'pointer', borderRadius:'8px', fontSize:'13px', fontWeight:'600', color:'#1e293b'}} onMouseOver={e=>e.currentTarget.style.background='#f1f5f9'} onMouseOut={e=>e.currentTarget.style.background='none'}><Edit size={16}/> Düzenle</button>
              {contextMenu.nodeType === 'box' && (
                <button onClick={() => startResize(contextMenu.nodeId)} style={{display:'flex', alignItems:'center', gap:'10px', width:'100%', padding:'10px 15px', border:'none', background:'none', cursor:'pointer', borderRadius:'8px', fontSize:'13px', fontWeight:'600', color:'#1e293b'}} onMouseOver={e=>e.currentTarget.style.background='#f1f5f9'} onMouseOut={e=>e.currentTarget.style.background='none'}><Plus size={16}/> Boyutlandır</button>
              )}
              <button onClick={() => bringToFront(contextMenu.nodeId)} style={{display:'flex', alignItems:'center', gap:'10px', width:'100%', padding:'10px 15px', border:'none', background:'none', cursor:'pointer', borderRadius:'8px', fontSize:'13px', fontWeight:'600', color:'#1e293b'}} onMouseOver={e=>e.currentTarget.style.background='#f1f5f9'} onMouseOut={e=>e.currentTarget.style.background='none'}><ChevronUp size={16}/> Öne Getir</button>
              <button onClick={() => sendToBack(contextMenu.nodeId)} style={{display:'flex', alignItems:'center', gap:'10px', width:'100%', padding:'10px 15px', border:'none', background:'none', cursor:'pointer', borderRadius:'8px', fontSize:'13px', fontWeight:'600', color:'#1e293b'}} onMouseOver={e=>e.currentTarget.style.background='#f1f5f9'} onMouseOut={e=>e.currentTarget.style.background='none'}><ChevronDown size={16}/> Geriye Götür</button>
              <div style={{height:'1px', background:'#f1f5f9', margin:'4px 0'}}></div>
              <button onClick={() => deleteNode(contextMenu.nodeId)} style={{display:'flex', alignItems:'center', gap:'10px', width:'100%', padding:'10px 15px', border:'none', background:'none', cursor:'pointer', borderRadius:'8px', fontSize:'13px', fontWeight:'600', color:'#ef4444'}} onMouseOver={e=>e.currentTarget.style.background='#fef2f2'} onMouseOut={e=>e.currentTarget.style.background='none'}><Trash2 size={16}/> Sil</button>
            </>
          ) : (
            <>
              <button onClick={() => resetEdge(contextMenu.edgeId)} style={{display:'flex', alignItems:'center', gap:'10px', width:'100%', padding:'10px 15px', border:'none', background:'none', cursor:'pointer', borderRadius:'8px', fontSize:'13px', fontWeight:'600', color:'#1e293b'}} onMouseOver={e=>e.currentTarget.style.background='#f1f5f9'} onMouseOut={e=>e.currentTarget.style.background='none'}><RefreshCw size={16}/> Sıfırla (Noktaları Sil)</button>
              <div style={{height:'1px', background:'#f1f5f9', margin:'4px 0'}}></div>
              <button onClick={() => deleteEdge(contextMenu.edgeId)} style={{display:'flex', alignItems:'center', gap:'10px', width:'100%', padding:'10px 15px', border:'none', background:'none', cursor:'pointer', borderRadius:'8px', fontSize:'13px', fontWeight:'600', color:'#ef4444'}} onMouseOver={e=>e.currentTarget.style.background='#fef2f2'} onMouseOut={e=>e.currentTarget.style.background='none'}><Trash2 size={16}/> Kabloyu Sil</button>
            </>
          )}
        </div>
      )}
    </div>
  );
};

// --- Switch Analysis View ---
const SwitchAnalysisView = ({ API_URL, onStartAnalysis, devices = [] }) => {
  const [vendor, setVendor] = useState('cisco');
  const [method, setMethod] = useState('file'); // 'file' | 'ssh'
  const [sshForm, setSshForm] = useState({ host: '', port: '22', username: '', password: '' });
  const [loading, setLoading] = useState(false);

  const handleDeviceSelect = (e) => {
    const devId = e.target.value;
    if (!devId) {
      setSshForm({ host: '', port: '22', username: '', password: '' });
      return;
    }
    const dev = devices.find(d => String(d.id) === devId);
    if (dev) {
      setSshForm({
        ...sshForm,
        host: dev.ip_address || '',
      });
    }
  };

  const handleFileChange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setLoading(true);
    const formData = new FormData();
    formData.append('file', file);
    formData.append('vendor', vendor);
    formData.append('model', 'generic');

    try {
      const res = await axios.post(`${API_URL}/switch-scan/file`, formData);
      onStartAnalysis(res.data.fileUid);
    } catch (err) {
      alert('Dosya yukleme hatasi: ' + (err.response?.data?.error || err.message));
    } finally {
      setLoading(false);
    }
  };

  const handleSshScan = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await axios.post(`${API_URL}/switch-scan/ssh`, { ...sshForm, vendor, model: 'generic' });
      onStartAnalysis(res.data.fileUid);
    } catch (err) {
      alert('SSH Tarama hatasi: ' + (err.response?.data?.error || err.message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="switch-analysis-view fade-in">
      <div style={{background:'white', padding:'30px', borderRadius:'24px', border:'1px solid #e2e8f0', boxShadow:'0 10px 15px -3px rgba(0,0,0,0.05)'}}>
        <h3 style={{fontSize:'1.25rem', fontWeight:'800', marginBottom:'20px'}}>Switch Güvenlik Analizi</h3>
        
        <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'30px'}}>
          {/* Step 1: Vendor Selection */}
          <div style={{borderRight:'1px solid #e2e8f0', paddingRight:'30px'}}>
            <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b', display:'block', marginBottom:'10px'}}>1. MARKA (VENDOR) SEÇİN</label>
            <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'10px'}}>
              {[
                { id: 'cisco', name: 'Cisco', icon: <Server size={20}/> },
                { id: 'arista', name: 'Arista', icon: <Zap size={20}/> },
                { id: 'huawei', name: 'Huawei', icon: <Activity size={20}/> }
              ].map((v) => (
                <div 
                  key={v.id} 
                  onClick={() => setVendor(v.id)}
                  style={{
                    padding:'15px', borderRadius:'15px', border:`2px solid ${vendor === v.id ? 'var(--primary)' : '#f1f5f9'}`,
                    background: vendor === v.id ? '#eff6ff' : 'white', cursor:'pointer', textAlign:'center', transition:'all 0.2s'
                  }}
                >
                  <div style={{color: vendor === v.id ? 'var(--primary)' : '#94a3b8', marginBottom:'8px'}}>{v.icon}</div>
                  <div style={{fontSize:'13px', fontWeight:'700', color: vendor === v.id ? '#1e40af' : '#475569'}}>{v.name}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Step 2: Method Selection */}
          <div>
            <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b', display:'block', marginBottom:'10px'}}>2. TARAMA YÖNTEMİ</label>
            <div style={{display:'flex', gap:'10px', marginBottom:'20px'}}>
              <button 
                onClick={() => setMethod('file')}
                style={{
                  flex:1, padding:'12px', borderRadius:'12px', border:'none', 
                  background: method === 'file' ? '#0f172a' : '#f1f5f9', color: method === 'file' ? 'white' : '#64748b',
                  fontWeight:'700', cursor:'pointer'
                }}
              >
                <FileText size={18} style={{verticalAlign:'middle', marginRight:'8px'}}/> Dosyadan (.conf, .txt)
              </button>
              <button 
                onClick={() => setMethod('ssh')}
                style={{
                  flex:1, padding:'12px', borderRadius:'12px', border:'none', 
                  background: method === 'ssh' ? '#0f172a' : '#f1f5f9', color: method === 'ssh' ? 'white' : '#64748b',
                  fontWeight:'700', cursor:'pointer'
                }}
              >
                <Terminal size={18} style={{verticalAlign:'middle', marginRight:'8px'}}/> Canlı SSH Bağlantısı
              </button>
            </div>

            {method === 'file' ? (
              <div style={{padding:'20px', border:'2px dashed #e2e8f0', borderRadius:'15px', textAlign:'center'}}>
                <Upload size={32} style={{color:'#94a3b8', marginBottom:'10px'}}/>
                <p style={{fontSize:'13px', color:'#64748b', marginBottom:'15px'}}>Seçilen <strong>{vendor.toUpperCase()}</strong> marka switch için konfigürasyon dosyasını yükleyin.</p>
                <input type="file" id="sw-up" onChange={handleFileChange} style={{display:'none'}} disabled={loading} />
                <label htmlFor="sw-up" style={{background:'var(--primary)', color:'white', padding:'10px 20px', borderRadius:'10px', fontWeight:'700', cursor:'pointer', opacity: loading ? 0.6 : 1}}>
                  {loading ? 'Yükleniyor...' : 'Dosya Seç ve Analiz Et'}
                </label>
              </div>
            ) : (
              <div style={{display:'grid', gap:'15px'}}>
                <div>
                  <label style={{fontSize:'11px', fontWeight:'700', color:'#64748b', marginBottom:'5px', display:'block'}}>KAYITLI CİHAZLARDAN SEÇİN</label>
                  <select 
                    onChange={handleDeviceSelect}
                    style={{width:'100%', padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0', background:'white', fontSize:'14px'}}
                  >
                    <option value="">-- Cihaz Seçin (Opsiyonel) --</option>
                    {devices.map(d => (
                      <option key={d.id} value={d.id}>{d.name || d.ip_address} ({d.ip_address})</option>
                    ))}
                  </select>
                </div>

                <div style={{height:'1px', background:'#f1f5f9', margin:'5px 0'}}></div>

                <form onSubmit={handleSshScan} style={{display:'grid', gap:'12px'}}>
                  <div style={{display:'grid', gridTemplateColumns:'2fr 1fr', gap:'10px'}}>
                    <input type="text" placeholder="IP Adresi" value={sshForm.host} onChange={e => setSshForm({...sshForm, host: e.target.value})} style={{padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required />
                    <input type="text" placeholder="Port (22)" value={sshForm.port} onChange={e => setSshForm({...sshForm, port: e.target.value})} style={{padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}} />
                  </div>
                  <input type="text" placeholder="Kullanıcı Adı" value={sshForm.username} onChange={e => setSshForm({...sshForm, username: e.target.value})} style={{padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required />
                  <input type="password" placeholder="Şifre" value={sshForm.password} onChange={e => setSshForm({...sshForm, password: e.target.value})} style={{padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required />
                  <button type="submit" disabled={loading} style={{background:'var(--primary)', color:'white', border:'none', padding:'12px', borderRadius:'10px', fontWeight:'700', cursor:'pointer', opacity: loading ? 0.6 : 1}}>
                    {loading ? 'Bağlanıyor ve Config Çekiliyor...' : 'Bağlan ve Tara'}
                  </button>
                </form>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

// --- Dashboard Component ---
function Dashboard() {
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentView, setCurrentView] = useState('recent'); // 'recent' | 'devices' | 'monitor' | 'hitcounts' | 'performance'
  const [devices, setDevices] = useState([]);
  const [snmpDevices, setSnmpDevices] = useState([]);
  const [newDevice, setNewDevice] = useState({ name: '', ip_address: '', api_key: '', vdom: 'root' });
  const [editingDevice, setEditingDevice] = useState(null);
  const [isAddDeviceModalOpen, setIsAddDeviceModalOpen] = useState(false);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [lastMonitorCheck, setLastMonitorCheck] = useState(null);
  const [autoRefreshInterval, setAutoRefreshInterval] = useState(60); // saniye cinsinden
  const [scanSource, setScanSource] = useState(null); // null | 'file' | 'deviceApi'
  const [selectedScanDeviceId, setSelectedScanDeviceId] = useState('');
  const [isDeviceScanLoading, setIsDeviceScanLoading] = useState(false);
  const [unreadCVE, setUnreadCVE] = useState(0);
  const [isDebugMenuOpen, setIsDebugMenuOpen] = useState(false);
  const [scanLogs, setScanLogs] = useState([]);
  const [activeScanId, setActiveScanId] = useState(null);
  const devicesRef = useRef([]);

  const addScanLog = (message, type = 'info', scanId = null) => {
    const scanIdToUse = scanId || activeScanId;
    setScanLogs(prev => [...prev, {
      id: uuidv4(),
      timestamp: new Date().toLocaleTimeString('tr-TR'),
      message,
      type, // 'info' | 'success' | 'error' | 'warning'
      scanId: scanIdToUse
    }]);
  };

  const startScan = (scanName) => {
    const newScanId = uuidv4();
    setActiveScanId(newScanId);
    addScanLog(`${scanName} taraması başlatıldı`, 'info', newScanId);
    return newScanId;
  };

  const stopScan = (scanId) => {
    addScanLog('Tarama durduruldu', 'warning', scanId);
  };

  const completeScan = (scanId) => {
    addScanLog('Tarama tamamlandı', 'success', scanId);
  };

  const clearScanLogs = () => {
    setScanLogs([]);
    setActiveScanId(null);
  };

  const fetchUnreadCVE = async () => {
    try {
      const res = await axios.get(`${API_URL}/cve/unread-count`);
      setUnreadCVE(res.data.count);
    } catch (e) { console.error(e); }
  };

  const markCVEAsRead = async () => {
    try {
      await axios.post(`${API_URL}/cve/mark-read`);
      setUnreadCVE(0);
    } catch (e) { console.error(e); }
  };

  const fetchFiles = async () => {
    try {
      const f = await axios.get(`${API_URL}/uploaded-files`);
      setUploadedFiles(f.data);
    } catch (err) { console.error(err); }
  };

  const fetchDevices = async () => {
    try {
      const res = await axios.get(`${API_URL}/devices?api=true`);
      setDevices(res.data);
    } catch (err) { console.error(err); }
  };

  const fetchSnmpDevices = async () => {
    try {
      const res = await axios.get(`${API_URL}/devices?snmp=true`);
      setSnmpDevices(res.data);
    } catch (err) { console.error(err); }
  };

  const monitorDevices = async () => {
    setIsMonitoring(true);
    try {
      await axios.get(`${API_URL}/devices/monitor`);
      await Promise.all([fetchDevices(), fetchSnmpDevices()]);
      setLastMonitorCheck(new Date());
    } catch (err) { console.error('Monitor error:', err); }
    finally { setIsMonitoring(false); }
  };

  useEffect(() => { 
    fetchFiles(); 
    fetchDevices();
    fetchSnmpDevices();
    fetchUnreadCVE();
    
    // Initial monitor check
    monitorDevices();

    const cveInterval = setInterval(fetchUnreadCVE, 300000); // 5 dk'da bir kontrol
    return () => clearInterval(cveInterval);
  }, []);

  // Monitor'daki interval hem cihaz durumunu hem de HitCount/Performans verilerini tetikler.
  useEffect(() => {
    if (autoRefreshInterval > 0) {
      const autoSync = async () => {
        try {
          await axios.get(`${API_URL}/devices/monitor`);
          await fetchDevices();
          setLastMonitorCheck(new Date());

          const currentDevices = devicesRef.current || [];
          if (currentDevices.length === 0) return;

          await Promise.allSettled(
            currentDevices.map((d) => axios.post(`${API_URL}/devices/${d.id}/fetch-hits`))
          );

          await Promise.allSettled(
            currentDevices.map((d) => axios.post(`${API_URL}/devices/${d.id}/collect-metrics`))
          );
        } catch (err) {
          console.error('Auto sync error:', err);
        }
      };

      autoSync();
      const monitorInterval = setInterval(autoSync, autoRefreshInterval * 1000);
      return () => clearInterval(monitorInterval);
    }
  }, [autoRefreshInterval]);

  const simulateAnalysis = async (fileUid) => {
    const scanId = startScan('Konfigürasyon Analizi');
    setIsAnalyzing(true);
    setProgress(0);
    addScanLog(`Dosya UID: ${fileUid}`, 'info', scanId);
    
    const duration = 10000; 
    const interval = 100;
    const step = 100 / (duration / interval);
    const timer = setInterval(() => {
      setProgress(prev => {
        if (prev >= 99) { clearInterval(timer); return 99; }
        return prev + step;
      });
    }, interval);

    try {
      addScanLog('Konfigürasyon ayrıştırılıyor...', 'info', scanId);
      await axios.post(`${API_URL}/parse-config`, { fileUid });
      setProgress(100);
      addScanLog('Analiz başarıyla tamamlandı', 'success', scanId);
      completeScan(scanId);
      setTimeout(() => { setIsAnalyzing(false); fetchFiles(); }, 500);
    } catch (err) { 
      clearInterval(timer); 
      setIsAnalyzing(false); 
      addScanLog(`Analiz hatası: ${err.message}`, 'error', scanId);
      alert('Analiz hatası!'); 
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files[0]; if (!file) return;
    addScanLog(`Dosya yükleniyor: ${file.name} (${(file.size / 1024 / 1024).toFixed(2)} MB)`, 'info');
    const formData = new FormData(); formData.append('file', file);
    try {
      const res = await axios.post(`${API_URL}/upload-config`, formData);
      addScanLog(`Dosya başarıyla yüklendi`, 'success');
      simulateAnalysis(res.data.fileUid);
    } catch (err) { 
      addScanLog(`Yükleme hatası: ${err.message}`, 'error');
      alert('Yükleme hatası!'); 
    }
  };

  const handleDeviceApiScan = async () => {
    if (!selectedScanDeviceId) {
      alert('Lutfen API ile taranacak cihazi secin.');
      return;
    }

    const scanId = startScan('Cihaz API Taraması');
    const selectedDevice = devices.find(d => d.id === selectedScanDeviceId);
    addScanLog(`Cihaz: ${selectedDevice?.name || selectedDevice?.ip_address}`, 'info', scanId);

    try {
      setIsDeviceScanLoading(true);
      addScanLog(`${selectedDevice?.ip_address} adresine bağlanılıyor...`, 'info', scanId);
      const res = await axios.post(`${API_URL}/devices/${selectedScanDeviceId}/scan-config`);
      if (!res.data?.fileUid) throw new Error('Config dosyasi olusturulamadi.');
      addScanLog('Konfigürasyon başarıyla alındı', 'success', scanId);
      await simulateAnalysis(res.data.fileUid);
    } catch (err) {
      const errMsg = err?.response?.data?.error || 'Cihaz config cekme hatasi!';
      const errDetails = err?.response?.data?.details || '';
      const errSuggestion = err?.response?.data?.suggestion || '';
      const isOffline = err?.response?.status === 503 || err?.response?.data?.deviceStatus === 'offline';
      addScanLog(`Tarama hatası: ${errMsg}`, 'error', scanId);
      
      if (isOffline) {
        alert('⚠️ Cihaz Offline\n\nSeçili cihaz şu anda erişilebilir değil. Config çekebilmek için:\n• Cihazın açık ve ağda olduğundan emin olun\n• Monitoring sayfasından cihaz durumunu kontrol edin\n• API erişim ayarlarını doğrulayın');
      } else if (err?.response?.status === 403) {
        alert(`🔒 API Yetki Hatası\n\n${errMsg}\n\n${errSuggestion || 'API token için gerekli yetkiler eksik. FortiGate üzerinde API token ayarlarını kontrol edin.'}\n\nAlternatif: Config dosyasını manuel olarak indirip Upload sayfasından yükleyebilirsiniz.`);
      } else {
        alert(`❌ Hata\n\n${errMsg}${errDetails ? '\n\n' + errDetails : ''}`);
      }
    } finally {
      setIsDeviceScanLoading(false);
    }
  };

  const handleAddDevice = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${API_URL}/devices`, newDevice);
      setNewDevice({ name: '', ip_address: '', api_key: '', vdom: 'root' });
      setIsAddDeviceModalOpen(false);
      fetchDevices();
    } catch (err) { alert('Cihaz ekleme hatası!'); }
  };

  const handleUpdateDevice = async (e) => {
    e.preventDefault();
    try {
      await axios.put(`${API_URL}/devices/${editingDevice.id}`, editingDevice);
      setEditingDevice(null);
      fetchDevices();
    } catch (err) { alert('Güncelleme hatası!'); }
  };

  const handleDeleteDevice = async (id) => {
    if (!window.confirm('Cihazı silmek istediğinize emin misiniz?')) return;
    try {
      await axios.delete(`${API_URL}/devices/${id}`);
      fetchDevices();
    } catch (err) { alert('Silme hatası!'); }
  };

  useEffect(() => {
    devicesRef.current = devices;
    if (!selectedScanDeviceId && devices.length > 0) {
      setSelectedScanDeviceId(String(devices[0].id));
    }
  }, [devices]);

  return (
    <div className="app-layout">
      {isAnalyzing && <CircularLoader progress={progress} />}
      <DebugMenu 
        isOpen={isDebugMenuOpen} 
        onClose={() => setIsDebugMenuOpen(false)} 
        scanLogs={scanLogs} 
        onStopScan={stopScan}
        onClearLogs={clearScanLogs}
      />
      
      {/* Cihaz Ekleme Modalı */}
      {isAddDeviceModalOpen && (
        <div className="modal-overlay" style={{position:'fixed', top:0, left:0, right:0, bottom:0, background:'rgba(15,23,42,0.6)', backdropFilter:'blur(4px)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:1000}}>
          <div style={{background:'white', width:'500px', maxWidth:'96vw', borderRadius:'24px', padding:'30px', boxShadow:'0 25px 50px -12px rgba(0,0,0,0.25)'}}>
            <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'20px'}}>
              <h3 style={{margin:0, fontSize:'1.25rem', fontWeight:'800'}}>Yeni FortiGate Cihazı Ekle</h3>
              <button onClick={() => setIsAddDeviceModalOpen(false)} style={{background:'none', border:'none', cursor:'pointer', color:'#64748b'}}><X size={24}/></button>
            </div>
            <form onSubmit={handleAddDevice} style={{display:'grid', gap:'15px'}}>
              <div>
                <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b', display:'block', marginBottom:'5px'}}>CİHAZ ADI (OPSİYONEL)</label>
                <input type="text" placeholder="Örn: FW-Merkez" value={newDevice.name} onChange={e => setNewDevice({...newDevice, name: e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} />
              </div>
              <div>
                <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b', display:'block', marginBottom:'5px'}}>IP ADRESİ</label>
                <input type="text" placeholder="10.0.0.1" value={newDevice.ip_address} onChange={e => setNewDevice({...newDevice, ip_address: e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required />
              </div>
              <div>
                <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b', display:'block', marginBottom:'5px'}}>API KEY (TOKEN)</label>
                <input type="password" placeholder="FortiGate API Token" value={newDevice.api_key} onChange={e => setNewDevice({...newDevice, api_key: e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required />
              </div>
              <div>
                <label style={{fontSize:'12px', fontWeight:'700', color:'#64748b', display:'block', marginBottom:'5px'}}>VDOM</label>
                <input type="text" placeholder="root" value={newDevice.vdom} onChange={e => setNewDevice({...newDevice, vdom: e.target.value})} style={{width:'100%', padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0'}} />
              </div>
              <div style={{display:'flex', gap:'10px', marginTop:'10px'}}>
                <button type="button" onClick={() => setIsAddDeviceModalOpen(false)} style={{flex:1, padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0', background:'white', fontWeight:'700', cursor:'pointer'}}>İptal</button>
                <button type="submit" style={{flex:2, background:'var(--primary)', color:'white', border:'none', padding:'12px', borderRadius:'10px', fontWeight:'700', cursor:'pointer'}}>Cihazı Kaydet</button>
              </div>
            </form>
          </div>
        </div>
      )}

      <aside className="app-sidebar">
        <div className="sidebar-brand"><Shield size={32} style={{color:'#818cf8'}} /><h2>NSS ENGINE</h2></div>
        <nav className="sidebar-nav">
          <div className={`nav-item ${currentView === 'recent' ? 'active' : ''}`} onClick={() => setCurrentView('recent')} style={{cursor:'pointer'}}><Home size={20} /><span>Ana Panel</span></div>
          <div className={`nav-item ${currentView === 'deviceMgmt' ? 'active' : ''}`} onClick={() => setCurrentView('deviceMgmt')} style={{cursor:'pointer'}}><Monitor size={20} /><span>Cihaz Yönetimi</span></div>
          <div className={`nav-item ${currentView === 'networkScan' ? 'active' : ''}`} onClick={() => setCurrentView('networkScan')} style={{cursor:'pointer'}}><Search size={20} /><span>Ağ Tarama</span></div>
          <div className={`nav-item ${currentView === 'topology' ? 'active' : ''}`} onClick={() => setCurrentView('topology')} style={{cursor:'pointer'}}><Activity size={20} /><span>Topoloji</span></div>

          <div className="nav-group">            <div className={`nav-item ${currentView === 'firewallAnalysis' || currentView === 'hitcounts' ? 'active' : ''}`} onClick={() => setCurrentView('firewallAnalysis')} style={{cursor:'pointer'}}>
              <Shield size={20} /><span>Firewall Analizi</span>
            </div>
            {(currentView === 'firewallAnalysis' || currentView === 'hitcounts') && (
              <div className="sub-menu" style={{paddingLeft: '35px', display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '5px', marginBottom: '10px'}}>
                <div className={`nav-item sub ${currentView === 'firewallAnalysis' ? 'active' : ''}`} onClick={(e) => { e.stopPropagation(); setCurrentView('firewallAnalysis'); }} style={{fontSize: '13px', padding: '8px 12px', cursor:'pointer', opacity: currentView === 'firewallAnalysis' ? 1 : 0.7, background: 'transparent', border: 'none', display: 'flex', alignItems: 'center', gap: '10px', color: currentView === 'firewallAnalysis' ? 'white' : '#94a3b8'}}>
                  <Zap size={16} /> <span>Güvenlik Analizi</span>
                </div>
                <div className={`nav-item sub ${currentView === 'hitcounts' ? 'active' : ''}`} onClick={(e) => { e.stopPropagation(); setCurrentView('hitcounts'); }} style={{fontSize: '13px', padding: '8px 12px', cursor:'pointer', opacity: currentView === 'hitcounts' ? 1 : 0.7, background: 'transparent', border: 'none', display: 'flex', alignItems: 'center', gap: '10px', color: currentView === 'hitcounts' ? 'white' : '#94a3b8'}}>
                  <BarChart3 size={16} /> <span>Hit Count Analizi</span>
                </div>
              </div>
            )}
          </div>

          <div className={`nav-item ${currentView === 'switchAnalysis' ? 'active' : ''}`} onClick={() => setCurrentView('switchAnalysis')} style={{cursor:'pointer'}}><Monitor size={20} /><span>Switch Güvenlik Analizi</span></div>          <div className={`nav-item ${currentView === 'cve' ? 'active' : ''}`} onClick={() => setCurrentView('cve')} style={{cursor:'pointer', position:'relative'}}><AlertTriangle size={20} /><span>CVE Takibi</span>{unreadCVE > 0 && <span style={{position:'absolute', top:'10px', right:'15px', width:'8px', height:'8px', background:'#ef4444', borderRadius:'50%', border:'2px solid #1e293b'}}></span>}</div>
          <div className={`nav-item ${currentView === 'performance' ? 'active' : ''}`} onClick={() => setCurrentView('performance')} style={{cursor:'pointer'}}><Cpu size={20} /><span>Performans</span></div>
          <div className={`nav-item ${currentView === 'settings' ? 'active' : ''}`} onClick={() => setCurrentView('settings')} style={{cursor:'pointer'}}><SettingsIcon size={20} /><span>Ayarlar</span></div>
        </nav>

        <div className="sidebar-footer">
          <div className="version-info">{APP_VERSION}</div>
          <HealthIndicators />
        </div>
      </aside>
      <div className="app-main">
        <header className="app-topbar">
          <div className="welcome-msg"><h1>{currentView === 'recent' ? 'Güvenlik Paneli' : currentView === 'firewallAnalysis' ? 'Firewall Güvenlik Analizi' : currentView === 'deviceMgmt' ? 'Cihaz Yönetimi' : currentView === 'monitor' ? 'Cihaz Monitor' : currentView === 'hitcounts' ? 'HitCount Analizi' : currentView === 'performance' ? 'Performans & Metrikler' : currentView === 'cve' ? 'CVE Takibi' : currentView === 'switchAnalysis' ? 'Switch Güvenlik Analizi' : 'Sistem Ayarları'}</h1><p>{currentView === 'recent' ? 'Son analiz raporları ve sistem özeti' : currentView === 'firewallAnalysis' ? 'Dosya yükleyerek veya API üzerinden cihaz tarayarak güvenlik analizi başlatın' : currentView === 'deviceMgmt' ? 'Ağ cihazlarınızı merkezi olarak ekleyin ve yönetin' : currentView === 'monitor' ? 'Eklenen cihazların acik/kapali durumunu izleyin' : currentView === 'hitcounts' ? 'Politika hit count trendi ve gecmis analizi' : currentView === 'performance' ? 'CPU, Memory, VPN, Interface, HA Status, Certificates' : currentView === 'cve' ? 'Güncel Fortinet PSIRT ve CVE duyuruları' : currentView === 'switchAnalysis' ? 'Switch konfigürasyonlarını analiz edin' : 'LDAP, Sertifika ve Güvenlik Bilgi Tabanı yönetimi'}</p></div>
          <div style={{display:'flex', alignItems:'center', gap:'20px'}}>
            <button onClick={() => setIsDebugMenuOpen(true)} style={{position:'relative', cursor:'pointer', color:'#64748b', background:'none', border:'none', padding:'8px', display:'flex', alignItems:'center', justifyContent:'center', transition:'all 0.3s', borderRadius:'8px'}} className="debug-button" title="Debug Menüsünü Aç">
              <Terminal size={20} />
              {scanLogs.length > 0 && <span style={{position:'absolute', top:'0px', right:'0px', background:'#6366f1', color:'white', fontSize:'9px', fontWeight:'800', padding:'1px 4px', borderRadius:'8px', minWidth:'16px', textAlign:'center', boxShadow:'0 4px 10px rgba(99,102,241,0.4)'}}>{scanLogs.length}</span>}
            </button>
            <div onClick={() => setCurrentView('cve')} style={{position:'relative', cursor:'pointer', color: unreadCVE > 0 ? '#ef4444' : '#64748b', transition:'all 0.3s'}} className={unreadCVE > 0 ? 'pulse' : ''}>
              <Bell size={24} />
              {unreadCVE > 0 && <span style={{position:'absolute', top:'-5px', right:'-5px', background:'#ef4444', color:'white', fontSize:'10px', fontWeight:'800', padding:'2px 6px', borderRadius:'10px', boxShadow:'0 4px 10px rgba(239,68,68,0.4)'}}>{unreadCVE}</span>}
            </div>
            <div className="status-pill success"><CheckCircle2 size={14}/> Online</div>
          </div>
        </header>
        <div className="content-area">
          {currentView === 'recent' ? (
            <div className="recent-view fade-in" style={{display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', minHeight:'60vh', textAlign:'center', color:'#64748b'}}>
              <div style={{background:'#f8fafc', padding:'40px', borderRadius:'30px', border:'1px solid #e2e8f0', maxWidth:'500px'}}>
                <Shield size={60} style={{color:'#818cf8', marginBottom:'20px', opacity:0.5}} />
                <h2 style={{color:'#1e293b', marginBottom:'10px', fontWeight:'800'}}>NSS ENGINE Hoş Geldiniz</h2>
                <p>Güvenlik analizlerini başlatmak ve raporları yönetmek için yan menüdeki <strong>Firewall Güvenlik Analizi</strong> sekmesini kullanabilirsiniz.</p>
              </div>
            </div>
          ) : currentView === 'deviceMgmt' ? (
            <DeviceManagementView API_URL={API_URL} />
          ) : currentView === 'networkScan' ? (
            <NetworkScanView API_URL={API_URL} />
          ) : currentView === 'topology' ? (
            <TopologyView API_URL={API_URL} />
          ) : currentView === 'firewallAnalysis' ? (
            <div className="firewall-analysis-view fade-in">
              <div className="hero-upload-card" style={{display:'grid', gap:'16px', marginBottom:'40px'}}>
                {!scanSource && (
                  <>
                    <div className="hero-text">
                      <h2>Analiz Yöntemi Seçin</h2>
                      <p>Sistem yapılandırmasını nasıl analiz etmek istersiniz? Config dosyasını yükleyebilir veya ekli bir cihazdan otomatik çekebilirsiniz.</p>
                    </div>
                    <div style={{display:'flex', gap:'12px', flexWrap:'wrap'}}>
                      <button onClick={() => setScanSource('file')} style={{background:'var(--primary)', color:'white', border:'none', padding:'15px 25px', borderRadius:'12px', fontWeight:'700', cursor:'pointer', display:'inline-flex', alignItems:'center', gap:'10px'}}>
                        <Upload size={20}/> 1) Config Dosyası Yükle
                      </button>
                      <button onClick={() => setScanSource('deviceApi')} style={{background:'#0f172a', color:'white', border:'none', padding:'15px 25px', borderRadius:'12px', fontWeight:'700', cursor:'pointer', display:'inline-flex', alignItems:'center', gap:'10px'}}>
                        <Server size={20}/> 2) API ile Cihazdan Çek
                      </button>
                    </div>
                  </>
                )}

                {scanSource === 'file' && (
                  <>
                    <div className="hero-text"><h2>Dosyadan Tarama</h2><p>FortiGate konfigürasyon (.conf) dosyasını yükleyin, otomatik güvenlik analizi başlasın.</p></div>
                    <div style={{display:'flex', gap:'10px', alignItems:'center', flexWrap:'wrap'}}>
                      <input type="file" id="hero-up" onChange={handleFileUpload} style={{display:'none'}} />
                      <label htmlFor="hero-up" className="upload-btn-lg"><Upload size={24} /><span>DOSYA SEÇİN VE ANALİZ ET</span></label>
                      <button onClick={() => setScanSource(null)} style={{padding:'12px 18px', borderRadius:'12px', border:'1px solid #e2e8f0', background:'white', cursor:'pointer', fontWeight:'700'}}>Yöntemi Değiştir</button>
                    </div>
                  </>
                )}

                {scanSource === 'deviceApi' && (
                  <>
                    <div className="hero-text"><h2>API ile Cihazdan Tarama</h2><p>Bağlı olan FortiGate cihazınızdan güncel konfigürasyonu çekerek analizi başlatın.</p></div>
                    <div style={{display:'flex', gap:'10px', alignItems:'center', flexWrap:'wrap'}}>
                      <select value={selectedScanDeviceId} onChange={(e) => setSelectedScanDeviceId(e.target.value)} style={{padding:'12px', borderRadius:'10px', border:'1px solid #e2e8f0', minWidth:'320px', background:'white', fontSize:'14px'}}>
                        {devices.filter(d => d.connection_method === 'api').length === 0 && <option value="">API destekli cihaz bulunamadı</option>}
                        {devices.filter(d => d.connection_method === 'api').map((d) => (
                          <option key={d.id} value={d.id}>{d.name || d.ip_address} ({d.ip_address})</option>
                        ))}
                      </select>
                      <button onClick={handleDeviceApiScan} disabled={isDeviceScanLoading || devices.filter(d => d.connection_method === 'api').length === 0} style={{background:'var(--primary)', color:'white', border:'none', padding:'13px 25px', borderRadius:'12px', fontWeight:'700', cursor: isDeviceScanLoading ? 'not-allowed' : 'pointer', opacity: isDeviceScanLoading ? 0.7 : 1}}>
                        {isDeviceScanLoading ? 'Konfigürasyon Çekiliyor...' : 'Analizi Başlat'}
                      </button>
                      <button onClick={() => setScanSource(null)} style={{padding:'12px 18px', borderRadius:'12px', border:'1px solid #e2e8f0', background:'white', cursor:'pointer', fontWeight:'700'}}>Yöntemi Değiştir</button>
                    </div>
                    {devices.filter(d => d.connection_method === 'api').length === 0 && <p style={{margin:'10px 0 0', color:'#ef4444', fontSize:'13px', fontWeight:'600'}}>Bu özellik için önce "Cihaz Yönetimi" menüsünden <strong>API (REST)</strong> yöntemiyle bir cihaz eklemelisiniz.</p>}
                  </>
                )}
              </div>

              <div className="recent-reports-section" style={{marginTop: 0}}>
                <div className="section-header"><h3>Son Analiz Raporları</h3></div>
                <div className="report-list">
                  {uploadedFiles.map((f, idx) => (
                    <div key={`${f.id ?? f.file_uid ?? f.file_name ?? 'file'}-${idx}`} className="report-mini-card fade-in">
                      <div className="card-top"><div className="card-icon"><FileJson size={24}/></div></div>
                      <div className="card-body">
                        <h4>{f.file_name}</h4>
                        <div style={{display:'flex', gap:'15px', alignItems:'center', marginTop:'5px'}}>
                          <span className={`badge ${f.parse_status==='parsed'?'badge-success':'badge-warning'}`}>{f.parse_status==='parsed'?'Hazır':'Bekliyor'}</span>
                          <p style={{display:'flex', alignItems:'center', gap:'4px'}}><Clock size={12}/> {new Date(f.created_at).toLocaleDateString()} {new Date(f.created_at).toLocaleTimeString()}</p>
                        </div>
                      </div>
                      <div className="card-footer"><Link to={`/report/${f.file_uid}`} className="view-report-link">Raporu Aç <ChevronRight size={16}/></Link></div>
                    </div>
                  ))}
                  {uploadedFiles.length === 0 && <div style={{textAlign:'center', padding:'40px', color:'#64748b'}}>Henüz rapor bulunmuyor.</div>}
                </div>
              </div>
            </div>
          ) : currentView === 'switchAnalysis' ? (
            <SwitchAnalysisView API_URL={API_URL} onStartAnalysis={simulateAnalysis} devices={devices.filter(d => d.connection_method === 'snmp_ssh')} />
          ) : currentView === 'monitor' ? (
            <div className="monitor-view fade-in">
              <div style={{background:'white', border:'1px solid #e2e8f0', borderRadius:'24px', padding:'24px', marginBottom:'20px', display:'flex', justifyContent:'space-between', alignItems:'center', gap:'20px', flexWrap:'wrap'}}>
                <div>
                  <h3 style={{margin:'0 0 6px', fontSize:'1.15rem', fontWeight:'800', color:'#0f172a'}}>CIHAZ MONITORU</h3>
                  <p style={{margin:0, fontSize:'13px', color:'#64748b'}}>
                    Son kontrol: {lastMonitorCheck ? lastMonitorCheck.toLocaleString() : 'Henuz yapilmadi'}
                  </p>
                </div>
                <div style={{display:'flex', gap:'12px', alignItems:'center'}}>
                  <select 
                    value={autoRefreshInterval} 
                    onChange={(e) => setAutoRefreshInterval(Number(e.target.value))}
                    style={{padding:'11px 14px', borderRadius:'10px', border:'1px solid #e2e8f0', fontSize:'13px', fontWeight:'600', background:'white', cursor:'pointer'}}
                  >
                    <option value="0">Manuel</option>
                    <option value="15">15 saniye</option>
                    <option value="30">30 saniye</option>
                    <option value="60">60 saniye</option>
                  </select>
                  <button type="button" onClick={monitorDevices} disabled={isMonitoring} style={{background:'#0f172a', color:'white', border:'none', padding:'11px 18px', borderRadius:'10px', fontWeight:'700', cursor: isMonitoring ? 'not-allowed' : 'pointer', opacity: isMonitoring ? 0.7 : 1}}>
                    {isMonitoring ? 'Kontrol Ediliyor...' : 'Simdi Kontrol Et'}
                  </button>
                </div>
              </div>

              <div style={{display:'grid', gridTemplateColumns:'repeat(auto-fill, minmax(260px, 1fr))', gap:'16px'}}>
                {devices.map((d, idx) => {
                  const isOnline = d.status === 'online';
                  return (
                    <div key={`${d.id ?? d.ip_address ?? 'monitor-device'}-${idx}`} style={{background:'white', border:'1px solid #e2e8f0', borderRadius:'18px', padding:'18px', boxShadow:'0 10px 20px rgba(15,23,42,0.04)'}}>
                      <div style={{display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:'12px'}}>
                        <strong style={{fontSize:'14px', color:'#0f172a'}}>{d.name || d.ip_address || 'Isimsiz Cihaz'}</strong>
                        <span style={{fontSize:'11px', fontWeight:'700', padding:'4px 8px', borderRadius:'999px', background:isOnline ? '#dcfce7' : '#fee2e2', color:isOnline ? '#166534' : '#991b1b'}}>
                          {isOnline ? 'Acik' : 'Kapali'}
                        </span>
                      </div>
                      <div style={{fontSize:'13px', color:'#334155', marginBottom:'8px'}}>{d.ip_address || '-'}</div>
                      <div style={{fontSize:'12px', color:'#64748b'}}>VDOM: {d.vdom || 'root'}</div>
                    </div>
                  );
                })}
              </div>

              {devices.length === 0 && <div style={{marginTop:'20px', background:'white', border:'1px solid #e2e8f0', borderRadius:'16px', padding:'24px', textAlign:'center', color:'#64748b'}}>Monitor icin once cihaz ekleyin.</div>}
            </div>
          ) : currentView === 'hitcounts' ? (
            <HitCountView devices={devices} API_URL={API_URL} autoRefreshInterval={autoRefreshInterval} />
          ) : currentView === 'performance' ? (
            <PerformanceView devices={devices} API_URL={API_URL} autoRefreshInterval={autoRefreshInterval} />
          ) : currentView === 'cve' ? (
            <CVEView API_URL={API_URL} onMarkRead={markCVEAsRead} />
          ) : currentView === 'settings' ? (
            <SettingsView API_URL={API_URL} />
          ) : (
            <div style={{padding:'40px', textAlign:'center', color:'#64748b'}}>Sayfa bulunamadı.</div>
          )}
        </div>
      </div>
    </div>
  );
}

// --- Hit Count Analysis View ---
const HitCountView = ({ devices, API_URL, autoRefreshInterval }) => {
  const [selectedDevice, setSelectedDevice] = useState(devices[0]?.id || '');
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!selectedDevice && devices.length > 0) {
      setSelectedDevice(devices[0].id);
    }
  }, [devices, selectedDevice]);

  const fetchHistory = async (deviceId) => {
    if (!deviceId) return;
    setLoading(true);
    try {
      const res = await axios.get(`${API_URL}/devices/${deviceId}/hit-history`);
      const formatted = (res.data || []).map((h) => ({
        date: new Date(h.collected_at).toLocaleDateString('tr-TR', { day: '2-digit', month: '2-digit' }),
        hits: parseInt(h.hit_count, 10) || 0,
        fullDate: new Date(h.collected_at).toLocaleString('tr-TR')
      }));
      setHistory(formatted);
    } catch (err) {
      console.error(err);
      setHistory([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory(selectedDevice);
  }, [selectedDevice]);

  useEffect(() => {
    if (!selectedDevice || autoRefreshInterval <= 0) return;
    const interval = setInterval(() => {
      fetchHistory(selectedDevice);
    }, autoRefreshInterval * 1000);
    return () => clearInterval(interval);
  }, [selectedDevice, autoRefreshInterval]);

  return (
    <div className="hit-count-view fade-in">
      <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'30px', gap:'12px', flexWrap:'wrap'}}>
        <div style={{display:'flex', gap:'15px', alignItems:'center', flexWrap:'wrap'}}>
          <select
            value={selectedDevice}
            onChange={(e) => setSelectedDevice(e.target.value)}
            style={{padding:'12px 20px', borderRadius:'14px', border:'1px solid #e2e8f0', fontSize:'14px', fontWeight:'600', outline:'none', background:'white', minWidth:'260px'}}
          >
            <option value="">Cihaz Secin</option>
            {devices.map((d, idx) => (
              <option key={`${d.id ?? d.ip_address ?? 'hit-device'}-${idx}`} value={d.id}>{d.name || d.ip_address} ({d.ip_address})</option>
            ))}
          </select>
        </div>
      </div>

      <div style={{background:'white', padding:'30px', borderRadius:'24px', border:'1px solid #e2e8f0', minHeight:'500px', boxShadow:'0 10px 15px -3px rgba(0,0,0,0.05)'}}>
        <div style={{marginBottom:'20px'}}>
          <h3 style={{fontSize:'1.1rem', fontWeight:'800'}}>Hit Count Gecmisi (Son 3 Ay)</h3>
          <p style={{fontSize:'13px', color:'#64748b'}}>Politika kullanim yogunlugu trend analizi</p>
        </div>

        {loading ? (
          <div style={{height:'350px', display:'flex', alignItems:'center', justifyContent:'center'}}><Activity className="spin" /></div>
        ) : history.length > 0 ? (
          <ResponsiveContainer width="100%" height={380}>
            <AreaChart data={history}>
              <defs>
                <linearGradient id="colorHits" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" />
              <XAxis dataKey="date" stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} />
              <YAxis stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} tickFormatter={(val) => val >= 1000 ? `${(val / 1000).toFixed(1)}k` : val} />
              <Tooltip contentStyle={{borderRadius:'12px', border:'none', boxShadow:'0 10px 15px -3px rgba(0,0,0,0.1)'}} labelStyle={{fontWeight:'bold', color:'#1e293b'}} />
              <Area type="monotone" dataKey="hits" stroke="#6366f1" strokeWidth={3} fillOpacity={1} fill="url(#colorHits)" />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div style={{height:'350px', display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', color:'#94a3b8', gap:'15px'}}>
            <BarChart3 size={48} opacity={0.3} />
            <p>Secili cihaz icin henuz hit count verisi bulunmuyor.</p>
          </div>
        )}
      </div>

      <div style={{marginTop:'30px', display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(220px, 1fr))', gap:'20px'}}>
        <div style={{background:'white', padding:'25px', borderRadius:'20px', border:'1px solid #e2e8f0'}}>
          <div style={{fontSize:'11px', color:'#64748b', fontWeight:'800', textTransform:'uppercase', marginBottom:'5px'}}>SON HITS</div>
          <div style={{fontSize:'24px', fontWeight:'800', color:'#1e293b'}}>{history.length > 0 ? history[history.length - 1].hits.toLocaleString() : 0}</div>
        </div>
        <div style={{background:'white', padding:'25px', borderRadius:'20px', border:'1px solid #e2e8f0'}}>
          <div style={{fontSize:'11px', color:'#64748b', fontWeight:'800', textTransform:'uppercase', marginBottom:'5px'}}>GUNLUK ORTALAMA</div>
          <div style={{fontSize:'24px', fontWeight:'800', color:'#6366f1'}}>{history.length > 0 ? Math.round(history.reduce((acc, item) => acc + item.hits, 0) / history.length).toLocaleString() : 0}</div>
        </div>
        <div style={{background:'white', padding:'25px', borderRadius:'20px', border:'1px solid #e2e8f0'}}>
          <div style={{fontSize:'11px', color:'#64748b', fontWeight:'800', textTransform:'uppercase', marginBottom:'5px'}}>SON GUNCELLEME</div>
          <div style={{fontSize:'14px', fontWeight:'700', color:'#1e293b', marginTop:'10px'}}>{history.length > 0 ? history[history.length - 1].fullDate : 'Veri yok'}</div>
        </div>
      </div>
    </div>
  );
};

// --- Performance View ---
const PerformanceView = ({ devices, API_URL, autoRefreshInterval }) => {
  const [latestMetrics, setLatestMetrics] = useState([]);
  const [loading, setLoading] = useState(false);

  const extractMetricCurrent = (rawValue) => {
    // FortiGate payload can be number, object({current}), or array([{current,...}]).
    if (Array.isArray(rawValue)) {
      const first = rawValue[0];
      if (first && typeof first === 'object' && first.current !== undefined) {
        return Number(first.current) || 0;
      }
      return Number(first) || 0;
    }
    if (rawValue && typeof rawValue === 'object') {
      if (rawValue.current !== undefined) return Number(rawValue.current) || 0;
      return 0;
    }
    return Number(rawValue) || 0;
  };

  const fetchLatestMetrics = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_URL}/metrics/latest`);
      setLatestMetrics(res.data);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  };

  useEffect(() => {
    fetchLatestMetrics();
    if (autoRefreshInterval <= 0) return;
    const interval = setInterval(fetchLatestMetrics, autoRefreshInterval * 1000);
    return () => clearInterval(interval);
  }, [autoRefreshInterval]);

  if (loading && latestMetrics.length === 0) {
    return <div style={{textAlign:'center', padding:'60px', color:'#64748b'}}>Yükleniyor...</div>;
  }

  return (
    <div className="performance-view fade-in">
      <div style={{background:'white', border:'1px solid #e2e8f0', borderRadius:'24px', padding:'24px', marginBottom:'20px'}}>
        <h3 style={{margin:'0 0 12px', fontSize:'1.15rem', fontWeight:'800'}}>PERFORMANS & METRİKLER</h3>
        <p style={{margin:0, fontSize:'13px', color:'#64748b'}}>Cihaz CPU, Memory, VPN, Session, HA, Certificate ve Interface metriklerini izleyin (Son 3 ay)</p>
      </div>

      <div style={{display:'grid', gridTemplateColumns:'repeat(auto-fill, minmax(300px, 1fr))', gap:'16px', marginBottom:'20px'}}>
        {devices.map((d) => {
          const deviceMetrics = latestMetrics.find(m => m.id === d.id);
          const sysRes = deviceMetrics?.metrics?.system_resources?.data || {};
          const cpu = extractMetricCurrent(sysRes.cpu);
          const memory = extractMetricCurrent(sysRes.mem);
          const sessions = extractMetricCurrent(deviceMetrics?.metrics?.session_count?.data);
          
          return (
            <div key={d.id} style={{background:'white', border:'1px solid #e2e8f0', borderRadius:'18px', padding:'20px', boxShadow:'0 10px 20px rgba(15,23,42,0.04)'}}>
              <div style={{marginBottom:'12px'}}>
                <strong style={{fontSize:'15px', color:'#0f172a'}}>{d.name || d.ip_address}</strong>
                <div style={{fontSize:'12px', color:'#64748b', marginTop:'2px'}}>{d.ip_address}</div>
              </div>

              <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'10px', marginBottom:'12px'}}>
                <div style={{background:'#f8fafc', padding:'10px', borderRadius:'10px'}}>
                  <div style={{fontSize:'10px', fontWeight:'700', color:'#64748b', marginBottom:'4px'}}>CPU</div>
                  <div style={{fontSize:'18px', fontWeight:'800', color: cpu > 80 ? '#ef4444' : cpu > 60 ? '#f59e0b' : '#10b981'}}>{cpu}%</div>
                </div>
                <div style={{background:'#f8fafc', padding:'10px', borderRadius:'10px'}}>
                  <div style={{fontSize:'10px', fontWeight:'700', color:'#64748b', marginBottom:'4px'}}>MEMORY</div>
                  <div style={{fontSize:'18px', fontWeight:'800', color: memory > 80 ? '#ef4444' : memory > 60 ? '#f59e0b' : '#10b981'}}>{memory}%</div>
                </div>
              </div>

              <div style={{background:'#f8fafc', padding:'10px', borderRadius:'10px', marginBottom:'12px'}}>
                <div style={{fontSize:'10px', fontWeight:'700', color:'#64748b', marginBottom:'4px'}}>SESSIONS</div>
                <div style={{fontSize:'16px', fontWeight:'700', color:'#475569'}}>{sessions.toLocaleString()}</div>
              </div>
            </div>
          );
        })}
      </div>

      {devices.length === 0 && <div style={{background:'white', border:'1px solid #e2e8f0', borderRadius:'16px', padding:'24px', textAlign:'center', color:'#64748b'}}>Performans metrikleri için önce cihaz ekleyin.</div>}
    </div>
  );
};

// --- Report Page ---
const SwitchAnalysisCard = ({ finding }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  
  return (
    <div className={`analysis-detail-card ${isExpanded ? 'is-expanded' : ''}`} onClick={() => setIsExpanded(!isExpanded)}>
      <div className="analysis-card-header">
        <div className="policy-meta">
          <span className={`badge ${finding.passed ? 'badge-success' : 'badge-danger'}`} style={{marginRight:'10px'}}>
            {finding.passed ? 'BAŞARILI' : 'İHLAL'}
          </span>
          <span className="policy-id">ID: {finding.rule_id}</span>
          <h4 className="policy-name">{finding.name}</h4>
        </div>
        <div style={{display:'flex', alignItems:'center', gap:'15px'}}>
          <span style={{fontSize:'11px', fontWeight:'800', padding:'4px 10px', borderRadius:'8px', background: finding.severity==='CRITICAL'?'#fee2e2':finding.severity==='HIGH'?'#ffedd5':'#f1f5f9', color: finding.severity==='CRITICAL'?'#ef4444':finding.severity==='HIGH'?'#f59e0b':'#64748b'}}>{finding.severity}</span>
          <div className="expand-icon"><ChevronRight size={20} /></div>
        </div>
      </div>
      
      {isExpanded && (
        <div className="analysis-card-body fade-in">
          <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'20px', marginBottom:'20px'}}>
            <div className="detail-col">
              <label>Kontrol Mantığı</label>
              <div className="detail-box" style={{fontSize:'13px', color:'#475569'}}>{finding.check_logic}</div>
            </div>
            <div className="detail-col">
              <label>Tespit Edilen Değer</label>
              <div className="detail-box" style={{fontFamily:'monospace', fontSize:'13px', color: finding.passed ? '#166534' : '#991b1b', background: finding.passed ? '#f0fdf4' : '#fef2f2'}}>
                {finding.found_line || 'Kayıt bulunamadı'}
              </div>
            </div>
          </div>

          {!finding.passed && (
            <div className="risks-section">
              <label>Çözüm Önerisi (Remediation)</label>
              <div style={{background:'#f8fafc', padding:'15px', borderRadius:'12px', border:'1px solid #e2e8f0', marginBottom:'15px'}}>
                <div style={{fontFamily:'monospace', fontSize:'13px', color:'#1e293b', marginBottom:'10px'}}>{finding.remediation}</div>
              </div>
              {finding.details && finding.details.length > 0 && (
                <div style={{fontSize:'13px', color:'#64748b'}}>
                  <ul style={{paddingLeft:'20px', margin:0}}>
                    {finding.details.map((d, i) => <li key={i} style={{marginBottom:'4px'}}>{d}</li>)}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

function ReportPage() {
  const { uid } = useParams(); const navigate = useNavigate();
  const [data, setData] = useState(null); const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('summary');
  const [ipSearch, setIpSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');

  useEffect(() => { 
    setLoading(true);
    const fetchData = async () => {
      try {
        const start = Date.now();
        const r = await axios.get(`${API_URL}/config-detail/${uid}`);
        const elapsed = Date.now() - start;
        const delay = Math.max(0, 2000 - elapsed);
        
        setTimeout(() => {
          setData(r.data);
          setLoading(false);
        }, delay);
      } catch (e) {
        console.error(e);
        setLoading(false);
      }
    };
    fetchData();
  }, [uid]);

  if (loading) return <div className="loading-screen"><Activity className="spin" size={80} /><p>Veriler Yükleniyor...</p></div>;
  if (!data || !data.file) return <div className="error-screen"><h2>Hata!</h2><button onClick={()=>navigate('/')}>Geri</button></div>;

  const { file } = data; const analysis = file.analysis_data || {}; const summary = file.summary_data || {};
  const isSwitch = analysis.config_type === 'switch';
  const stigScore = analysis.stig_score ?? 0; const cisScore = analysis.cis_score ?? 0; const bpScore = analysis.bp_score ?? 0;

  return (
    <div className="app-layout">
      <aside className="report-sidebar">
        <div className="report-sidebar-header">
          <div className="back-btn" onClick={()=>navigate('/')}><ArrowLeft size={18}/><span>Dashboard'a Dön</span></div>
          <div className="device-info-compact">
            <label>{isSwitch ? 'Switch Analizi' : 'FortiGate Analizi'}</label>
            <span>{summary.device_name || (isSwitch ? 'Switch' : 'FortiGate')}</span>
          </div>
        </div>
        <nav className="report-nav">
          <button className={`report-nav-item ${activeTab==='summary'?'active':''}`} onClick={()=>setActiveTab('summary')}><Info size={18}/><span>{isSwitch ? 'Cihaz Özeti' : 'Cihaz Özeti'}</span></button>
          {!isSwitch ? (
            <>
              <button className={`report-nav-item ${activeTab==='interface'?'active':''}`} onClick={()=>setActiveTab('interface')}><ArrowRight size={18}/><span>Arayüz Analizi</span></button>
              <button className={`report-nav-item ${activeTab==='ip_analysis'?'active':''}`} onClick={()=>setActiveTab('ip_analysis')}><Database size={18}/><span>IP Analizi</span></button>
              <button className={`report-nav-item ${activeTab==='compliance'?'active':''}`} onClick={()=>setActiveTab('compliance')}><Shield size={18}/><span>Sıkılaştırma Denetimi</span></button>
              <button className={`report-nav-item ${activeTab==='analysis'?'active':''}`} onClick={()=>setActiveTab('analysis')}><Search size={18}/><span>Geniş Erişim Analizi</span></button>
              <button className={`report-nav-item ${activeTab==='profiles'?'active':''}`} onClick={()=>setActiveTab('profiles')}><Activity size={18}/><span>Güvenlik Profil Tespiti</span></button>
              <button className={`report-nav-item ${activeTab==='shadow'?'active':''}`} onClick={()=>setActiveTab('shadow')}><Zap size={18}/><span>Shadow Analizi</span></button>
            </>
          ) : (
            <button className={`report-nav-item ${activeTab==='findings'?'active':''}`} onClick={()=>setActiveTab('findings')}><Shield size={18}/><span>Güvenlik Bulguları</span></button>
          )}
        </nav>
      </aside>

      <div className="app-main">
        <header className="app-topbar">
          <h2 className="page-title">{isSwitch ? 'Switch Güvenlik Raporu' : 'FortiGate Denetim Raporu'}</h2>
          <div style={{display:'flex', gap:'10px'}}>
            <button className="btn-secondary" onClick={()=>{
              window.print();
            }}><Printer size={18}/> PDF Dışa Aktar</button>
          </div>
        </header>

        <div className="content-area">
          <main className="report-paper fade-in">
            <div className="report-content-body">
              {activeTab === 'summary' && (
                <div className="fade-in">
                  <div style={{background:'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)', padding:'40px', borderRadius:'24px', color:'white', marginBottom:'40px', position:'relative', overflow:'hidden', boxShadow:'0 20px 25px -5px rgba(0,0,0,0.1)'}}>
                    <div style={{position:'relative', zIndex:2}}>
                      <div style={{display:'flex', alignItems:'center', gap:'15px', marginBottom:'20px'}}>
                        <div style={{background:'rgba(255,255,255,0.1)', padding:'12px', borderRadius:'14px', backdropFilter:'blur(10px)'}}>
                          <Shield size={32} style={{color: isSwitch ? '#10b981' : '#818cf8'}}/>
                        </div>
                        <div>
                          <h1 style={{fontSize:'2rem', fontWeight:'800', marginBottom:'4px'}}>{summary.device_name || (isSwitch ? 'Switch' : 'FortiGate')}</h1>
                          <p style={{opacity:0.6, fontSize:'0.9rem', letterSpacing:'1px', textTransform:'uppercase'}}>{isSwitch ? 'Switch Güvenlik Özeti' : 'Sistem Özet Raporu'}</p>
                        </div>
                      </div>
                      <div style={{display:'flex', gap:'40px', borderTop:'1px solid rgba(255,255,255,0.1)', paddingTop:'30px'}}>
                        <div>
                          <label style={{fontSize:'10px', color:'#94a3b8', fontWeight:'800', textTransform:'uppercase', display:'block', marginBottom:'5px'}}>Vendor / Model</label>
                          <span style={{fontSize:'1.1rem', fontWeight:'700'}}>{isSwitch ? `${summary.vendor} ${summary.model}` : summary.model}</span>
                        </div>
                        <div>
                          <label style={{fontSize:'10px', color:'#94a3b8', fontWeight:'800', textTransform:'uppercase', display:'block', marginBottom:'5px'}}>Versiyon</label>
                          <span style={{fontSize:'1.1rem', fontWeight:'700'}}>{summary.version}</span>
                        </div>
                        <div>
                          <label style={{fontSize:'10px', color:'#94a3b8', fontWeight:'800', textTransform:'uppercase', display:'block', marginBottom:'5px'}}>Analiz Tarihi</label>
                          <span style={{fontSize:'1.1rem', fontWeight:'700'}}>{new Date(file.updated_at).toLocaleDateString()}</span>
                        </div>
                      </div>
                    </div>
                    <div style={{position:'absolute', top:'-20%', right:'-10%', width:'400px', height:'400px', background: isSwitch ? '#10b981' : 'var(--primary)', filter:'blur(120px)', opacity:0.15, borderRadius:'50%'}}></div>
                  </div>

                  <h3 className="section-subtitle">{isSwitch ? 'GÜVENLİK SKORU' : 'SİSTEM METRİKLERİ'}</h3>
                  <div style={{display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(220px, 1fr))', gap:'20px', marginBottom:'40px'}}>
                    {isSwitch ? (
                      <>
                        <div style={{background:'white', padding:'25px', borderRadius:'20px', border:'1px solid #e2e8f0', display:'flex', alignItems:'center', gap:'20px'}}>
                          <div style={{background: '#6366f115', color: '#6366f1', padding:'12px', borderRadius:'14px'}}><Shield size={22}/></div>
                          <div>
                            <div style={{fontSize:'0.75rem', color:'#64748b', fontWeight:'700', textTransform:'uppercase', marginBottom:'4px'}}>Genel Skor</div>
                            <div style={{fontSize:'1.5rem', fontWeight:'800', color:'#1e293b'}}>{summary.score}%</div>
                          </div>
                        </div>
                        <div style={{background:'white', padding:'25px', borderRadius:'20px', border:'1px solid #e2e8f0', display:'flex', alignItems:'center', gap:'20px'}}>
                          <div style={{background: '#10b98115', color: '#10b981', padding:'12px', borderRadius:'14px'}}><CheckCircle2 size={22}/></div>
                          <div>
                            <div style={{fontSize:'0.75rem', color:'#64748b', fontWeight:'700', textTransform:'uppercase', marginBottom:'4px'}}>Başarılı</div>
                            <div style={{fontSize:'1.5rem', fontWeight:'800', color:'#10b981'}}>{summary.passed}</div>
                          </div>
                        </div>
                        <div style={{background:'white', padding:'25px', borderRadius:'20px', border:'1px solid #e2e8f0', display:'flex', alignItems:'center', gap:'20px'}}>
                          <div style={{background: '#ef444415', color: '#ef4444', padding:'12px', borderRadius:'14px'}}><AlertTriangle size={22}/></div>
                          <div>
                            <div style={{fontSize:'0.75rem', color:'#64748b', fontWeight:'700', textTransform:'uppercase', marginBottom:'4px'}}>İhlal Sayısı</div>
                            <div style={{fontSize:'1.5rem', fontWeight:'800', color:'#ef4444'}}>{summary.failed}</div>
                          </div>
                        </div>
                      </>
                    ) : (
                      <>
                        {[
                          { label: 'Toplam Politika', val: summary.total_rules, icon: <Terminal size={22}/>, color: '#6366f1' },
                          { label: 'Sanal Domain (VDOM)', val: summary.total_vdom, icon: <Database size={22}/>, color: '#10b981' },
                          { label: 'Arayüz Sayısı', val: summary.total_interface, icon: <Activity size={22}/>, color: '#f59e0b' },
                          { label: 'VPN Tünelleri', val: summary.total_ipsec, icon: <Lock size={22}/>, color: '#ec4899' }
                        ].map((m, i) => (
                          <div key={i} style={{background:'white', padding:'25px', borderRadius:'20px', border:'1px solid #e2e8f0', display:'flex', alignItems:'center', gap:'20px', transition:'transform 0.2s', cursor:'default'}}>
                            <div style={{background: `${m.color}15`, color: m.color, padding:'12px', borderRadius:'14px'}}>
                              {m.icon}
                            </div>
                            <div>
                              <div style={{fontSize:'0.75rem', color:'#64748b', fontWeight:'700', textTransform:'uppercase', marginBottom:'4px'}}>{m.label}</div>
                              <div style={{fontSize:'1.5rem', fontWeight:'800', color:'#1e293b'}}>{m.val || 0}</div>
                            </div>
                          </div>
                        ))}
                      </>
                    )}
                  </div>

                  <h3 className="section-subtitle">YAPILANDIRMA DETAYLARI</h3>
                  <div style={{background:'white', borderRadius:'20px', border:'1px solid #e2e8f0', overflow:'hidden', boxShadow:'0 4px 6px -1px rgba(0,0,0,0.05)'}}>
                    <table style={{width:'100%', borderCollapse:'collapse'}}>
                      <tbody>
                        {[
                          ['Cihaz Hostname', summary.device_name],
                          ['Cihaz Türü', isSwitch ? 'Network Switch' : 'FortiGate Firewall'],
                          ['Marka (Vendor)', isSwitch ? summary.vendor : 'Fortinet'],
                          ['İşletim Sistemi', isSwitch ? summary.version : `FortiOS ${summary.version}`],
                          ['Analiz Edilen Dosya', file.file_name],
                          ['Dosya Boyutu', (file.file_size / 1024).toFixed(2) + ' KB'],
                          ['Rapor Durumu', 'Tamamlandı']
                        ].map(([label, val], i) => (
                          <tr key={i} style={{borderBottom: i === 6 ? 'none' : '1px solid #f1f5f9'}}>
                            <td style={{padding:'18px 30px', fontSize:'13px', color:'#64748b', fontWeight:'700', background:'#f8fafc', width:'30%', textTransform:'uppercase', letterSpacing:'0.5px'}}>{label}</td>
                            <td style={{padding:'18px 30px', fontSize:'14px', color:'#1e293b', fontWeight:'700'}}>{val}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {isSwitch && activeTab === 'findings' && (
                <div className="fade-in">
                  <h3 className="section-subtitle">GÜVENLİK BULGULARI VE DENETİM</h3>
                  <p style={{color:'#64748b', fontSize:'14px', marginBottom:'25px'}}>Sistem konfigürasyonu üzerinde yapılan otomatik denetimlerin sonuçları aşağıdadır.</p>
                  <div style={{display:'grid', gap:'15px'}}>
                    {analysis.list?.map((f, i) => <SwitchAnalysisCard key={i} finding={f} />)}
                    {(!analysis.list || analysis.list.length === 0) && (
                      <div className="no-findings">Analiz edilecek kural bulunamadı.</div>
                    )}
                  </div>
                </div>
              )}

              {!isSwitch && activeTab === 'interface' && (
                <div className="fade-in">
                  <h3 className="section-subtitle">ARAYÜZ ETKİLEŞİM ANALİZİ</h3>
                  <p style={{color:'#64748b', fontSize:'14px', marginBottom:'25px'}}>Aşağıdaki liste, konfigürasyondaki politikaların hangi arayüzler arasında yoğunlaştığını göstermektedir. Bu, ağ trafiği akışını anlamak için kritiktir.</p>
                  
                  <div style={{display:'grid', gap:'15px'}}>
                    {analysis.interface_interactions?.map((item, i) => (
                      <div key={i} style={{background:'white', padding:'20px', borderRadius:'16px', border:'1px solid #e2e8f0', display:'flex', justifyContent:'space-between', alignItems:'center', boxShadow:'0 2px 4px rgba(0,0,0,0.02)'}}>
                        <div style={{display:'flex', alignItems:'center', gap:'20px', flex:1}}>
                          <div style={{background:'#f1f5f9', padding:'8px 15px', borderRadius:'10px', fontSize:'13px', fontWeight:'700', color:'#1e293b', minWidth:'120px', textAlign:'center', border:'1px solid #e2e8f0'}}>{item.src}</div>
                          <ArrowRight size={20} style={{color:'#94a3b8'}}/>
                          <div style={{background:'#f1f5f9', padding:'8px 15px', borderRadius:'10px', fontSize:'13px', fontWeight:'700', color:'#1e293b', minWidth:'120px', textAlign:'center', border:'1px solid #e2e8f0'}}>{item.dst}</div>
                        </div>
                        <div style={{textAlign:'right'}}>
                          <div style={{fontSize:'11px', color:'#64748b', fontWeight:'700', textTransform:'uppercase', marginBottom:'2px'}}>Politika Sayısı</div>
                          <div style={{fontSize:'1.25rem', fontWeight:'800', color: item.count > 10 ? '#ef4444' : '#6366f1'}}>{item.count}</div>
                        </div>
                      </div>
                    ))}
                    {(!analysis.interface_interactions || analysis.interface_interactions.length === 0) && (
                      <div className="no-findings">Henüz arayüz etkileşim verisi bulunamadı.</div>
                    )}
                  </div>
                </div>
              )}

              {activeTab === 'ip_analysis' && (() => {
                const filteredList = analysis.ip_analysis?.list?.filter(i => {
                  const matchesSearch = i.name.toLowerCase().includes(ipSearch.toLowerCase()) || 
                                       i.ip.toLowerCase().includes(ipSearch.toLowerCase());
                  const matchesType = typeFilter === 'all' || i.type === typeFilter;
                  const matchesStatus = statusFilter === 'all' || i.status === statusFilter;
                  return matchesSearch && matchesType && matchesStatus;
                }) || [];
                const isSearchActive = ipSearch.trim().length > 0;
                const isExactMatch = filteredList.some(i => i.ip === ipSearch.trim() || i.name === ipSearch.trim());

                return (
                  <div className="fade-in">
                    <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'30px'}}>
                      <h3 className="section-subtitle" style={{marginBottom:0}}>IP ADRES VE DHCP ANALİZİ</h3>
                      <div className="search-box-wrapper" style={{display:'flex', gap:'15px', alignItems:'center'}}>
                        <select 
                          value={typeFilter} 
                          onChange={(e)=>setTypeFilter(e.target.value)}
                          style={{padding:'10px', borderRadius:'12px', border:'1px solid #e2e8f0', fontSize:'13px', outline:'none', background:'white'}}
                        >
                          <option value="all">Tüm Türler</option>
                          <option value="Statik">Statik</option>
                          <option value="Range">Range</option>
                          <option value="DHCP">DHCP</option>
                        </select>
                        <select 
                          value={statusFilter} 
                          onChange={(e)=>setStatusFilter(e.target.value)}
                          style={{padding:'10px', borderRadius:'12px', border:'1px solid #e2e8f0', fontSize:'13px', outline:'none', background:'white'}}
                        >
                          <option value="all">Tüm Durumlar</option>
                          <option value="Kullanılıyor">Kullanılıyor</option>
                          <option value="Şüpheli">Şüpheli</option>
                          <option value="Boşta">Boşta</option>
                        </select>
                        <div style={{position:'relative', width:'250px'}}>
                          <Search size={18} style={{position:'absolute', left:'12px', top:'50%', transform:'translateY(-50%)', color:'#94a3b8'}}/>
                          <input 
                            type="text" 
                            placeholder="IP veya İsim Ara..." 
                            value={ipSearch}
                            onChange={(e)=>setIpSearch(e.target.value)}
                            style={{width:'100%', padding:'10px 15px 10px 40px', borderRadius:'12px', border:'1px solid #e2e8f0', fontSize:'14px', outline:'none'}}
                          />
                        </div>
                      </div>

                    </div>

                    <div style={{display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:'20px', marginBottom:'30px'}}>
                      <div style={{background:'white', padding:'20px', borderRadius:'16px', border:'1px solid #e2e8f0', textAlign:'center'}}>
                        <div style={{fontSize:'11px', color:'#64748b', fontWeight:'700', textTransform:'uppercase'}}>TOPLAM ADRES</div>
                        <div style={{fontSize:'24px', fontWeight:'800', color:'#1e293b'}}>{analysis.ip_analysis?.total || 0}</div>
                      </div>
                      <div style={{background:'white', padding:'20px', borderRadius:'16px', border:'1px solid #e2e8f0', textAlign:'center', borderBottom:'3px solid #10b981'}}>
                        <div style={{fontSize:'11px', color:'#64748b', fontWeight:'700', textTransform:'uppercase'}}>KULLANILAN</div>
                        <div style={{fontSize:'24px', fontWeight:'800', color:'#10b981'}}>{analysis.ip_analysis?.used || 0}</div>
                      </div>
                      <div style={{background:'white', padding:'20px', borderRadius:'16px', border:'1px solid #e2e8f0', textAlign:'center', borderBottom:'3px solid #f59e0b'}}>
                        <div style={{fontSize:'11px', color:'#64748b', fontWeight:'700', textTransform:'uppercase'}}>BOŞTA / ŞÜPHELİ</div>
                        <div style={{fontSize:'24px', fontWeight:'800', color:'#f59e0b'}}>{analysis.ip_analysis?.unused || 0}</div>
                      </div>
                    </div>

                    <div style={{background:'white', borderRadius:'20px', border:'1px solid #e2e8f0', overflow:'hidden', boxShadow:'0 4px 6px rgba(0,0,0,0.02)'}}>
                      <table style={{width:'100%', borderCollapse:'collapse', fontSize:'13px'}}>
                        <thead>
                          <tr style={{background:'#f8fafc', borderBottom:'1px solid #e2e8f0'}}>
                            <th style={{padding:'15px 20px', textAlign:'left', color:'#64748b', fontWeight:'700'}}>ADRES ADI</th>
                            <th style={{padding:'15px 20px', textAlign:'left', color:'#64748b', fontWeight:'700'}}>IP / SUBNET</th>
                            <th style={{padding:'15px 20px', textAlign:'left', color:'#64748b', fontWeight:'700'}}>TÜR</th>
                            <th style={{padding:'15px 20px', textAlign:'left', color:'#64748b', fontWeight:'700'}}>DURUM</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredList.map((item, i) => (
                            <tr key={i} style={{borderBottom:'1px solid #f1f5f9'}}>
                              <td style={{padding:'15px 20px', fontWeight:'700', color:'#1e293b'}}>{item.name}</td>
                              <td style={{padding:'15px 20px', color:'#475569', fontFamily:'monospace'}}>{item.ip}</td>
                              <td style={{padding:'15px 20px'}}><span style={{padding:'4px 8px', borderRadius:'6px', background:'#f1f5f9', fontSize:'11px', fontWeight:'700'}}>{item.type}</span></td>
                              <td style={{padding:'15px 20px'}}>
                                <span 
                                  className={`badge ${item.status === 'Kullanılıyor' ? 'badge-success' : item.status === 'Şüpheli' ? 'badge-warning' : 'badge-secondary'}`} 
                                  style={{fontSize:'10px', background: item.status === 'Şüpheli' ? '#fff7ed' : '', color: item.status === 'Şüpheli' ? '#c2410c' : '', cursor: item.status === 'Şüpheli' ? 'help' : 'default'}}
                                  title={item.status === 'Şüpheli' ? (item.type === 'Range' ? 'Bu aralık hiçbir kuralda doğrudan kullanılmıyor.' : `Bu IP adresi ${item.range_name} aralığı içindedir.`) : ''}
                                >
                                  {item.status}
                                </span>
                              </td>
                            </tr>
                          ))}
                          {isSearchActive && !isExactMatch && (() => {
                            const ipToLong = (ip) => {
                              const parts = ip.split('.');
                              if (parts.length !== 4) return 0;
                              return ((((((+parts[0]) << 8) | (+parts[1])) << 8) | (+parts[2])) << 8) | (+parts[3]) >>> 0;
                            };
                            const sVal = ipToLong(ipSearch.trim());
                            const foundRange = analysis.ip_analysis?.ranges?.find(r => {
                              const start = ipToLong(r.start);
                              const end = ipToLong(r.end);
                              return sVal >= start && sVal <= end;
                            });

                            return (
                              <tr style={{background:'rgba(241, 245, 249, 0.5)'}}>
                                <td style={{padding:'15px 20px', fontWeight:'700', color:'#64748b'}}>Arama Sonucu</td>
                                <td style={{padding:'15px 20px', color:'#475569', fontFamily:'monospace'}}>{ipSearch}</td>
                                <td style={{padding:'15px 20px'}}>
                                  <span style={{padding:'4px 8px', borderRadius:'6px', background:'#e2e8f0', fontSize:'11px', fontWeight:'700'}}>
                                    {foundRange?.type === 'DHCP' ? 'DHCP' : 'Tanımsız'}
                                  </span>
                                </td>
                                <td style={{padding:'15px 20px'}}>
                                  {foundRange ? (
                                    <span className={`badge ${foundRange.type === 'DHCP' ? 'badge-success' : 'badge-warning'}`} style={{fontSize:'10px', background: foundRange.type === 'DHCP' ? '#dcfce7' : '#fff7ed', color: foundRange.type === 'DHCP' ? '#166534' : '#c2410c', cursor:'help'}} title={`Bu IP adresi ${foundRange.name} aralığı içindedir.`}>
                                      {foundRange.type === 'DHCP' ? `Aktif DHCP (${foundRange.name})` : 'Şüpheli'}
                                    </span>
                                  ) : (
                                    <span className="badge badge-secondary" style={{fontSize:'10px', background:'#f1f5f9', color:'#64748b'}}>Boşta (Kayıt Yok)</span>
                                  )}
                                </td>
                              </tr>
                            );
                          })()}
                        </tbody>
                      </table>
                    </div>
                  </div>
                );
              })()}

              {activeTab === 'compliance' && (
                <div className="fade-in">
                  <h3 className="section-subtitle">SİSTEM GÜVENLİK KARNESİ</h3>
                  <div style={{display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:'20px', marginBottom:'40px'}}>
                    <div className="score-card" style={{background:'linear-gradient(135deg, #1e293b 0%, #334155 100%)', padding:'30px', borderRadius:'16px', color:'white', textAlign:'center'}}>
                      <div style={{fontSize:'12px', opacity:0.7, fontWeight:'700', marginBottom:'10px'}}>STIG UYUMU</div>
                      <div style={{fontSize:'48px', fontWeight:'800'}}>{stigScore}%</div>
                    </div>
                    <div className="score-card" style={{background:'linear-gradient(135deg, #0369a1 0%, #0ea5e9 100%)', padding:'30px', borderRadius:'16px', color:'white', textAlign:'center'}}>
                      <div style={{fontSize:'12px', opacity:0.7, fontWeight:'700', marginBottom:'10px'}}>CIS BENCHMARK</div>
                      <div style={{fontSize:'48px', fontWeight:'800'}}>{cisScore}%</div>
                    </div>
                    <div className="score-card" style={{background:'linear-gradient(135deg, #7e22ce 0%, #a855f7 100%)', padding:'30px', borderRadius:'16px', color:'white', textAlign:'center'}}>
                      <div style={{fontSize:'12px', opacity:0.7, fontWeight:'700', marginBottom:'10px'}}>BEST PRACTICES</div>
                      <div style={{fontSize:'48px', fontWeight:'800'}}>{bpScore}%</div>
                    </div>
                  </div>
                  
                  <h3 className="section-subtitle">DENETİM BULGULARI</h3>
                  {analysis.compliance_risks?.length > 0 ? (
                    analysis.compliance_risks.map((f, i) => <ComplianceAlert key={i} finding={f} />)
                  ) : (
                    <div className="no-findings success">✓ Tebrikler! Hiçbir güvenlik zafiyeti tespit edilmedi.</div>
                  )}
                </div>
              )}

              {activeTab === 'analysis' && (
                <div className="fade-in">
                  <h3 className="section-subtitle">NESNE KULLANIM SKORU</h3>
                  <div className="score-card" style={{background:'linear-gradient(135deg, #f59e0b 0%, #ef4444 100%)', padding:'25px', borderRadius:'16px', color:'white', textAlign:'center', maxWidth:'350px', marginBottom:'30px'}}>
                    <div style={{fontSize:'12px', opacity:0.8, fontWeight:'700', marginBottom:'5px'}}>ERİŞİM GÜVENLİĞİ</div>
                    <div style={{fontSize:'42px', fontWeight:'800'}}>{analysis.all_any_score || 0}%</div>
                  </div>
                  {analysis.security_risks?.map((f, i) => (
                    <AnalysisCard key={i} finding={f} />
                  ))}
                  {(!analysis.security_risks || analysis.security_risks.length === 0) && (
                    <div className="no-findings success">✓ Tüm kurallar ideal kısıtlamalara sahip.</div>
                  )}
                </div>
              )}

              {activeTab === 'profiles' && (
                <div className="fade-in">
                  <h3 className="section-subtitle">L7 GÜVENLİK SERVİSLERİ SKORU</h3>
                  <div className="score-card" style={{background:'linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%)', padding:'25px', borderRadius:'16px', color:'white', textAlign:'center', maxWidth:'350px', marginBottom:'30px'}}>
                    <div style={{fontSize:'12px', opacity:0.8, fontWeight:'700', marginBottom:'5px'}}>PROFİL KAPSAMI</div>
                    <div style={{fontSize:'42px', fontWeight:'800'}}>{analysis.l7_score || 0}%</div>
                  </div>
                  {analysis.profile_risks?.map((f, i) => (
                    <ProfileDetectionCard key={i} finding={f} />
                  ))}
                </div>
              )}

              {activeTab === 'shadow' && (
                <div className="fade-in">
                  <h3 className="section-subtitle">POLİTİKA OPTİMİZASYON SKORU</h3>
                  <div className="score-card" style={{background:'linear-gradient(135deg, #059669 0%, #064e3b 100%)', padding:'25px', borderRadius:'16px', color:'white', textAlign:'center', maxWidth:'350px', marginBottom:'30px'}}>
                    <div style={{fontSize:'12px', opacity:0.8, fontWeight:'700', marginBottom:'5px'}}>GÖLGE KURAL ORANI</div>
                    <div style={{fontSize:'42px', fontWeight:'800'}}>{analysis.shadow_score || 0}%</div>
                  </div>
                  
                  <h3 className="section-subtitle">Detaylı Çakışma Analizi</h3>
                  {analysis.shadow_risks?.map((r, i) => (
                    <div key={i} style={{background:'white', borderRadius:'16px', border:'1px solid #fca5a5', marginBottom:'25px', overflow:'hidden', boxShadow:'0 4px 6px rgba(0,0,0,0.05)'}}>
                      <div style={{background:'#fef2f2', padding:'15px 20px', borderBottom:'1px solid #fca5a5', display:'flex', justifyContent:'space-between', alignItems:'center'}}>
                        <div style={{fontWeight:'800', color:'#991b1b'}}>GÖLGELENEN KURAL TESPİTİ (ID {r.policy_id})</div>
                        <span style={{fontSize:'11px', background:'#ef4444', color:'white', padding:'2px 10px', borderRadius:'10px'}}>KRİTİK OPTİMİZASYON</span>
                      </div>
                      
                      <div style={{padding:'20px'}}>
                        <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:'20px'}}>
                          <div style={{background:'#f8fafc', padding:'15px', borderRadius:'12px', border:'1px solid #e2e8f0'}}>
                            <div style={{fontSize:'11px', fontWeight:'800', color:'#64748b', marginBottom:'5px', textTransform:'uppercase'}}>PASİF KURAL (ID {r.policy_id})</div>
                            <div style={{fontSize:'12px', fontWeight:'700', color:'#1e293b', marginBottom:'10px'}}>{r.name}</div>
                            <table style={{width:'100%', fontSize:'12px'}}>
                              <tbody>
                                <tr><td style={{color:'#94a3b8', padding:'4px 0'}}>Source Interface:</td><td style={{fontWeight:'700'}}>{r.shadowed_data?.srcintf || 'any'}</td></tr>
                                <tr><td style={{color:'#94a3b8', padding:'4px 0'}}>Destination Interface:</td><td style={{fontWeight:'700'}}>{r.shadowed_data?.dstintf || 'any'}</td></tr>
                                <tr><td style={{color:'#94a3b8', padding:'4px 0'}}>Source Address:</td><td style={{fontWeight:'700'}}>{Array.isArray(r.shadowed_data?.srcaddr) ? r.shadowed_data.srcaddr.join(', ') : (r.shadowed_data?.srcaddr || 'N/A')}</td></tr>
                                <tr><td style={{color:'#94a3b8', padding:'4px 0'}}>Destination Address:</td><td style={{fontWeight:'700'}}>{Array.isArray(r.shadowed_data?.dstaddr) ? r.shadowed_data.dstaddr.join(', ') : (r.shadowed_data?.dstaddr || 'N/A')}</td></tr>
                                <tr>
                                  <td style={{color:'#94a3b8', padding:'4px 0'}}>Service:</td>
                                  <td>
                                    <div style={{display:'flex', flexWrap:'wrap', gap:'4px'}}>
                                      {Array.isArray(r.shadowed_data?.service) ? r.shadowed_data.service.map((s, si) => (
                                        <span key={si} style={{fontSize:'10px', background:'white', padding:'1px 6px', borderRadius:'4px', border:'1px solid #e2e8f0', fontWeight:'700', color: (s.toLowerCase()==='all' || s.toLowerCase()==='any') ? '#ef4444' : '#1e293b'}}>{s}</span>
                                      )) : <span style={{fontWeight:'700'}}>{r.shadowed_data?.service || 'any'}</span>}
                                    </div>
                                  </td>
                                </tr>
                              </tbody>
                            </table>
                          </div>

                          <div style={{background:'#ecfdf5', padding:'15px', borderRadius:'12px', border:'1px solid #86efac'}}>
                            <div style={{fontSize:'11px', fontWeight:'800', color:'#059669', marginBottom:'5px', textTransform:'uppercase'}}>ENGELLEYEN ÜST KURAL (ID {r.shadowed_by})</div>
                            <div style={{fontSize:'12px', fontWeight:'700', color:'#064e3b', marginBottom:'10px'}}>{r.shadow_name}</div>
                            <table style={{width:'100%', fontSize:'12px'}}>
                              <tbody>
                                <tr><td style={{color:'#64748b', padding:'4px 0'}}>Source Interface:</td><td style={{fontWeight:'700', color:'#064e3b'}}>{r.shadowing_data?.srcintf || 'any'}</td></tr>
                                <tr><td style={{color:'#64748b', padding:'4px 0'}}>Destination Interface:</td><td style={{fontWeight:'700', color:'#064e3b'}}>{r.shadowing_data?.dstintf || 'any'}</td></tr>
                                <tr><td style={{color:'#64748b', padding:'4px 0'}}>Source Address:</td><td style={{fontWeight:'700', color:'#064e3b'}}>{Array.isArray(r.shadowing_data?.srcaddr) ? r.shadowing_data.srcaddr.join(', ') : (r.shadowing_data?.srcaddr || 'N/A')}</td></tr>
                                <tr><td style={{color:'#64748b', padding:'4px 0'}}>Destination Address:</td><td style={{fontWeight:'700', color:'#064e3b'}}>{Array.isArray(r.shadowing_data?.dstaddr) ? r.shadowing_data.dstaddr.join(', ') : (r.shadowing_data?.dstaddr || 'N/A')}</td></tr>
                                <tr>
                                  <td style={{color:'#64748b', padding:'4px 0'}}>Service:</td>
                                  <td>
                                    <div style={{display:'flex', flexWrap:'wrap', gap:'4px'}}>
                                      {Array.isArray(r.shadowing_data?.service) ? r.shadowing_data.service.map((s, si) => (
                                        <span key={si} style={{fontSize:'10px', background:'white', padding:'1px 6px', borderRadius:'4px', border:'1px solid #86efac', fontWeight:'700', color: (s.toLowerCase()==='all' || s.toLowerCase()==='any') ? '#ef4444' : '#064e3b'}}>{s}</span>
                                      )) : <span style={{fontWeight:'700', color:'#064e3b'}}>{r.shadowing_data?.service || 'any'}</span>}
                                    </div>
                                  </td>
                                </tr>
                              </tbody>
                            </table>
                          </div>
                        </div>

                        <div style={{marginTop:'20px', padding:'15px', background:'#fff7ed', borderRadius:'10px', border:'1px solid #fed7aa'}}>
                          <div style={{display:'flex', gap:'10px', alignItems:'start'}}>
                            <Info size={18} style={{color:'#ea580c', marginTop:'2px'}}/>
                            <div>
                              <div style={{fontSize:'13px', fontWeight:'700', color:'#9a3412'}}>Neden Gölge Kural?</div>
                              <p style={{fontSize:'12px', color:'#c2410c', marginTop:'4px', lineHeight:'1.5'}}>
                                Yukarıdaki tablolarda görüldüğü üzere, <strong>ID {r.shadowed_by}</strong> kuralının kapsamı, <strong>ID {r.policy_id}</strong> kuralının tüm parametrelerini (Source Interface, Destination Interface, Source Address, Destination Address, Service) tam olarak kapsamaktadır. 
                                FortiGate kuralları yukarıdan aşağıya işlediği için, trafik üstteki kuralda eşleşecek ve alttaki kurala asla sıra gelmeyecektir.
                              </p>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </main>
        </div>
      </div>
    </div>
  );
}

function App() { return (<Router><Routes><Route path="/" element={<Dashboard />} /><Route path="/report/:uid" element={<ReportPage />} /></Routes></Router>); }
export default App;

