import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { BrowserRouter as Router, Routes, Route, Link, useParams, useNavigate } from 'react-router-dom';
import { Shield, Home, Upload, Activity, AlertTriangle, Zap, CheckCircle2, FileJson, ArrowLeft, ArrowRight, Printer, Info, BarChart3, Clock, Database, ChevronRight, Terminal, Search, Lock, Cpu } from 'lucide-react';
import './App.css';

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

function Dashboard() {
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentView, setCurrentView] = useState('recent'); // 'recent' or 'devices'
  const [devices, setDevices] = useState([]);
  const [newDevice, setNewDevice] = useState({ name: '', ip_address: '', api_key: '', vdom: 'root' });
  const [editingDevice, setEditingDevice] = useState(null);

  const fetchFiles = async () => {
    try {
      const f = await axios.get(`${API_URL}/uploaded-files`);
      setUploadedFiles(f.data);
    } catch (err) { console.error(err); }
  };

  const fetchDevices = async () => {
    try {
      const res = await axios.get(`${API_URL}/devices`);
      setDevices(res.data);
    } catch (err) { console.error(err); }
  };

  useEffect(() => { 
    fetchFiles(); 
    fetchDevices();
  }, []);

  const simulateAnalysis = async (fileUid) => {
    setIsAnalyzing(true);
    setProgress(0);
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
      await axios.post(`${API_URL}/parse-config`, { fileUid });
      setProgress(100);
      setTimeout(() => { setIsAnalyzing(false); fetchFiles(); }, 500);
    } catch (err) { clearInterval(timer); setIsAnalyzing(false); alert('Analiz hatası!'); }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files[0]; if (!file) return;
    const formData = new FormData(); formData.append('file', file);
    try {
      const res = await axios.post(`${API_URL}/upload-config`, formData);
      simulateAnalysis(res.data.fileUid);
    } catch (err) { alert('Yükleme hatası!'); }
  };

  const handleAddDevice = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${API_URL}/devices`, newDevice);
      setNewDevice({ name: '', ip_address: '', api_key: '', vdom: 'root' });
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

  return (
    <div className="app-layout">
      {isAnalyzing && <CircularLoader progress={progress} />}
      <aside className="app-sidebar">
        <div className="sidebar-brand"><Shield size={32} style={{color:'#818cf8'}} /><h2>NSS ENGINE</h2></div>
        <nav className="sidebar-nav">
          <div className={`nav-item ${currentView === 'recent' ? 'active' : ''}`} onClick={() => setCurrentView('recent')} style={{cursor:'pointer'}}><Home size={20} /><span>Ana Panel</span></div>
          <div className={`nav-item ${currentView === 'devices' ? 'active' : ''}`} onClick={() => setCurrentView('devices')} style={{cursor:'pointer'}}><Database size={20} /><span>Cihazlar</span></div>
        </nav>
        
        <div className="sidebar-footer">
          <div className="version-info">{APP_VERSION}</div>
          <HealthIndicators />
        </div>
      </aside>
      <div className="app-main">
        <header className="app-topbar"><div className="welcome-msg"><h1>{currentView === 'recent' ? 'Güvenlik Paneli' : 'Cihaz Yönetimi'}</h1><p>{currentView === 'recent' ? 'Sistem yapılandırma analizleri' : 'API üzerinden FortiGate cihazlarını bağlayın'}</p></div><div className="status-pill success"><CheckCircle2 size={14}/> Online</div></header>
        <div className="content-area">
          {currentView === 'recent' ? (
            <>
              <div className="hero-upload-card">
                <div className="hero-text"><h2>Analiz Başlatın</h2><p>Konfigürasyon dosyasını yükleyin, 158+ kriterde tam denetim yapalım.</p></div>
                <input type="file" id="hero-up" onChange={handleFileUpload} style={{display:'none'}} /><label htmlFor="hero-up" className="upload-btn-lg"><Upload size={24} /><span>DOSYA SEÇİN</span></label>
              </div>
              <div className="recent-reports-section">
                <div className="section-header"><h3>Son Raporlar</h3></div>
                <div className="report-list">
                  {uploadedFiles.map(f => (
                    <div key={f.id} className="report-mini-card fade-in">
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
            </>
          ) : (
            <div className="devices-view fade-in">
              <div style={{background:'white', padding:'30px', borderRadius:'24px', border:'1px solid #e2e8f0', marginBottom:'30px'}}>
                <h3 style={{marginBottom:'20px', fontSize:'1.25rem', fontWeight:'800'}}>{editingDevice ? 'Cihazı Düzenle' : 'Yeni Cihaz Ekle'}</h3>
                <form onSubmit={editingDevice ? handleUpdateDevice : handleAddDevice} style={{display:'grid', gridTemplateColumns:'1fr 1fr 1fr 1fr auto auto', gap:'15px', alignItems:'end'}}>
                  <div><label style={{fontSize:'11px', fontWeight:'700', color:'#64748b', display:'block', marginBottom:'5px'}}>CİHAZ ADI</label><input type="text" placeholder="FW-01" value={editingDevice ? editingDevice.name : newDevice.name} onChange={e => editingDevice ? setEditingDevice({...editingDevice, name: e.target.value}) : setNewDevice({...newDevice, name: e.target.value})} style={{width:'100%', padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required /></div>
                  <div><label style={{fontSize:'11px', fontWeight:'700', color:'#64748b', display:'block', marginBottom:'5px'}}>IP ADRESİ</label><input type="text" placeholder="1.1.1.1" value={editingDevice ? editingDevice.ip_address : newDevice.ip_address} onChange={e => editingDevice ? setEditingDevice({...editingDevice, ip_address: e.target.value}) : setNewDevice({...newDevice, ip_address: e.target.value})} style={{width:'100%', padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required /></div>
                  <div><label style={{fontSize:'11px', fontWeight:'700', color:'#64748b', display:'block', marginBottom:'5px'}}>API KEY</label><input type="password" placeholder="Token" value={editingDevice ? editingDevice.api_key : newDevice.api_key} onChange={e => editingDevice ? setEditingDevice({...editingDevice, api_key: e.target.value}) : setNewDevice({...newDevice, api_key: e.target.value})} style={{width:'100%', padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}} required={!editingDevice} /></div>
                  <div><label style={{fontSize:'11px', fontWeight:'700', color:'#64748b', display:'block', marginBottom:'5px'}}>VDOM</label><input type="text" placeholder="root" value={editingDevice ? editingDevice.vdom : newDevice.vdom} onChange={e => editingDevice ? setEditingDevice({...editingDevice, vdom: e.target.value}) : setNewDevice({...newDevice, vdom: e.target.value})} style={{width:'100%', padding:'10px', borderRadius:'10px', border:'1px solid #e2e8f0'}} /></div>
                  <button type="submit" style={{background: editingDevice ? '#10b981' : 'var(--primary)', color:'white', border:'none', padding:'12px 25px', borderRadius:'10px', fontWeight:'700', cursor:'pointer'}}>{editingDevice ? 'Güncelle' : 'Kaydet'}</button>
                  {editingDevice && <button type="button" onClick={() => setEditingDevice(null)} style={{background:'#94a3b8', color:'white', border:'none', padding:'12px 25px', borderRadius:'10px', fontWeight:'700', cursor:'pointer'}}>İptal</button>}
                </form>
              </div>

              <div style={{background:'white', borderRadius:'24px', border:'1px solid #e2e8f0', overflow:'hidden'}}>
                <table style={{width:'100%', borderCollapse:'collapse'}}>
                  <thead style={{background:'#f8fafc', borderBottom:'1px solid #e2e8f0'}}>
                    <tr>
                      <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>CİHAZ</th>
                      <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>IP / VDOM</th>
                      <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>DURUM</th>
                      <th style={{padding:'15px 25px', textAlign:'left', fontSize:'12px', color:'#64748b'}}>SON SENK.</th>
                      <th style={{padding:'15px 25px', textAlign:'right', fontSize:'12px', color:'#64748b'}}>İŞLEMLER</th>
                    </tr>
                  </thead>
                  <tbody>
                    {devices.map(d => (
                      <tr key={d.id} style={{borderBottom:'1px solid #f1f5f9'}}>
                        <td style={{padding:'15px 25px'}}><div style={{fontWeight:'700', color:'#1e293b'}}>{d.name}</div></td>
                        <td style={{padding:'15px 25px'}}><div style={{fontSize:'13px', color:'#475569'}}>{d.ip_address} <span style={{fontSize:'11px', background:'#f1f5f9', padding:'2px 6px', borderRadius:'4px', marginLeft:'5px'}}>{d.vdom}</span></div></td>
                        <td style={{padding:'15px 25px'}}><span className="badge" style={{background:'#f1f5f9', color:'#64748b'}}>{d.status}</span></td>
                        <td style={{padding:'15px 25px'}}><div style={{fontSize:'12px', color:'#94a3b8'}}>{d.last_sync ? new Date(d.last_sync).toLocaleString() : 'Hiç senkronize edilmedi'}</div></td>
                        <td style={{padding:'15px 25px', textAlign:'right'}}>
                          <button onClick={() => setEditingDevice(d)} style={{padding:'6px 12px', borderRadius:'8px', border:'1px solid #e2e8f0', background:'white', fontSize:'12px', fontWeight:'700', marginRight:'10px', cursor:'pointer'}}>Düzenle</button>
                          <button onClick={() => alert('API senkronizasyonu yakında aktif edilecek.')} style={{padding:'6px 12px', borderRadius:'8px', border:'1px solid #e2e8f0', background:'white', fontSize:'12px', fontWeight:'700', marginRight:'10px', cursor:'pointer'}}>Senkronize Et</button>
                          <button onClick={() => handleDeleteDevice(d.id)} style={{padding:'6px 12px', borderRadius:'8px', border:'1px solid #fee2e2', background:'#fef2f2', color:'#ef4444', fontSize:'12px', fontWeight:'700', cursor:'pointer'}}>Sil</button>
                        </td>
                      </tr>
                    ))}
                    {devices.length === 0 && <tr><td colSpan="5" style={{padding:'40px', textAlign:'center', color:'#64748b'}}>Henüz bir cihaz eklenmedi.</td></tr>}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// --- Report Page ---
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
        const delay = Math.max(0, 3000 - elapsed);
        
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
  const stigScore = analysis.stig_score ?? 0; const cisScore = analysis.cis_score ?? 0; const bpScore = analysis.bp_score ?? 0;

  return (
    <div className="app-layout">
      <aside className="report-sidebar">
        <div className="report-sidebar-header">
          <div className="back-btn" onClick={()=>navigate('/')}><ArrowLeft size={18}/><span>Dashboard'a Dön</span></div>
          <div className="device-info-compact">
            <label>Cihaz Analizi</label>
            <span>{summary.device_name || 'FortiGate'}</span>
          </div>
        </div>
        <nav className="report-nav">
          <button className={`report-nav-item ${activeTab==='summary'?'active':''}`} onClick={()=>setActiveTab('summary')}><Info size={18}/><span>Cihaz Özeti</span></button>
          <button className={`report-nav-item ${activeTab==='interface'?'active':''}`} onClick={()=>setActiveTab('interface')}><ArrowRight size={18}/><span>Arayüz Analizi</span></button>
          <button className={`report-nav-item ${activeTab==='ip_analysis'?'active':''}`} onClick={()=>setActiveTab('ip_analysis')}><Database size={18}/><span>IP Analizi</span></button>
          <button className={`report-nav-item ${activeTab==='compliance'?'active':''}`} onClick={()=>setActiveTab('compliance')}><Shield size={18}/><span>Sıkılaştırma Denetimi</span></button>
          <button className={`report-nav-item ${activeTab==='analysis'?'active':''}`} onClick={()=>setActiveTab('analysis')}><Search size={18}/><span>Geniş Erişim Analizi</span></button>
          <button className={`report-nav-item ${activeTab==='profiles'?'active':''}`} onClick={()=>setActiveTab('profiles')}><Activity size={18}/><span>Güvenlik Profil Tespiti</span></button>
          <button className={`report-nav-item ${activeTab==='shadow'?'active':''}`} onClick={()=>setActiveTab('shadow')}><Zap size={18}/><span>Shadow Analizi</span></button>
        </nav>
      </aside>

      <div className="app-main">
        <header className="app-topbar">
          <h2 className="page-title">Denetim Raporu</h2>
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
                          <Shield size={32} style={{color:'#818cf8'}}/>
                        </div>
                        <div>
                          <h1 style={{fontSize:'2rem', fontWeight:'800', marginBottom:'4px'}}>{summary.device_name || 'FortiGate'}</h1>
                          <p style={{opacity:0.6, fontSize:'0.9rem', letterSpacing:'1px', textTransform:'uppercase'}}>Sistem Özet Raporu</p>
                        </div>
                      </div>
                      <div style={{display:'flex', gap:'40px', borderTop:'1px solid rgba(255,255,255,0.1)', paddingTop:'30px'}}>
                        <div>
                          <label style={{fontSize:'10px', color:'#94a3b8', fontWeight:'800', textTransform:'uppercase', display:'block', marginBottom:'5px'}}>Model</label>
                          <span style={{fontSize:'1.1rem', fontWeight:'700'}}>{summary.model}</span>
                        </div>
                        <div>
                          <label style={{fontSize:'10px', color:'#94a3b8', fontWeight:'800', textTransform:'uppercase', display:'block', marginBottom:'5px'}}>Firmware</label>
                          <span style={{fontSize:'1.1rem', fontWeight:'700'}}>{summary.version}</span>
                        </div>
                        <div>
                          <label style={{fontSize:'10px', color:'#94a3b8', fontWeight:'800', textTransform:'uppercase', display:'block', marginBottom:'5px'}}>Analiz Tarihi</label>
                          <span style={{fontSize:'1.1rem', fontWeight:'700'}}>{new Date(file.updated_at).toLocaleDateString()}</span>
                        </div>
                      </div>
                    </div>
                    <div style={{position:'absolute', top:'-20%', right:'-10%', width:'400px', height:'400px', background:'var(--primary)', filter:'blur(120px)', opacity:0.15, borderRadius:'50%'}}></div>
                  </div>

                  <h3 className="section-subtitle">SİSTEM METRİKLERİ</h3>
                  <div style={{display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(220px, 1fr))', gap:'20px', marginBottom:'40px'}}>
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
                  </div>

                  <h3 className="section-subtitle">YAPILANDIRMA DETAYLARI</h3>
                  <div style={{background:'white', borderRadius:'20px', border:'1px solid #e2e8f0', overflow:'hidden', boxShadow:'0 4px 6px -1px rgba(0,0,0,0.05)'}}>
                    <table style={{width:'100%', borderCollapse:'collapse'}}>
                      <tbody>
                        {[
                          ['Cihaz Hostname', summary.device_name],
                          ['İşletim Sistemi', `FortiOS ${summary.version}`],
                          ['Analiz Edilen Dosya', file.file_name],
                          ['Dosya Boyutu', (file.file_size / 1024).toFixed(2) + ' KB'],
                          ['Benzersiz UID', file.file_uid],
                          ['Rapor Durumu', 'Tamamlandı']
                        ].map(([label, val], i) => (
                          <tr key={i} style={{borderBottom: i === 5 ? 'none' : '1px solid #f1f5f9'}}>
                            <td style={{padding:'18px 30px', fontSize:'13px', color:'#64748b', fontWeight:'700', background:'#f8fafc', width:'30%', textTransform:'uppercase', letterSpacing:'0.5px'}}>{label}</td>
                            <td style={{padding:'18px 30px', fontSize:'14px', color:'#1e293b', fontWeight:'700'}}>{val}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {activeTab === 'interface' && (
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
