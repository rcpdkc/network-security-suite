import React from 'react';
import { Terminal, X } from 'lucide-react';

const DebugMenu = ({ isOpen, onClose, scanLogs = [], onStopScan, onClearLogs }) => {
  if (!isOpen) return null;
  
  const logsArray = Array.isArray(scanLogs) ? scanLogs : [];
  const groupedLogs = logsArray.reduce((acc, log) => {
    const scanId = log.scanId || 'default';
    if (!acc[scanId]) acc[scanId] = [];
    acc[scanId].push(log);
    return acc;
  }, {});

  const getTypeColor = (type) => {
    switch(type) {
      case 'success': return '#10b981';
      case 'error': return '#ef4444';
      case 'warning': return '#f59e0b';
      default: return '#6366f1';
    }
  };

  const getTypeIcon = (type) => {
    switch(type) {
      case 'success': return 'O';
      case 'error': return 'X';
      case 'warning': return '!';
      default: return 'i';
    }
  };

  return (
    <div style={{position:'fixed', top:0, left:0, right:0, bottom:0, background:'rgba(15,23,42,0.6)', backdropFilter:'blur(4px)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:1001}}>
      <div style={{background:'white', width:'90%', maxWidth:'900px', maxHeight:'85vh', borderRadius:'24px', boxShadow:'0 25px 50px -12px rgba(0,0,0,0.25)', display:'flex', flexDirection:'column', overflow:'hidden', animation:'zoomIn 0.2s ease-out'}}>
        
        <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', padding:'24px', borderBottom:'1px solid #e2e8f0', background:'linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%)'}}>
          <div>
            <h2 style={{margin:0, fontSize:'1.25rem', fontWeight:'800', color:'#1e293b', display:'flex', alignItems:'center', gap:'10px'}}>
              <Terminal size={24} style={{color:'#6366f1'}}/>
              Scan Debug Logs
            </h2>
            <p style={{margin:'4px 0 0', fontSize:'13px', color:'#64748b'}}>
              {logsArray.length} total entries
            </p>
          </div>
          <button onClick={onClose} style={{background:'none', border:'none', cursor:'pointer', color:'#64748b', padding:'8px', display:'flex', alignItems:'center', justifyContent:'center', borderRadius:'8px'}}>
            <X size={24}/>
          </button>
        </div>

        <div style={{flex:1, overflow:'auto', padding:'24px', backgroundColor:'#fafbfc'}}>
          {logsArray.length === 0 ? (
            <div style={{textAlign:'center', padding:'60px 20px', color:'#64748b', display:'flex', flexDirection:'column', alignItems:'center', gap:'15px'}}>
              <Terminal size={48} style={{opacity:0.3}}/>
              <p>No scan logs. Start scanning to see entries here.</p>
            </div>
          ) : (
            <div style={{display:'grid', gap:'20px'}}>
              {Object.entries(groupedLogs).map(([scanId, logs]) => (
                <div key={scanId} style={{background:'white', borderRadius:'16px', border:'1px solid #e2e8f0', overflow:'hidden', boxShadow:'0 4px 6px -1px rgba(0,0,0,0.05)'}}>
                  
                  <div style={{padding:'16px', backgroundColor:'#f8fafc', borderBottom:'1px solid #e2e8f0', display:'flex', justifyContent:'space-between', alignItems:'center'}}>
                    <div style={{display:'flex', alignItems:'center', gap:'12px', flex:1}}>
                      <div style={{width:'12px', height:'12px', borderRadius:'50%', background:'#6366f1', animation:'pulse 2s infinite'}}></div>
                      <div>
                        <div style={{fontSize:'14px', fontWeight:'700', color:'#1e293b'}}>
                          Scan ID: {scanId.substring(0, 8)}
                        </div>
                        <div style={{fontSize:'12px', color:'#64748b', marginTop:'2px'}}>
                          {logs.length} entries
                        </div>
                      </div>
                    </div>
                    <div style={{display:'flex', gap:'8px'}}>
                      <button 
                        onClick={() => onStopScan(scanId)}
                        style={{padding:'8px 16px', borderRadius:'8px', border:'1px solid #f59e0b', background:'#fffbeb', color:'#92400e', fontWeight:'600', cursor:'pointer', fontSize:'12px'}}
                      >
                        Stop
                      </button>
                      <button 
                        onClick={() => onStopScan(scanId)}
                        style={{padding:'8px 16px', borderRadius:'8px', border:'1px solid #ef4444', background:'#fef2f2', color:'#991b1b', fontWeight:'600', cursor:'pointer', fontSize:'12px'}}
                      >
                        Cancel
                      </button>
                    </div>
                  </div>

                  <div style={{padding:'16px', display:'grid', gap:'10px', maxHeight:'300px', overflow:'auto'}}>
                    {logs.map((log) => (
                      <div key={log.id} style={{display:'flex', alignItems:'flex-start', gap:'12px', fontSize:'13px'}}>
                        <div style={{
                          background:getTypeColor(log.type),
                          color:'white',
                          width:'24px',
                          height:'24px',
                          borderRadius:'50%',
                          display:'flex',
                          alignItems:'center',
                          justifyContent:'center',
                          fontWeight:'bold',
                          fontSize:'12px',
                          flexShrink:0,
                          marginTop:'2px'
                        }}>
                          {getTypeIcon(log.type)}
                        </div>
                        <div style={{flex:1}}>
                          <div style={{color:"#1e293b", fontWeight:"500"}}>{log.message}</div>
                          <div style={{fontSize:"11px", color:"#94a3b8", marginTop:"2px"}}>{log.timestamp}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div style={{padding:'16px 24px', borderTop:'1px solid #e2e8f0', background:'#f8fafc', display:'flex', justifyContent:'space-between', alignItems:'center'}}>
          <button 
            onClick={onClearLogs}
            style={{padding:'10px 20px', borderRadius:'10px', border:'1px solid #e2e8f0', background:'white', color:'#64748b', fontWeight:'600', cursor:'pointer', fontSize:'13px'}}
          >
            Clear
          </button>
          <button 
            onClick={onClose}
            style={{padding:'10px 24px', borderRadius:'10px', border:'none', background:'var(--primary)', color:'white', fontWeight:'600', cursor:'pointer', fontSize:'13px'}}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

export default DebugMenu;
