import React, { useState, useEffect } from 'react';

function Audit() {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    const fetchAudit = async () => {
      try {
        const res = await fetch('/api/audit?limit=50');
        if (res.ok) {
          setLogs(await res.json());
        }
      } catch (e) {
        console.error(e);
      }
    };
    fetchAudit();
    const interval = setInterval(fetchAudit, 2000);
    return () => clearInterval(interval);
  }, []);

  return (
    <section className="bg-surface-container-low border border-outline-variant overflow-hidden">
      <div className="px-space-md py-space-sm bg-surface-container border-b border-outline-variant flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-primary-container text-base">manage_search</span>
          <span className="font-label-tactical text-label-tactical uppercase tracking-wider text-primary">TAMPER-EVIDENT AUDIT LEDGER</span>
        </div>
      </div>
      
      <div className="overflow-x-auto">
        <table className="w-full text-left font-code-sm text-code-sm">
          <thead className="bg-surface-container-highest text-outline font-label-tactical text-[9px] uppercase tracking-widest border-b border-outline-variant">
            <tr>
              <th className="p-3">Time (UTC)</th>
              <th className="p-3">Client</th>
              <th className="p-3">Event</th>
              <th className="p-3">Tool</th>
              <th className="p-3">Reason</th>
              <th className="p-3">Hash Chain</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-outline-variant/40">
            {logs.length === 0 ? (
              <tr>
                <td colSpan="6" className="p-4 text-center text-outline">No ledger entries found.</td>
              </tr>
            ) : (
              logs.map((log, idx) => {
                const isAllowed = log.event === 'ToolCallAllowed';
                const d = new Date(log.ts * 1000);
                return (
                  <tr key={idx} className="hover:bg-surface-container transition-colors">
                    <td className="p-3 text-on-surface-variant">{d.toLocaleTimeString()}</td>
                    <td className="p-3 text-primary-fixed-dim">{log.client || 'unknown'}</td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 border ${isAllowed ? 'bg-tertiary-container/10 border-tertiary-container/50 text-tertiary-container' : 'bg-error-container/10 border-error-container/50 text-error'} font-label-tactical text-[9px]`}>
                        {isAllowed ? 'ALLOWED' : 'DENIED'}
                      </span>
                    </td>
                    <td className="p-3">
                      <span className="text-secondary-fixed bg-surface-container px-1 py-0.5 border border-outline-variant/50 font-mono">
                        {log.tool || '-'}
                      </span>
                    </td>
                    <td className="p-3 text-on-surface truncate max-w-50" title={log.reason}>{log.reason || '-'}</td>
                    <td className="p-3 text-outline font-mono text-[10px]" title={`Hash: ${log.hash}\nPrev: ${log.prev_hash}`}>
                      {log.hash ? log.hash.substring(0, 16) + '...' : '-'}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default Audit;
