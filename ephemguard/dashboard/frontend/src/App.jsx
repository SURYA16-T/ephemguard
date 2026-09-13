import React, { useState, useEffect } from 'react';
import Overview from './components/Overview';
import Terminal from './components/Terminal';
import Approvals from './components/Approvals';
import Audit from './components/Audit';

function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [sysInfo, setSysInfo] = useState(null);
  const [pendingReqs, setPendingReqs] = useState([]);
  const [requireApproval, setRequireApproval] = useState(false);

  const fetchSystemInfo = async () => {
    try {
      const res = await fetch('/api/system');
      if (res.ok) setSysInfo(await res.json());
    } catch (e) {
      console.error(e);
    }
  };

  const fetchPending = async () => {
    try {
      const res = await fetch('/api/pending');
      if (res.ok) setPendingReqs(await res.json());
    } catch (e) {
      console.error(e);
    }
  };

  const fetchSettings = async () => {
    try {
      const res = await fetch('/api/settings/approval');
      if (res.ok) {
        const data = await res.json();
        setRequireApproval(data.require_approval);
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchSystemInfo();
    fetchPending();
    fetchSettings();
    const interval = setInterval(() => {
      fetchSystemInfo();
      fetchPending();
      fetchSettings();
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const handleApproveDeny = async (id, approved) => {
    try {
      await fetch('/api/decide', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, approved })
      });
      fetchPending();
    } catch (e) {
      console.error(e);
    }
  };

  const toggleApprovalSetting = async () => {
    try {
      const newValue = !requireApproval;
      await fetch('/api/settings/approval', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ require_approval: newValue })
      });
      setRequireApproval(newValue);
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="bg-surface-container-lowest text-on-surface font-body-md antialiased min-h-screen pb-24 selection:bg-primary-container selection:text-on-primary select-none bg-grid-cyber">
      {/* Header */}
      <header className="bg-surface-container-low docked full-width top-0 sticky z-30 flex justify-between items-center w-full px-space-md py-space-sm max-w-full">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5">
            <span className="material-symbols-outlined text-primary-container text-xl animate-pulse">shield</span>
            <span className="font-headline-md text-headline-md uppercase tracking-wider text-primary">EPHEMGUARD</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <a href="https://github.com/SURYA16-T/ephemguard" target="_blank" rel="noopener noreferrer" className="text-on-surface-variant hover:text-primary-container transition-colors hidden sm:flex items-center" title="View Source on GitHub">
            <svg viewBox="0 0 24 24" className="w-5 h-5 fill-current"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
          </a>
          <div className="hidden sm:flex items-center gap-1.5 px-2 py-0.5 bg-surface-container-lowest border border-outline-variant text-[10px] font-code-sm text-tertiary-container">
            <span className="inline-block w-1.5 h-1.5 bg-tertiary-container animate-ping"></span>
            ONLINE // ZERO-TRUST
          </div>
          <div className="px-2 py-1 bg-surface-container-high text-primary-container border border-outline-variant font-label-tactical text-label-tactical uppercase tracking-wider flex items-center gap-1.5">
            <span className="inline-block w-1.5 h-1.5 bg-primary-container"></span>
            <span>SEC_DEFENSE</span>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="w-full px-space-md py-space-sm space-y-space-md mt-4">
        {activeTab === 'overview' && <Overview sysInfo={sysInfo} requireApproval={requireApproval} onToggleApproval={toggleApprovalSetting} />}
        {activeTab === 'terminal' && <Terminal sysInfo={sysInfo} />}
        {activeTab === 'approvals' && <Approvals pendingReqs={pendingReqs} onDecide={handleApproveDeny} />}
        {activeTab === 'audit' && <Audit />}
      </main>

      {/* Bottom Nav */}
      <nav className="fixed bottom-0 left-0 w-full z-50 flex justify-around items-center px-space-xs py-space-xs bg-surface-container-low border-t border-outline-variant shadow-2xl">
        <button onClick={() => setActiveTab('overview')} className={`flex flex-col items-center justify-center pt-1 w-1/4 transition-colors ${activeTab === 'overview' ? 'text-primary-container border-t-2 border-primary-container' : 'text-on-surface-variant hover:text-primary active:scale-95'}`}>
          <span className="material-symbols-outlined text-xl">shield</span>
          <span className="font-code-sm text-code-sm font-medium tracking-tight">Overview</span>
        </button>
        <button onClick={() => setActiveTab('terminal')} className={`flex flex-col items-center justify-center pt-1 w-1/4 transition-colors ${activeTab === 'terminal' ? 'text-primary-container border-t-2 border-primary-container' : 'text-on-surface-variant hover:text-primary active:scale-95'}`}>
          <span className="material-symbols-outlined text-xl">terminal</span>
          <span className="font-code-sm text-code-sm tracking-tight">Terminal</span>
        </button>
        <button onClick={() => setActiveTab('approvals')} className={`flex flex-col items-center justify-center pt-1 w-1/4 transition-colors relative ${activeTab === 'approvals' ? 'text-primary-container border-t-2 border-primary-container' : 'text-on-surface-variant hover:text-primary active:scale-95'}`}>
          <div className="relative">
            <span className="material-symbols-outlined text-xl">lock</span>
            {pendingReqs.length > 0 && <span className="absolute -top-1 -right-1 w-2 h-2 bg-secondary-container rounded-full"></span>}
          </div>
          <span className="font-code-sm text-code-sm tracking-tight">Approvals</span>
        </button>
        <button onClick={() => setActiveTab('audit')} className={`flex flex-col items-center justify-center pt-1 w-1/4 transition-colors ${activeTab === 'audit' ? 'text-primary-container border-t-2 border-primary-container' : 'text-on-surface-variant hover:text-primary active:scale-95'}`}>
          <span className="material-symbols-outlined text-xl">manage_search</span>
          <span className="font-code-sm text-code-sm tracking-tight">Audit</span>
        </button>
      </nav>
    </div>
  );
}

export default App;
