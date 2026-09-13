import React, { useState, useEffect } from 'react';
import Overview from './components/Overview';
import Terminal from './components/Terminal';
import Approvals from './components/Approvals';
import Audit from './components/Audit';

function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [sysInfo, setSysInfo] = useState(null);
  const [pendingReqs, setPendingReqs] = useState([]);

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

  useEffect(() => {
    fetchSystemInfo();
    fetchPending();
    const interval = setInterval(() => {
      fetchSystemInfo();
      fetchPending();
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
        {activeTab === 'overview' && <Overview sysInfo={sysInfo} />}
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
