import React from 'react';

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function Overview({ sysInfo }) {
  if (!sysInfo) {
    return <div className="text-on-surface-variant font-code-md">Loading telemetry...</div>;
  }

  return (
    <>
      <div className="bg-surface-container-low border border-outline-variant p-space-md corner-tick">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-headline-xl text-headline-xl text-primary font-bold tracking-tight">System Overview</h1>
              <span className="bg-primary-container/10 border border-primary-container/40 text-primary-container px-1.5 py-0.2 font-label-tactical text-[9px] uppercase tracking-widest">
                LIVE_INGRESS
              </span>
            </div>
            <p className="font-code-sm text-code-sm text-on-surface-variant mt-0.5">Tactical telemetry & node integrity monitoring</p>
          </div>
          <div className="flex flex-wrap items-center gap-2 mt-1 sm:mt-0">
            <div className="flex items-center gap-1.5 px-2 py-1 bg-surface-container border border-tertiary-container/50 text-tertiary-container font-label-tactical text-label-tactical">
              <span className="w-1.5 h-1.5 bg-tertiary-container"></span>
              DEFENSE MATRIX // THREAT LEVEL 1
            </div>
            <div className="px-2 py-1 bg-surface-container-lowest border border-outline-variant text-on-surface-variant font-code-sm text-[10px]">
              CLUSTER: <span className="text-primary">{sysInfo.platform || sysInfo.os}</span>
            </div>
          </div>
        </div>
      </div>

      <section className="grid grid-cols-1 md:grid-cols-2 gap-space-md">
        <article className="bg-surface-container-low border border-outline-variant p-space-md relative overflow-hidden flex flex-col justify-between">
          <div className="absolute top-0 right-0 w-16 h-16 pointer-events-none opacity-10 flex items-center justify-center text-primary-container">
            <span className="material-symbols-outlined text-6xl">memory</span>
          </div>
          <div>
            <div className="flex items-center justify-between border-b border-outline-variant/60 pb-space-xs mb-2">
              <span className="font-label-tactical text-label-tactical uppercase tracking-wider text-on-surface-variant flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 bg-primary-container"></span>
                TELEMETRY // CPU LOAD
              </span>
            </div>
            <div className="flex items-baseline gap-2 mt-1">
              <div className="font-headline-xl text-3xl font-bold text-primary tracking-tight">
                {sysInfo.has_psutil ? sysInfo.cpu.usage_percent : '--'}%
              </div>
              <span className="text-outline font-code-sm text-code-sm uppercase">UTILIZED</span>
            </div>
            <div className="mt-3 space-y-1.5">
              <div className="flex justify-between text-code-sm font-code-sm text-on-surface-variant">
                <span>Cores: <strong className="text-primary font-mono">{sysInfo.has_psutil ? sysInfo.cpu.physical_cores : '-'} Physical, {sysInfo.has_psutil ? sysInfo.cpu.total_cores : '-'} Logical</strong></span>
              </div>
            </div>
          </div>
        </article>

        <article className="bg-surface-container-low border border-outline-variant p-space-md relative overflow-hidden flex flex-col justify-between">
          <div className="absolute top-0 right-0 w-16 h-16 pointer-events-none opacity-10 flex items-center justify-center text-primary-container">
            <span className="material-symbols-outlined text-6xl">storage</span>
          </div>
          <div>
            <div className="flex items-center justify-between border-b border-outline-variant/60 pb-space-xs mb-2">
              <span className="font-label-tactical text-label-tactical uppercase tracking-wider text-on-surface-variant flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 bg-primary-container"></span>
                BUFFER // RAM
              </span>
            </div>
            <div className="flex items-baseline gap-2 mt-1">
              <div className="font-headline-xl text-3xl font-bold text-primary tracking-tight">
                {sysInfo.has_psutil ? sysInfo.memory.usage_percent : '--'}%
              </div>
            </div>
            <div className="mt-3 space-y-1.5 text-code-sm font-code-sm">
              <div className="flex justify-between text-outline">
                <span>Used: {sysInfo.has_psutil ? formatBytes(sysInfo.memory.used_bytes) : '-'}</span>
                <span>Total: {sysInfo.has_psutil ? formatBytes(sysInfo.memory.total_bytes) : '-'}</span>
              </div>
            </div>
          </div>
        </article>
      </section>

      <section className="bg-surface-container-low border border-outline-variant overflow-hidden">
        <div className="px-space-md py-space-sm bg-surface-container border-b border-outline-variant flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-primary-container text-base">dns</span>
            <span className="font-label-tactical text-label-tactical uppercase tracking-wider text-primary">NODE TELEMETRY & SPECIFICATION</span>
          </div>
          <div className="flex items-center gap-1.5 font-code-sm text-[11px] text-tertiary-container">
            <span className="w-1.5 h-1.5 bg-tertiary-container rounded-none"></span>
            INTEGRITY VALID
          </div>
        </div>
        <div className="divide-y divide-outline-variant/40 font-code-sm text-code-sm">
          <div className="p-space-sm sm:px-space-md flex flex-col sm:flex-row sm:items-center justify-between gap-1 hover:bg-surface-container transition-colors">
            <span className="text-outline flex items-center gap-1.5"><span className="text-primary-container">#</span> OS</span>
            <span className="text-primary font-mono">{sysInfo.os}</span>
          </div>
          <div className="p-space-sm sm:px-space-md flex flex-col sm:flex-row sm:items-center justify-between gap-1 hover:bg-surface-container transition-colors bg-surface-container-lowest/50">
            <span className="text-outline flex items-center gap-1.5"><span className="text-primary-container">#</span> Platform</span>
            <span className="text-on-surface font-mono">{sysInfo.platform}</span>
          </div>
          <div className="p-space-sm sm:px-space-md flex flex-col sm:flex-row sm:items-center justify-between gap-1 hover:bg-surface-container transition-colors">
            <span className="text-outline flex items-center gap-1.5"><span className="text-primary-container">#</span> Architecture</span>
            <span className="text-tertiary-container font-mono">{sysInfo.architecture}</span>
          </div>
          <div className="p-space-sm sm:px-space-md flex flex-col sm:flex-row sm:items-center justify-between gap-1 hover:bg-surface-container transition-colors bg-surface-container-lowest/50">
            <span className="text-outline flex items-center gap-1.5"><span className="text-primary-container">#</span> Python</span>
            <span className="text-secondary-fixed-dim font-mono">{sysInfo.python_version}</span>
          </div>
          {sysInfo.has_psutil && (
            <>
              <div className="p-space-sm sm:px-space-md flex flex-col sm:flex-row sm:items-center justify-between gap-1 hover:bg-surface-container transition-colors">
                <span className="text-outline flex items-center gap-1.5"><span className="text-primary-container">#</span> Active Processes</span>
                <span className="text-primary font-mono">{sysInfo.processes}</span>
              </div>
              <div className="p-space-sm sm:px-space-md flex flex-col sm:flex-row sm:items-center justify-between gap-1 hover:bg-surface-container transition-colors bg-surface-container-lowest/50">
                <span className="text-outline flex items-center gap-1.5"><span className="text-primary-container">#</span> Network Sent/Recv</span>
                <span className="text-on-surface font-mono">{formatBytes(sysInfo.network.bytes_sent)} / {formatBytes(sysInfo.network.bytes_recv)}</span>
              </div>
            </>
          )}
        </div>
      </section>
    </>
  );
}

export default Overview;
