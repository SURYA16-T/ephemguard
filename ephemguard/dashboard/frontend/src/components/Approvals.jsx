import React from 'react';

function Approvals({ pendingReqs, onDecide }) {
  if (!pendingReqs || pendingReqs.length === 0) {
    return (
      <section className="bg-surface-container-low border border-outline-variant p-space-md text-center">
        <span className="material-symbols-outlined text-4xl text-outline mb-2">verified_user</span>
        <div className="font-code-md text-outline">No pending requests in queue.</div>
      </section>
    );
  }

  return (
    <section className="space-y-4">
      <div className="flex items-center justify-between border-b border-outline-variant pb-2">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-secondary-container">lock_clock</span>
          <h2 className="font-headline-md text-primary">Pending Intercepts</h2>
        </div>
        <span className="bg-secondary-container/20 border border-secondary-container text-secondary-container px-2 py-0.5 font-label-tactical text-[10px]">
          {pendingReqs.length} ACTION REQ
        </span>
      </div>

      <div className="grid gap-4">
        {pendingReqs.map(req => (
          <article key={req.id} className="bg-surface-container-lowest border border-secondary-container/50 p-space-md shadow-[0_0_15px_rgba(0,162,253,0.1)] relative overflow-hidden">
            <div className="absolute top-0 left-0 w-1 h-full bg-secondary-container"></div>
            
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4 pl-2">
              <div>
                <div className="font-code-sm text-outline mb-1">
                  CLIENT: <span className="text-primary-fixed">{req.client}</span>
                </div>
                <div className="font-headline-md text-on-surface">
                  Intercepted Tool: <span className="text-primary font-mono">{req.request.params.name}</span>
                </div>
              </div>
              <div className="flex gap-2">
                <button 
                  onClick={() => onDecide(req.id, false)}
                  className="bg-error-container text-on-error-container font-label-tactical text-label-tactical uppercase tracking-widest px-4 py-2 hover:bg-error hover:text-on-error transition-colors"
                >
                  DENY_EXEC
                </button>
                <button 
                  onClick={() => onDecide(req.id, true)}
                  className="bg-tertiary-container text-on-tertiary-container font-label-tactical text-label-tactical uppercase tracking-widest px-4 py-2 hover:bg-tertiary hover:text-on-tertiary transition-colors shadow-[0_0_8px_rgba(101,242,181,0.4)]"
                >
                  APPROVE
                </button>
              </div>
            </div>

            <div className="bg-surface-container-high border border-outline-variant/50 p-3 ml-2 overflow-x-auto">
              <div className="font-label-tactical text-[9px] text-outline mb-2">PAYLOAD_INSPECTION</div>
              <pre className="font-code-sm text-code-sm text-tertiary-fixed-dim">
                {JSON.stringify(req.request.params.arguments, null, 2)}
              </pre>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

export default Approvals;
