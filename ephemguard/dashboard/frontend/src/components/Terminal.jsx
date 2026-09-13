import React, { useState, useEffect, useRef } from 'react';

function Terminal({ sysInfo }) {
  const [commands, setCommands] = useState([]);
  const [osType, setOsType] = useState('macos');
  const [output, setOutput] = useState([]);
  const [inputValue, setInputValue] = useState('');
  const outputRef = useRef(null);

  useEffect(() => {
    const fetchCommands = async () => {
      try {
        const res = await fetch('/api/terminal/commands');
        if (res.ok) {
          const data = await res.json();
          setCommands(data.commands);
          setOsType(data.os);
        }
      } catch (e) {
        console.error(e);
      }
    };
    fetchCommands();
  }, []);

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [output]);

  const getPromptPrefix = (os) => {
    if (os === 'macos') return 'ephemguard@mac % ';
    if (os === 'windows') return 'PS C:\\> ';
    return 'ephemguard@linux:~$ ';
  };

  const getPromptClass = (os) => {
    if (os === 'macos') return 'text-secondary-container font-bold';
    if (os === 'windows') return 'text-primary-fixed';
    return 'text-tertiary-fixed';
  };

  const executeCommand = async (id, cmdStr) => {
    setOutput(prev => [...prev, { type: 'input', text: cmdStr, prefix: getPromptPrefix(osType), pClass: getPromptClass(osType) }]);

    try {
      const res = await fetch('/api/terminal/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id })
      });
      const data = await res.json();

      if (data.error) {
        setOutput(prev => [...prev, { type: 'error', text: `[POLICY REJECTED] ${data.error}` }]);
      } else {
        const text = (data.stdout + '\n' + data.stderr).trim() || '(no output)';
        const status = `[Exit code: ${data.returncode} | Executed in: ${data.duration_ms ? data.duration_ms.toFixed(2) + 'ms' : ''}]`;
        setOutput(prev => [...prev, { type: 'result', text, status, success: data.returncode === 0 }]);
      }
    } catch (e) {
      setOutput(prev => [...prev, { type: 'error', text: `Connection error: ${e.message}` }]);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!inputValue.trim()) return;
    const val = inputValue.trim();
    setInputValue('');

    const found = commands.find(c => c.id.toLowerCase() === val.toLowerCase() || c.command.toLowerCase() === val.toLowerCase());
    if (found) {
      executeCommand(found.id, found.command);
    } else {
      executeCommand(val, val);
    }
  };

  const handleClear = () => {
    setOutput([]);
  };

  const handleRunAll = () => {
    commands.forEach((c, i) => {
      setTimeout(() => {
        executeCommand(c.id, c.command);
      }, i * 500);
    });
  };

  return (
    <section className="bg-surface-container-low border border-outline-variant p-space-md flex flex-col gap-3 h-150">
      <div className="flex items-center justify-between border-b border-outline-variant/60 pb-2">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-primary-container text-lg">terminal</span>
          <div className="font-code-sm text-code-sm text-outline">
            <span className="text-primary font-mono">DIAGNOSTICS CLI</span> // <span className="text-on-surface uppercase font-mono">{osType}</span>
          </div>
        </div>
        <div className="flex gap-2">
          <button onClick={handleClear} className="bg-surface-container-high border border-outline-variant text-on-surface-variant font-code-sm text-[10px] px-2 py-1 hover:text-error hover:border-error transition-colors">CLEAR</button>
          <button onClick={handleRunAll} className="bg-primary-container/10 border border-primary-container text-primary-container font-code-sm text-[10px] px-2 py-1 hover:bg-primary-container hover:text-surface-container-lowest transition-colors">RUN ALL</button>
        </div>
      </div>
      
      <div ref={outputRef} className="flex-1 overflow-y-auto bg-surface-container-lowest border border-outline-variant/50 p-3 font-code-sm text-code-sm space-y-2">
        <div><span className="text-outline">EphemGuard Diagnostics Console</span></div>
        <div><span className="text-primary-container">Tip:</span> <span className="text-outline">Type a command ID below or click any pre-approved button.</span></div>
        <br/>
        
        {output.map((item, idx) => (
          <div key={idx} className="break-all whitespace-pre-wrap">
            {item.type === 'input' && (
              <div>
                <span className={item.pClass}>{item.prefix}</span>
                <span className="text-on-surface font-semibold">{item.text}</span>
              </div>
            )}
            {item.type === 'error' && <div className="text-error font-semibold mt-1">{item.text}</div>}
            {item.type === 'result' && (
              <div className="text-on-surface-variant mt-1">
                {item.text}
                <div className={`text-[10px] mt-1 ${item.success ? 'text-tertiary-container' : 'text-error'}`}>{item.status}</div>
              </div>
            )}
          </div>
        ))}
      </div>

      <form onSubmit={handleSubmit} className="flex items-center gap-2 bg-surface-container-lowest border border-outline-variant/50 p-2">
        <span className={`font-code-sm text-code-sm ${getPromptClass(osType)}`}>{getPromptPrefix(osType)}</span>
        <input 
          type="text" 
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          className="flex-1 bg-transparent border-none text-primary focus:ring-0 focus:outline-none font-code-sm text-code-sm"
          placeholder="Type a diagnostic command..."
          autoComplete="off"
          spellCheck="false"
        />
        <button type="submit" className="text-primary-container hover:text-primary transition-colors">
          <span className="material-symbols-outlined text-lg">send</span>
        </button>
      </form>

      <div className="flex flex-wrap gap-2 pt-2 border-t border-outline-variant/60">
        {commands.map(cmd => (
          <button 
            key={cmd.id}
            title={cmd.command}
            onClick={() => executeCommand(cmd.id, cmd.command)}
            className="bg-surface-container border border-outline-variant text-on-surface-variant hover:text-primary hover:border-primary-container px-2 py-1 font-code-sm text-[10px] uppercase transition-all"
          >
            {cmd.id}
          </button>
        ))}
      </div>
    </section>
  );
}

export default Terminal;
