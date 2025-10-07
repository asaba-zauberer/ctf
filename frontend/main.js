(() => {
  const PROMPT = '> ';
  const outputEl = document.getElementById('terminal-output');
  const commandForm = document.getElementById('command-form');
  const commandInput = document.getElementById('command-input');
  const scenarioInfoEl = document.getElementById('scenario-info');
  const scenarioSelectEl = document.getElementById('scenario-select');
  const sessionDisplayEl = document.getElementById('session-display');
  const statusMessageEl = document.getElementById('status-message');

  let sessionId = null;
  let history = [];
  let historyIndex = -1;
  let lastOutput = '';
  let defaultRender = 'text';
  let cliName = 'Shared CLI Terminal';
  let scenarios = [];
  let selectedScenario = null;

  scenarioSelectEl.disabled = true;

  function setStatus(text) {
    statusMessageEl.textContent = text || '';
  }

  function updateSessionSummary() {
    if (!sessionId) {
      sessionDisplayEl.textContent = '';
      return;
    }

    const active = scenarios.find((item) => item.slug === selectedScenario);
    const scenarioLabel = active ? `${active.slug} (${active.name})` : 'n/a';
    sessionDisplayEl.textContent = `Session: ${shortenSessionId(sessionId)} • Scenario: ${scenarioLabel}`;
  }

  function setSelectedScenario(slug) {
    if (!slug) {
      selectedScenario = null;
      scenarioSelectEl.value = '';
      scenarioInfoEl.textContent = cliName;
      updateSessionSummary();
      return;
    }

    const match = scenarios.find((item) => item.slug === slug);
    if (!match) {
      return;
    }

    selectedScenario = match.slug;
    scenarioSelectEl.value = match.slug;
    scenarioInfoEl.textContent = `${cliName} – ${match.name}`;
    updateSessionSummary();
  }

  function populateScenarios(list, defaultSlug) {
    scenarios = Array.isArray(list) ? list.slice() : [];
    scenarioSelectEl.innerHTML = '';
    scenarios.forEach((item) => {
      const option = document.createElement('option');
      option.value = item.slug;
      option.textContent = `${item.slug} — ${item.name}`;
      scenarioSelectEl.appendChild(option);
    });

    scenarioSelectEl.disabled = scenarios.length === 0;

    if (scenarios.length === 0) {
      setSelectedScenario(null);
      return;
    }

    const preferred = scenarios.find((item) => item.slug === defaultSlug);
    setSelectedScenario((preferred || scenarios[0]).slug);
  }

  function appendBlock(text, className = 'stdout') {
    const block = document.createElement('pre');
    block.className = `output-block ${className}`;
    block.textContent = text;
    outputEl.appendChild(block);
    outputEl.scrollTop = outputEl.scrollHeight;
  }

  function appendCommandEcho(command) {
    appendBlock(`${PROMPT}${command}`, 'command');
  }

  function clearOutput() {
    outputEl.innerHTML = '';
    lastOutput = '';
    setStatus('Cleared');
  }

  async function hydrateMeta() {
    try {
      const response = await fetch('api/meta');
      if (!response.ok) throw new Error('meta request failed');
      const data = await response.json();
      sessionId = data.sessionId;
      defaultRender = 'text';
      cliName = data.cliName || cliName;
      populateScenarios(data.scenarios || [], data.defaultScenario);
      updateSessionSummary();
      appendBlock('Sessions expire automatically after 30 minutes.');
      appendBlock('Welcome to the AWS CLI CTF simulator!');
      appendBlock('Select a scenario before running AWS CLI style commands, or type \"clear\" to reset the terminal.');
      commandInput.focus();
    } catch (err) {
      scenarioInfoEl.textContent = 'Scenario failed to load';
      appendBlock('Failed to load scenario metadata. Please retry later.', 'error');
      scenarioSelectEl.disabled = true;
      scenarioSelectEl.innerHTML = '';
      setStatus('Meta load error');
    }
  }

  function shortenSessionId(id) {
    if (!id) return 'n/a';
    return `${id.slice(0, 4)}…${id.slice(-4)}`;
  }

  async function runCommand(rawCommand) {
    const command = rawCommand.trim();
    if (!sessionId) {
      appendBlock('Session not ready. Refresh and try again.', 'error');
      return;
    }
    if (!selectedScenario) {
      appendBlock('Select a scenario before running commands.', 'error');
      setStatus('Scenario required');
      return;
    }

    try {
      const response = await fetch('api/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId, command, scenarioSlug: selectedScenario }),
      });
      let data = {};
      try {
        data = await response.json();
      } catch (parseErr) {
        appendBlock('Received invalid JSON response.', 'error');
        setStatus('Response parse error');
        return;
      }

      if (response.status === 429) {
        appendBlock('Error: rate limit exceeded (5 req/s).', 'error');
        setStatus('Rate limited');
        lastOutput = 'Error: rate limit exceeded (5 req/s).';
        return;
      }

      if (!data.ok) {
        const message = data.message || 'Unknown error';
        appendBlock(`Error (${data.errorCode || 'Error'}): ${message}`, 'error');
        setStatus(`Exit ${data.exitCode ?? 255}`);
        lastOutput = message;
        return;
      }

      const renderPreference = data.render || defaultRender;
      let outputText = data.stdout || '';
      if (renderPreference === 'json' && data.json && Object.keys(data.json).length) {
        outputText = JSON.stringify(data.json, null, 2);
      }
      if (renderPreference === 'text' && !outputText && data.json) {
        outputText = JSON.stringify(data.json, null, 2);
      }
      if (outputText) {
        appendBlock(outputText.replace(/\n$/, ''));
      }
      lastOutput = outputText;
      setStatus(`Exit ${data.exitCode ?? 0}`);
    } catch (err) {
      appendBlock('Network error occurred.', 'error');
      setStatus('Network error');
    }
  }

  commandForm.addEventListener('submit', (event) => {
    event.preventDefault();
    const rawValue = commandInput.value;
    const command = rawValue.trim();
    if (!command) {
      commandInput.value = '';
      return;
    }
    appendCommandEcho(command);
    commandInput.value = '';
    history.unshift(command);
    historyIndex = -1;

    if (command.toLowerCase() === 'clear') {
      clearOutput();
      return;
    }

    runCommand(command);
  });

  commandInput.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowUp') {
      if (history.length > 0 && historyIndex + 1 < history.length) {
        historyIndex += 1;
        commandInput.value = history[historyIndex];
        setTimeout(() => commandInput.setSelectionRange(commandInput.value.length, commandInput.value.length), 0);
      }
      event.preventDefault();
    } else if (event.key === 'ArrowDown') {
      if (historyIndex > 0) {
        historyIndex -= 1;
        commandInput.value = history[historyIndex];
      } else {
        historyIndex = -1;
        commandInput.value = '';
      }
      setTimeout(() => commandInput.setSelectionRange(commandInput.value.length, commandInput.value.length), 0);
      event.preventDefault();
    }
  });

  scenarioSelectEl.addEventListener('change', (event) => {
    const value = event.target.value;
    setSelectedScenario(value);
    setStatus(`Scenario set to ${value || 'n/a'}`);
    commandInput.focus();
  });

  hydrateMeta();
})();
