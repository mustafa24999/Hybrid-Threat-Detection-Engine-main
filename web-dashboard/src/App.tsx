/* web-dashboard/src/App.tsx */
import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Dashboard from './components/Dashboard';
import './styles/global.css';

const App: React.FC = () => {
  const [activeView, setActiveView] = useState('dashboard');
  const [isOnline, setIsOnline] = useState(true);

  // Simulate health polling
  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await fetch('http://127.0.0.1:8000/health', {
          headers: { 'X-Zenith-Auth': 'zenith_default_dev_key' }
        });
        setIsOnline(res.ok);
      } catch {
        setIsOnline(false);
      }
    };
    const interval = setInterval(checkHealth, 10000);
    checkHealth();
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="app">
      <Sidebar 
        activeView={activeView} 
        onViewChange={setActiveView} 
        isOnline={isOnline} 
      />
      {activeView === 'dashboard' && <Dashboard />}
      {activeView !== 'dashboard' && (
        <div style={{ marginLeft: '260px', padding: '100px', textAlign: 'center', color: 'var(--fg-dim)' }}>
          <h2>View "{activeView}" is under construction</h2>
          <p>Zenith V4 Enterprise modules are currently being provisioned.</p>
        </div>
      )}
    </div>
  );
};

export default App;
