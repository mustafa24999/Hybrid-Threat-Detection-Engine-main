/* web-dashboard/src/components/Dashboard.tsx */
import React, { useState } from 'react';
import styles from './Dashboard.module.css';

const Dashboard: React.FC = () => {
  const [url, setUrl] = useState('https://');

  const stats = [
    { label: 'Total Scans', value: '1,284' },
    { label: 'Malicious', value: '42' },
    { label: 'Avg Risk', value: '18%' },
    { label: 'Threat Intelligence', value: 'Active' },
  ];

  return (
    <main className={styles.container}>
      <header className={styles.header}>
        <h1 className={styles.title}>Threat Intelligence Overview</h1>
        <p className={styles.subtitle}>Unified visibility into hybrid URL and file-based threats.</p>
      </header>

      <div className={styles.statsGrid}>
        {stats.map((stat) => (
          <div key={stat.label} className={styles.card}>
            <div className={styles.cardLabel}>{stat.label}</div>
            <div className={styles.cardValue}>{stat.value}</div>
          </div>
        ))}
      </div>

      <div className={styles.scannerCard}>
        <h2 className={styles.cardLabel} style={{ color: 'var(--accent)' }}>Advanced Analysis</h2>
        <h3 style={{ fontSize: '20px', fontWeight: '800', marginTop: '8px' }}>Security Audit Scanner</h3>
        <p className={styles.subtitle} style={{ marginTop: '4px' }}>Submit URLs or File Hashes for immediate risk assessment.</p>
        
        <div className={styles.inputGroup}>
          <input 
            type="text" 
            className={styles.input} 
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
          />
          <button className={styles.primaryBtn}>ANALYZE TARGET</button>
        </div>
      </div>

      <div className={styles.resultsArea}>
        Awaiting analysis request...
      </div>
    </main>
  );
};

export default Dashboard;
