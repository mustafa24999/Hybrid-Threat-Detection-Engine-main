/* web-dashboard/src/components/Sidebar.tsx */
import React from 'react';
import styles from './Sidebar.module.css';

interface SidebarProps {
  activeView: string;
  onViewChange: (view: string) => void;
  isOnline: boolean;
}

const Sidebar: React.FC<SidebarProps> = ({ activeView, onViewChange, isOnline }) => {
  const navItems = [
    { id: 'dashboard', label: 'Overview', icon: '📊' },
    { id: 'scanner', label: 'Threat Scanner', icon: '🛡️' },
    { id: 'history', label: 'Scan History', icon: '📜' },
    { id: 'intel', label: 'Threat Intel', icon: '🌐' },
    { id: 'settings', label: 'Settings', icon: '⚙️' },
  ];

  return (
    <aside className={styles.sidebar}>
      <div className={styles.logoArea}>
        <div className={styles.logo}>ZENITH</div>
        <div className={styles.logoSub}>HYBRID THREAT ENGINE</div>
      </div>

      <nav className={styles.nav}>
        {navItems.map((item) => (
          <a
            key={item.id}
            href="#"
            className={`${styles.navItem} ${activeView === item.id ? styles.navActive : ''}`}
            onClick={(e) => {
              e.preventDefault();
              onViewChange(item.id);
            }}
          >
            <span className={styles.icon}>{item.icon}</span>
            {item.label}
          </a>
        ))}
      </nav>

      <div className={styles.footer}>
        <div className={styles.status}>
          <div className={`${styles.pulse} ${!isOnline ? styles.offline : ''}`} 
               style={{ background: isOnline ? 'var(--success)' : 'var(--danger)', boxShadow: `0 0 8px ${isOnline ? 'var(--success)' : 'var(--danger)'}` }} />
          SYSTEM {isOnline ? 'ONLINE' : 'OFFLINE'}
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
