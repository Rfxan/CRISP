import React from 'react';
import { ShieldAlert } from 'lucide-react';

export default function Sidebar({ tabs, activeTab, setActiveTab }) {
  return (
    <div style={{
      width: 100,
      minWidth: 100,
      background: 'var(--bg-sidebar)',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      paddingTop: 24,
      boxShadow: '2px 0 10px rgba(0,0,0,0.02)',
      zIndex: 110,
      height: '100vh',
      position: 'sticky',
      top: 0
    }}>
      {/* Logo imitating the user avatar */}
      <div 
        onClick={() => setActiveTab('home')}
        style={{
        width: 64, height: 64, borderRadius: '50%', background: 'var(--bg-card)', 
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        marginBottom: 40,
        boxShadow: '0 6px 16px rgba(0,0,0,0.2)',
        cursor: 'pointer'
      }}>
        <ShieldAlert size={32} color="var(--text-main)" strokeWidth={2} />
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', flexDirection: 'column', width: '100%', position: 'relative' }}>
        {tabs.map(tab => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          
          return (
            <div 
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`sidebar-item ${isActive ? 'active' : ''}`}
              style={{
                padding: '24px 0',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: 8,
                cursor: 'pointer',
                position: 'relative',
                color: isActive ? 'var(--accent-tan)' : 'var(--sidebar-text)'
              }}
            >
              <span style={{ 
                fontFamily: 'var(--font-rounded)', 
                fontSize: 14, 
                fontWeight: 800, 
                textAlign: 'center', 
                padding: '0 8px', 
                lineHeight: 1.3,
                letterSpacing: '0.02em'
              }}>
                {tab.shortLabel || tab.label}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
