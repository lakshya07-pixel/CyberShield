import React from 'react';
import { ModeSwitcher } from '../../components/common/ModeSwitcher';

export type UserNavTab = 'home' | 'url' | 'sms' | 'network' | 'history' | 'assistant';

interface UserNavbarProps {
  activeTab: UserNavTab;
  onSelectTab: (tab: UserNavTab) => void;
}

export const UserNavbar: React.FC<UserNavbarProps> = ({ activeTab, onSelectTab }) => {
  return (
    <header className="app-header" style={{ borderBottom: '1px solid #1e293b', background: '#0b1329' }}>
      <div className="header-container" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.75rem 1.5rem', maxWidth: '1400px', margin: '0 auto' }}>
        <div className="brand-section" style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', cursor: 'pointer' }} onClick={() => onSelectTab('home')}>
          <div className="brand-icon" style={{ fontSize: '1.4rem' }}>🛡️</div>
          <div className="brand-text">
            <span className="brand-title" style={{ fontSize: '1.15rem', fontWeight: 700, color: '#f8fafc', display: 'block' }}>
              Cyber Shield
            </span>
            <span className="brand-subtitle" style={{ fontSize: '0.75rem', color: '#10b981', fontWeight: 600, letterSpacing: '0.04em' }}>
              Personal Security Protection
            </span>
          </div>
        </div>

        <nav className="nav-tabs" aria-label="User Navigation" style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
          <button
            type="button"
            className={`nav-tab-btn ${activeTab === 'home' ? 'active' : ''}`}
            onClick={() => onSelectTab('home')}
            style={{ borderRadius: '8px', padding: '6px 14px', fontSize: '0.85rem' }}
          >
            Home
          </button>
          <button
            type="button"
            className={`nav-tab-btn ${activeTab === 'url' ? 'active' : ''}`}
            onClick={() => onSelectTab('url')}
            style={{ borderRadius: '8px', padding: '6px 14px', fontSize: '0.85rem' }}
          >
            Check Website
          </button>
          <button
            type="button"
            className={`nav-tab-btn ${activeTab === 'sms' ? 'active' : ''}`}
            onClick={() => onSelectTab('sms')}
            style={{ borderRadius: '8px', padding: '6px 14px', fontSize: '0.85rem' }}
          >
            Check Message
          </button>
          <button
            type="button"
            className={`nav-tab-btn ${activeTab === 'network' ? 'active' : ''}`}
            onClick={() => onSelectTab('network')}
            style={{ borderRadius: '8px', padding: '6px 14px', fontSize: '0.85rem' }}
          >
            Network Safety
          </button>
          <button
            type="button"
            className={`nav-tab-btn ${activeTab === 'history' ? 'active' : ''}`}
            onClick={() => onSelectTab('history')}
            style={{ borderRadius: '8px', padding: '6px 14px', fontSize: '0.85rem' }}
          >
            Security History
          </button>
          <button
            type="button"
            className={`nav-tab-btn ${activeTab === 'assistant' ? 'active' : ''}`}
            onClick={() => onSelectTab('assistant')}
            style={{ borderRadius: '8px', padding: '6px 14px', fontSize: '0.85rem' }}
          >
            Security Assistant
          </button>
        </nav>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <ModeSwitcher />
        </div>
      </div>
    </header>
  );
};
