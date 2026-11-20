import React from 'react';
import { ModeSwitcher } from './ModeSwitcher';

export type NavTab =
  | 'dashboard'
  | 'network'
  | 'url'
  | 'sms'
  | 'assistant'
  | 'status'
  | 'live'
  | 'correlation'
  | 'telemetry'
  | 'storyline';

export type GlobalOperatingMode = 'DEMO_MODE' | 'PCAP_REPLAY' | 'LIVE_CAPTURE';

interface NavbarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  operatingMode?: GlobalOperatingMode;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  onSelectTab,
  operatingMode = 'DEMO_MODE',
}) => {
  return (
    <header className="app-header">
      <div className="header-container">
        <div className="brand-section">
          <div className="brand-icon">🛡️</div>

          <div className="brand-text">
            <span className="brand-title">Cyber Shield</span>
            <span className="brand-subtitle">
              Security Operations Center
            </span>
          </div>
        </div>

        <nav className="nav-tabs" aria-label="Main Navigation">
          <button
            type="button"
            className={`nav-tab-btn ${
              activeTab === 'dashboard' ? 'active' : ''
            }`}
            onClick={() => onSelectTab('dashboard')}
          >
            Dashboard
          </button>

          <button
            type="button"
            className={`nav-tab-btn ${
              activeTab === 'network' ? 'active' : ''
            }`}
            onClick={() => onSelectTab('network')}
          >
            Network IDS
          </button>

          <button
            type="button"
            className={`nav-tab-btn ${
              activeTab === 'url' ? 'active' : ''
            }`}
            onClick={() => onSelectTab('url')}
          >
            URL Phishing
          </button>

          <button
            type="button"
            className={`nav-tab-btn ${
              activeTab === 'sms' ? 'active' : ''
            }`}
            onClick={() => onSelectTab('sms')}
          >
            SMS Scam
          </button>

          <button
            type="button"
            className={`nav-tab-btn ${
              activeTab === 'assistant' ? 'active' : ''
            }`}
            onClick={() => onSelectTab('assistant')}
          >
            AI Assistant
          </button>

          <button
            type="button"
            className={`nav-tab-btn ${
              activeTab === 'status' ? 'active' : ''
            }`}
            onClick={() => onSelectTab('status')}
          >
            Integration Contracts
          </button>

          <button
            type="button"
            className={`nav-tab-btn ${
              activeTab === 'live' ? 'active' : ''
            }`}
            onClick={() => onSelectTab('live')}
          >
            Live Monitoring
          </button>

          <button
            type="button"
            className={`nav-tab-btn ${
              activeTab === 'correlation' ? 'active' : ''
            }`}
            onClick={() => onSelectTab('correlation')}
          >
            Attack Correlation
          </button>

          <button
            type="button"
            className={`nav-tab-btn ${
              activeTab === 'telemetry' ? 'active' : ''
            }`}
            onClick={() => onSelectTab('telemetry')}
          >
            Network Topology Map
          </button>
          <button
          type="button"
          className={`nav-tab-btn ${
          activeTab === 'storyline' ? 'active' : ''
          }`}
          onClick={() => onSelectTab('storyline')}
          >
          Cross-Channel Storyline
          </button>
        </nav>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div className="header-status-badge">
            <span
              className="status-indicator-dot"
              style={{
                backgroundColor:
                  operatingMode === 'LIVE_CAPTURE'
                    ? 'var(--accent-green)'
                    : operatingMode === 'PCAP_REPLAY'
                    ? 'var(--accent-blue)'
                    : 'var(--accent-amber)',
              }}
            />
            <span className="status-text">
              {operatingMode === 'LIVE_CAPTURE'
                ? 'LIVE CAPTURE'
                : operatingMode === 'PCAP_REPLAY'
                ? 'PCAP REPLAY'
                : 'DEMO MODE'}
            </span>
          </div>

          <ModeSwitcher />
        </div>
      </div>
    </header>
  );
};
