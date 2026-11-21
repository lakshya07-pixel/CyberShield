import React, { useState } from 'react';
import { ModeProvider, useApplicationMode } from './context/ModeContext';
import { Navbar, NavTab, GlobalOperatingMode } from './components/common/Navbar';
import { DashboardOverview } from './pages/DashboardOverview';
import { NetworkIdsPage } from './pages/NetworkIdsPage';
import { UrlPhishingPage } from './pages/UrlPhishingPage';
import { SmsScamPage } from './pages/SmsScamPage';
import { SecurityAssistantPage } from './pages/SecurityAssistantPage';
import { IntegrationStatusPage } from './pages/IntegrationStatusPage';
import { LiveMonitoringPage } from './pages/LiveMonitoringPage';
import { CorrelationPage } from './pages/CorrelationPage';
import { SecurityTelemetryMapPage } from './pages/SecurityTelemetryMapPage';
import { AttackStorylinePage } from './pages/AttackStorylinePage';

// User Mode Components
import { UserNavbar, UserNavTab } from './modes/user/UserNavbar';
import { UserHomeDashboard } from './modes/user/UserHomeDashboard';
import { UserUrlCheck } from './modes/user/UserUrlCheck';
import { UserSmsCheck } from './modes/user/UserSmsCheck';
import { UserNetworkSafety } from './modes/user/UserNetworkSafety';
import { UserSecurityHistory } from './modes/user/UserSecurityHistory';
import { UserSecurityAssistant } from './modes/user/UserSecurityAssistant';

const MainApplication: React.FC = () => {
  const { mode } = useApplicationMode();

  // Expert Mode State
  const [expertTab, setExpertTab] = useState<NavTab>('dashboard');
  const [operatingMode, setOperatingMode] = useState<GlobalOperatingMode>('DEMO_MODE');

  // User Mode State
  const [userTab, setUserTab] = useState<UserNavTab>('home');

  return (
    <div className={`app-layout mode-${mode}`}>
      {mode === 'expert' ? (
        <>
          {/* EXPERT MODE: 10 Advanced SOC Modules Fully Preserved */}
          <Navbar
            activeTab={expertTab}
            onSelectTab={setExpertTab}
            operatingMode={operatingMode}
          />

          <main className="main-content">
            {expertTab === 'dashboard' && (
              <DashboardOverview
                currentMode={operatingMode}
                onModeChange={setOperatingMode}
              />
            )}
            {expertTab === 'network' && <NetworkIdsPage />}
            {expertTab === 'url' && <UrlPhishingPage />}
            {expertTab === 'sms' && <SmsScamPage />}
            {expertTab === 'assistant' && <SecurityAssistantPage />}
            {expertTab === 'status' && <IntegrationStatusPage />}
            {expertTab === 'live' && <LiveMonitoringPage />}
            {expertTab === 'correlation' && <CorrelationPage />}
            {expertTab === 'telemetry' && <SecurityTelemetryMapPage />}
            {expertTab === 'storyline' && <AttackStorylinePage />}
          </main>

          <footer className="app-footer">
            <div className="footer-container">
              <div className="footer-left">
                <span>🛡️ • Security Operations Center</span>
                <span className="footer-sep">|</span>
                <span>Autonomous Threat Defense Platform</span>
              </div>
              <div className="footer-right">
                <span className="status-badge-verified" style={{ fontSize: '0.8rem', padding: '0.2rem 0.6rem' }}>
                  EXPERT MODE ACTIVE
                </span>
                <span className="footer-sep">|</span>
                <span>Live Inference &amp; Multi-Channel Telemetry</span>
              </div>
            </div>
          </footer>
        </>
      ) : (
        <>
          {/* USER MODE: Friendly, Jargon-Free Cybersecurity Application */}
          <UserNavbar
            activeTab={userTab}
            onSelectTab={setUserTab}
          />

          <main className="main-content" style={{ padding: '2rem 1.5rem', minHeight: 'calc(100vh - 130px)' }}>
            {userTab === 'home' && (
              <UserHomeDashboard
                onNavigate={(tab) => setUserTab(tab)}
              />
            )}
            {userTab === 'url' && <UserUrlCheck />}
            {userTab === 'sms' && <UserSmsCheck />}
            {userTab === 'network' && <UserNetworkSafety />}
            {userTab === 'history' && <UserSecurityHistory />}
            {userTab === 'assistant' && <UserSecurityAssistant />}
          </main>

          <footer className="app-footer" style={{ borderTop: '1px solid #1e293b', background: '#0b1329' }}>
            <div className="footer-container">
              <div className="footer-left">
                <span>🛡️ Cyber Shield • Personal Security Protection</span>
                <span className="footer-sep">|</span>
                <span style={{ color: '#10b981' }}>Simple Everyday Safety</span>
              </div>
              <div className="footer-right">
                <span className="status-badge-verified" style={{ fontSize: '0.8rem', padding: '0.2rem 0.6rem', backgroundColor: '#10b981', color: '#ffffff' }}>
                  USER MODE ACTIVE
                </span>
                <span className="footer-sep">|</span>
                <span>On-Device Threat Detection</span>
              </div>
            </div>
          </footer>
        </>
      )}
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <ModeProvider>
      <MainApplication />
    </ModeProvider>
  );
};

export default App;
