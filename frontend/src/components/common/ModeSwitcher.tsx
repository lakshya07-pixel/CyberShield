import React from 'react';
import { useApplicationMode } from '../../context/ModeContext';

export const ModeSwitcher: React.FC = () => {
  const { mode, setMode } = useApplicationMode();

  return (
    <div
      className="mode-switcher-container"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        background: '#091122',
        border: '1px solid #1e293b',
        borderRadius: '24px',
        padding: '3px',
        gap: '2px',
        userSelect: 'none',
      }}
      role="radiogroup"
      aria-label="Application Mode Selection"
    >
      <button
        type="button"
        role="radio"
        aria-checked={mode === 'expert'}
        onClick={() => setMode('expert')}
        style={{
          border: 'none',
          outline: 'none',
          cursor: 'pointer',
          padding: '5px 14px',
          borderRadius: '20px',
          fontSize: '0.78rem',
          fontWeight: 600,
          letterSpacing: '0.02em',
          transition: 'all 0.2s ease',
          background: mode === 'expert' ? '#1e293b' : 'transparent',
          color: mode === 'expert' ? '#38bdf8' : '#94a3b8',
          boxShadow: mode === 'expert' ? '0 1px 4px rgba(0,0,0,0.4)' : 'none',
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
        }}
      >
        <span
          style={{
            width: '6px',
            height: '6px',
            borderRadius: '50%',
            backgroundColor: mode === 'expert' ? '#38bdf8' : '#64748b',
          }}
        />
        Expert Mode
      </button>

      <button
        type="button"
        role="radio"
        aria-checked={mode === 'user'}
        onClick={() => setMode('user')}
        style={{
          border: 'none',
          outline: 'none',
          cursor: 'pointer',
          padding: '5px 14px',
          borderRadius: '20px',
          fontSize: '0.78rem',
          fontWeight: 600,
          letterSpacing: '0.02em',
          transition: 'all 0.2s ease',
          background: mode === 'user' ? '#10b981' : 'transparent',
          color: mode === 'user' ? '#ffffff' : '#94a3b8',
          boxShadow: mode === 'user' ? '0 1px 4px rgba(0,0,0,0.4)' : 'none',
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
        }}
      >
        <span
          style={{
            width: '6px',
            height: '6px',
            borderRadius: '50%',
            backgroundColor: mode === 'user' ? '#ffffff' : '#64748b',
          }}
        />
        User Mode
      </button>
    </div>
  );
};
