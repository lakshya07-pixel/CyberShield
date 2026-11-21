import React, { createContext, useContext, useState, useEffect } from 'react';

export type ApplicationMode = 'expert' | 'user';

interface ModeContextType {
  mode: ApplicationMode;
  setMode: (mode: ApplicationMode) => void;
  toggleMode: () => void;
}

const STORAGE_KEY = 'cybershield_app_mode';

const ModeContext = createContext<ModeContextType | undefined>(undefined);

export const ModeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // Default to 'expert' mode for existing installations, persist in localStorage
  const [mode, setModeState] = useState<ApplicationMode>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved === 'expert' || saved === 'user') {
        return saved;
      }
    } catch {
      // Ignore localStorage access failures in restricted environments
    }
    return 'expert';
  });

  const setMode = (newMode: ApplicationMode) => {
    setModeState(newMode);
    try {
      localStorage.setItem(STORAGE_KEY, newMode);
    } catch {
      // Safe fallback
    }
  };

  const toggleMode = () => {
    setMode(mode === 'expert' ? 'user' : 'expert');
  };

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, mode);
    } catch {
      // Safe fallback
    }
  }, [mode]);

  return (
    <ModeContext.Provider value={{ mode, setMode, toggleMode }}>
      {children}
    </ModeContext.Provider>
  );
};

export const useApplicationMode = (): ModeContextType => {
  const context = useContext(ModeContext);
  if (!context) {
    throw new Error('useApplicationMode must be used within a ModeProvider');
  }
  return context;
};
