import React from 'react';
import { SeverityLevel } from '../../types/threat';

interface SeverityBadgeProps {
  severity: SeverityLevel;
  size?: 'sm' | 'md' | 'lg';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = 'md',
}) => {
  const norm = severity.toLowerCase() as SeverityLevel;

  return (
    <span className={`severity-badge severity-${norm} badge-${size}`}>
      <span className="severity-dot" />
      {norm.toUpperCase()}
    </span>
  );
};

