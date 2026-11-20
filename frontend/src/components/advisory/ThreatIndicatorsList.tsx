import React from 'react';

interface ThreatIndicatorsListProps {
  indicators: string[];
  formattedExplanations?: string[];
}

export const ThreatIndicatorsList: React.FC<ThreatIndicatorsListProps> = ({
  indicators,
  formattedExplanations,
}) => {
  if (!indicators || indicators.length === 0) {
    return <p className="text-muted">No specific indicators flagged.</p>;
  }

  const items = formattedExplanations && formattedExplanations.length === indicators.length
    ? formattedExplanations
    : indicators.map((ind) => `Suspicious indicator: ${ind}`);

  return (
    <div className="indicators-container">
      <h4 className="section-subtitle">Flagged Indicators ({indicators.length})</h4>
      <ul className="indicators-list">
        {items.map((item, idx) => (
          <li key={idx} className="indicator-item">
            <span className="indicator-bullet">▸</span>
            <span className="indicator-text">{item}</span>
          </li>
        ))}
      </ul>
    </div>
  );
};

