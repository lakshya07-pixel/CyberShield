import React from 'react';

interface ConfidenceMeterProps {
  confidence: number; // 0.0 to 1.0
  showBar?: boolean;
}

export const ConfidenceMeter: React.FC<ConfidenceMeterProps> = ({
  confidence,
  showBar = true,
}) => {
  const percentage = Math.round(confidence * 100);
  const rawValue = confidence.toFixed(2);

  // Determine meter color based on thresholds in severity.py
  let meterClass = 'meter-low';
  if (confidence >= 0.90) {
    meterClass = 'meter-critical';
  } else if (confidence >= 0.75) {
    meterClass = 'meter-high';
  } else if (confidence >= 0.50) {
    meterClass = 'meter-medium';
  }

  return (
    <div className="confidence-meter-container">
      <div className="confidence-labels">
        <span className="confidence-percent">{percentage}%</span>
        <span className="confidence-raw">(Raw score: {rawValue})</span>
      </div>
      {showBar && (
        <div className="meter-track">
          <div
            className={`meter-fill ${meterClass}`}
            style={{ width: `${Math.min(100, Math.max(0, percentage))}%` }}
          />
        </div>
      )}
    </div>
  );
};
