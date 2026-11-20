import React from 'react';
import { ThreatType } from '../../types/threat';
import { getRecommendation } from '../../services/threatRules';

interface RecommendationCardProps {
  threatType: ThreatType;
  customRecommendation?: string;
}

export const RecommendationCard: React.FC<RecommendationCardProps> = ({
  threatType,
  customRecommendation,
}) => {
  const text = customRecommendation || getRecommendation(threatType);

  return (
    <div className="recommendation-card">
      <div className="recommendation-header">
        <h4 className="recommendation-title">Recommended Action</h4>
      </div>
      <p className="recommendation-body">{text}</p>
      <div className="recommendation-footer">
        <span className="source-tag">SOC Recommendation Engine</span>
      </div>
    </div>
  );
};

