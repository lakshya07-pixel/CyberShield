import React from 'react';

interface EmptyStateProps {
  title: string;
  description: string;
  icon?: string;
  actionButton?: {
    label: string;
    onClick: () => void;
  };
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title,
  description,
  icon = '',
  actionButton,
}) => {
  return (
    <div className="empty-state-box">
      <div className="empty-state-icon">{icon}</div>
      <h3 className="empty-state-title">{title}</h3>
      <p className="empty-state-description">{description}</p>
      {actionButton && (
        <button
          type="button"
          className="btn btn-secondary mt-3"
          onClick={actionButton.onClick}
        >
          {actionButton.label}
        </button>
      )}
    </div>
  );
};

