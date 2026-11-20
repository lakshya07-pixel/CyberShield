import React from 'react';

interface LoadingSpinnerProps {
  message?: string;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  message = 'Processing request...',
}) => {
  return (
    <div className="loading-state-container">
      <div className="spinner-ring" />
      <p className="loading-message">{message}</p>
    </div>
  );
};

