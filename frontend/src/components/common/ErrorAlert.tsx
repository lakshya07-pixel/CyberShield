import React from 'react';

interface ErrorAlertProps {
  title?: string;
  message: string;
  contractNotice?: string;
  onDismiss?: () => void;
}

export const ErrorAlert: React.FC<ErrorAlertProps> = ({
  title = 'Integration Notice',
  message,
  contractNotice,
  onDismiss,
}) => {
  return (
    <div className="error-alert-box" role="alert">
      <div className="error-alert-header">

        <h4 className="error-alert-title">{title}</h4>
        {onDismiss && (
          <button
            type="button"
            className="error-alert-dismiss"
            onClick={onDismiss}
            aria-label="Dismiss"
          >
            &times;
          </button>
        )}
      </div>
      <p className="error-alert-body">{message}</p>
      {contractNotice && (
        <div className="error-contract-notice">
          <strong>Backend Contract Required:</strong> {contractNotice}
        </div>
      )}
    </div>
  );
};
