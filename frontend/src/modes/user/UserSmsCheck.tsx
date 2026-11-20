import React, { useState } from 'react';
import { apiClient } from '../../services/apiClient';

export const UserSmsCheck: React.FC = () => {
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = message.trim();
    if (!trimmed) {
      setError('Please enter or paste message text to analyze.');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await apiClient.scanSms(trimmed);
      if (res && res.success && res.data) {
        setResult(res.data);
      } else {
        const errorMsg = res?.error || 'Message analysis returned no result. Please try again.';
        setError(errorMsg);
      }
    } catch (err: any) {
      setError(err?.message || 'Could not connect to security scanning service. Ensure backend is running.');
    } finally {
      setLoading(false);
    }
  };

  const isScam =
    result &&
    (result.threat_type === 'scam' ||
      result.threat_type === 'phishing' ||
      result.threat_type === 'smishing' ||
      result.severity === 'CRITICAL' ||
      result.severity === 'HIGH' ||
      result.prediction === 'scam' ||
      result.prediction === 'spam');

  const isSuspicious =
    result &&
    !isScam &&
    (result.severity === 'MEDIUM' ||
      result.threat_type === 'suspicious' ||
      (result.confidence !== undefined && result.confidence > 0.5 && result.confidence < 0.75));

  return (
    <div style={{ maxWidth: '850px', margin: '0 auto', padding: '1rem 0' }}>
      <div style={{ marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '1.8rem', fontWeight: 700, color: '#f8fafc', margin: '0 0 0.5rem' }}>
          Check a Message (SMS / Chat Scam Detector)
        </h2>
        <p style={{ color: '#94a3b8', fontSize: '1.05rem', margin: 0 }}>
          Received an unexpected text message, WhatsApp alert, or urgent delivery notification? Paste it below to find out if it is an attempt to defraud you.
        </p>
      </div>

      {/* Input Card */}
      <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '16px', padding: '1.75rem', marginBottom: '2rem' }}>
        <form onSubmit={handleScan}>
          <label htmlFor="user-sms-input" style={{ display: 'block', fontSize: '0.95rem', fontWeight: 600, color: '#f8fafc', marginBottom: '0.5rem' }}>
            Paste the Text Message Content:
          </label>
          <textarea
            id="user-sms-input"
            className="form-control"
            rows={4}
            placeholder="e.g. URGENT: Your bank account is locked due to expired KYC. Click http://bit.ly/kyc-fix to unlock..."
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            disabled={loading}
            style={{ width: '100%', padding: '0.75rem 1rem', fontSize: '0.95rem', background: '#141f36', color: '#ffffff', borderColor: '#334155', borderRadius: '8px', marginBottom: '1rem', resize: 'vertical' }}
          />
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
              <span style={{ fontSize: '0.82rem', color: '#94a3b8' }}>Try an example:</span>
              <button
                type="button"
                className="btn btn-sm btn-outline-secondary"
                onClick={() => setMessage('Hey, dinner is scheduled for 7 PM at our place!')}
                style={{ fontSize: '0.78rem' }}
              >
                Safe: Dinner text
              </button>
              <button
                type="button"
                className="btn btn-sm btn-outline-secondary"
                onClick={() => setMessage('URGENT: Your State Bank account is suspended due to pending KYC. Click http://bit.ly/kyc-fix now to avoid immediate deactivation.')}
                style={{ fontSize: '0.78rem' }}
              >
                Scam: KYC urgency trap
              </button>
              <button
                type="button"
                className="btn btn-sm btn-outline-secondary"
                onClick={() => setMessage('Congratulations! You won a $1,000 gift voucher. Claim immediately at http://free-gift-reward.xyz before expiry!')}
                style={{ fontSize: '0.78rem' }}
              >
                Scam: Lottery lure
              </button>
            </div>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={loading || !message.trim()}
              style={{ padding: '0.75rem 1.75rem', fontWeight: 600, minWidth: '160px' }}
            >
              {loading ? 'Checking...' : 'Check Message'}
            </button>
          </div>
        </form>
      </div>

      {error && (
        <div style={{ padding: '1rem 1.25rem', background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444', borderRadius: '8px', color: '#fca5a5', marginBottom: '2rem' }}>
          <strong>Notice: </strong> {error}
        </div>
      )}

      {/* Result Card */}
      {result && (
        <div
          style={{
            background: isScam ? '#1a1016' : isSuspicious ? '#1c1912' : '#0d1f18',
            border: `2px solid ${isScam ? '#ef4444' : isSuspicious ? '#f59e0b' : '#10b981'}`,
            borderRadius: '16px',
            padding: '2rem',
            marginBottom: '2rem',
            boxShadow: '0 8px 24px rgba(0,0,0,0.3)',
          }}
        >
          {/* Header Verdict */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
            <span
              style={{
                padding: '4px 12px',
                borderRadius: '20px',
                fontWeight: 700,
                fontSize: '0.85rem',
                textTransform: 'uppercase',
                background: isScam ? '#ef4444' : isSuspicious ? '#f59e0b' : '#10b981',
                color: isSuspicious ? '#0f172a' : '#ffffff',
              }}
            >
              {isScam ? 'Scam / Dangerous' : isSuspicious ? 'Suspicious Content' : 'Safe Message'}
            </span>
            <span style={{ color: '#94a3b8', fontSize: '0.88rem' }}>
              Risk Level: <strong style={{ color: isScam ? '#fca5a5' : isSuspicious ? '#fcd34d' : '#86efac' }}>
                {result.severity || (isScam ? 'HIGH' : isSuspicious ? 'MEDIUM' : 'LOW')}
              </strong>
            </span>
            {result.confidence !== undefined && (
              <span style={{ color: '#94a3b8', fontSize: '0.88rem' }}>
                • Confidence: <strong>{Math.round(result.confidence * 100)}%</strong>
              </span>
            )}
          </div>

          <h3 style={{ fontSize: '1.6rem', color: '#f8fafc', margin: '0 0 1rem' }}>
            {isScam
              ? 'This message is highly likely a fraudulent scam or smishing attempt.'
              : isSuspicious
              ? 'This message contains suspicious wording or unverified claims.'
              : 'This message appears normal and safe.'}
          </h3>

          {/* Structured Risk Explanation Sections */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', marginTop: '1.5rem' }}>
            {/* Section 1: What happened? */}
            <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '10px', padding: '1.25rem' }}>
              <h4 style={{ color: '#f8fafc', fontSize: '1.05rem', margin: '0 0 0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ color: isScam ? '#ef4444' : isSuspicious ? '#f59e0b' : '#10b981' }}>1.</span> What happened?
              </h4>
              <p style={{ color: '#cbd5e1', fontSize: '0.95rem', lineHeight: 1.6, margin: 0 }}>
                {isScam
                  ? 'Our machine learning language analysis scanned the message text and identified high-risk social engineering markers. The text mimics high-urgency notifications (such as impending bank account suspension, KYC expiration, or fake prize awards) to trigger panic.'
                  : isSuspicious
                  ? 'The message text contains ambiguous phrases, shortened links, or requests that are atypical for regular personal communication, though not conclusively known malware.'
                  : 'Our detector analyzed the message content and detected genuine conversational language. There were no coercive panic cues, fraudulent prize promises, or deceptive web link redirects detected.'}
              </p>
            </div>

            {/* Section 2: Why is it risky? */}
            <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '10px', padding: '1.25rem' }}>
              <h4 style={{ color: '#f8fafc', fontSize: '1.05rem', margin: '0 0 0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ color: isScam ? '#ef4444' : isSuspicious ? '#f59e0b' : '#10b981' }}>2.</span> Why is it risky?
              </h4>
              <div style={{ color: '#cbd5e1', fontSize: '0.95rem', lineHeight: 1.6 }}>
                {isScam ? (
                  <ul style={{ margin: 0, paddingLeft: '1.25rem' }}>
                    <li><strong>Credential &amp; OTP Theft:</strong> Attackers often use these messages to trick you into entering one-time passwords (OTP) or banking credentials on counterfeit forms.</li>
                    <li><strong>Financial Loss:</strong> Following links or calling numbers provided in unverified texts can lead directly to unauthorized fund transfers via UPI or debit fraud.</li>
                    <li><strong>Malware Downloads:</strong> Tapping shortened links can trigger malicious APK or mobile malware downloads that spy on SMS verifications.</li>
                  </ul>
                ) : isSuspicious ? (
                  <p style={{ margin: 0 }}>
                    Messages with unverified claims or unexpected attachments can lead to unauthorized information gathering or misleading subscription traps.
                  </p>
                ) : (
                  <p style={{ margin: 0 }}>
                    This message does not present obvious fraud or smishing risk indicators.
                  </p>
                )}
              </div>
            </div>

            {/* Section 3: What should I do now? */}
            <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '10px', padding: '1.25rem' }}>
              <h4 style={{ color: '#f8fafc', fontSize: '1.05rem', margin: '0 0 0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ color: isScam ? '#ef4444' : isSuspicious ? '#f59e0b' : '#10b981' }}>3.</span> What should I do now?
              </h4>
              <ul style={{ margin: 0, paddingLeft: '1.25rem', color: isScam ? '#fca5a5' : isSuspicious ? '#fcd34d' : '#86efac', lineHeight: 1.7, fontSize: '0.95rem' }}>
                {isScam ? (
                  <>
                    <li><strong>Do not click any web links</strong> enclosed in the message.</li>
                    <li><strong>Never disclose One-Time Passwords (OTPs), PINs, or card details</strong>, even if the sender claims to be bank security staff.</li>
                    <li><strong>Block the sender number</strong> immediately in your phone settings to stop further harassment.</li>
                    <li><strong>Verify independently:</strong> If the message claims your bank account is locked, check via your official bank mobile app or customer care phone number printed on the back of your card.</li>
                  </>
                ) : isSuspicious ? (
                  <>
                    <li>Avoid clicking any link until you independently confirm the sender's identity.</li>
                    <li>Do not reply with sensitive details or money.</li>
                  </>
                ) : (
                  <>
                    <li>You can safely read and respond to this message.</li>
                    <li>Remember standard practice: never transmit banking passwords or debit card PINs over plain SMS or unsecured channels.</li>
                  </>
                )}
              </ul>
            </div>

            {/* Section 4: Prevention suggestions */}
            <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '10px', padding: '1.25rem' }}>
              <h4 style={{ color: '#f8fafc', fontSize: '1.05rem', margin: '0 0 0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ color: isScam ? '#ef4444' : isSuspicious ? '#f59e0b' : '#10b981' }}>4.</span> Prevention Suggestions &amp; Best Practices
              </h4>
              <ul style={{ margin: 0, paddingLeft: '1.25rem', color: '#cbd5e1', lineHeight: 1.7, fontSize: '0.95rem' }}>
                <li><strong>Official Banking Rules:</strong> Genuine financial institutions will never threaten account termination within hours over SMS or request KYC completion via third-party bit.ly links.</li>
                <li><strong>Spam Reporting:</strong> Use your mobile carrier's spam reporting tool (e.g. forward spam SMS to 1909 in India) or report cyber fraud at <a href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer" style={{ color: '#38bdf8' }}>cybercrime.gov.in</a>.</li>
                <li><strong>Enable Caller ID &amp; Spam Protection:</strong> Turn on spam filtering in your Android Messages or iOS settings to automatically quarantine suspicious sender IDs.</li>
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
