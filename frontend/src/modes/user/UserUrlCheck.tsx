import React, { useState } from 'react';
import { apiClient } from '../../services/apiClient';

export const UserUrlCheck: React.FC = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);

  const isValidUrl = (urlStr: string): boolean => {
    try {
      const parsed = new URL(urlStr);
      return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
      return false;
    }
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = url.trim();
    if (!trimmed) {
      setError('Please enter a website link to check.');
      return;
    }

    if (!isValidUrl(trimmed)) {
      setError('Please enter a valid HTTP or HTTPS web address (e.g., https://example.com/login).');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await apiClient.scanUrl(trimmed);
      if (res && res.success && res.data) {
        setResult(res.data);
      } else {
        setError(res?.error || 'Unable to complete website analysis. The detector service may be temporarily unavailable.');
      }
    } catch (err: any) {
      setError(err?.message || 'Could not connect to the security analysis service.');
    } finally {
      setLoading(false);
    }
  };

  const isDangerous = result && (result.threat_type === 'phishing' || result.severity === 'CRITICAL' || result.severity === 'HIGH');
  const isSuspicious = result && !isDangerous && (result.threat_type === 'suspicious' || result.severity === 'MEDIUM');
  const isSafe = result && !isDangerous && !isSuspicious;

  return (
    <div style={{ maxWidth: '850px', margin: '0 auto', padding: '1rem 0' }}>
      <div style={{ marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '1.8rem', fontWeight: 700, color: '#f8fafc', margin: '0 0 0.5rem' }}>
          Check a Website
        </h2>
        <p style={{ color: '#94a3b8', fontSize: '1.05rem', margin: 0 }}>
          Paste any website link before clicking to check if it is safe or a dangerous credential-stealing phishing clone.
        </p>
      </div>

      {/* Input Card */}
      <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '16px', padding: '1.75rem', marginBottom: '2rem' }}>
        <form onSubmit={handleScan}>
          <label htmlFor="user-url-input" style={{ display: 'block', fontSize: '0.95rem', fontWeight: 600, color: '#f8fafc', marginBottom: '0.5rem' }}>
            Website Address (URL):
          </label>
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            <input
              id="user-url-input"
              type="text"
              className="form-control"
              placeholder="e.g. https://sbi-secure-update.com or https://google.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={loading}
              style={{ flex: 1, minWidth: '280px', padding: '0.75rem 1rem', fontSize: '1rem', background: '#141f36', color: '#ffffff', borderColor: '#334155' }}
            />
            <button
              type="submit"
              className="btn btn-primary"
              disabled={loading || !url.trim()}
              style={{ padding: '0.75rem 1.5rem', fontWeight: 600, minWidth: '150px' }}
            >
              {loading ? 'Checking...' : 'Check Website'}
            </button>
          </div>
        </form>

        <div style={{ marginTop: '1rem', display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <span style={{ fontSize: '0.82rem', color: '#94a3b8' }}>Try a test example:</span>
          <button
            type="button"
            className="btn btn-sm btn-outline-secondary"
            onClick={() => setUrl('https://www.google.com')}
            style={{ fontSize: '0.78rem' }}
          >
            Safe: Google
          </button>
          <button
            type="button"
            className="btn btn-sm btn-outline-secondary"
            onClick={() => setUrl('http://sbi-secure-update-login-verify.com')}
            style={{ fontSize: '0.78rem' }}
          >
            Phishing: Fake Banking Login
          </button>
        </div>
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
            background: isDangerous ? '#1a1016' : isSuspicious ? '#1c170d' : '#0d1f18',
            border: `2px solid ${isDangerous ? '#ef4444' : isSuspicious ? '#f59e0b' : '#10b981'}`,
            borderRadius: '16px',
            padding: '2rem',
            marginBottom: '2rem',
            boxShadow: '0 8px 24px rgba(0,0,0,0.3)',
          }}
        >
          {/* 1. Result Status & Risk Level */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '1.25rem', borderBottom: '1px solid rgba(255,255,255,0.1)', pb: '1rem', paddingBottom: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <span
                style={{
                  padding: '4px 14px',
                  borderRadius: '20px',
                  fontWeight: 700,
                  fontSize: '0.85rem',
                  textTransform: 'uppercase',
                  background: isDangerous ? '#ef4444' : isSuspicious ? '#f59e0b' : '#10b981',
                  color: '#ffffff',
                }}
              >
                {isDangerous ? 'Phishing / Dangerous' : isSuspicious ? 'Suspicious' : 'Safe'}
              </span>
              <span style={{ color: '#cbd5e1', fontSize: '0.9rem', fontWeight: 600 }}>
                Risk Level: <strong style={{ color: isDangerous ? '#ef4444' : isSuspicious ? '#f59e0b' : '#10b981' }}>{result.severity || (isDangerous ? 'HIGH' : isSuspicious ? 'MEDIUM' : 'LOW')}</strong>
              </span>
            </div>

            {typeof result.confidence === 'number' && (
              <span style={{ fontSize: '0.82rem', color: '#94a3b8' }}>
                Detector Confidence: <strong>{(result.confidence * 100).toFixed(1)}%</strong>
              </span>
            )}
          </div>

          <div style={{ marginBottom: '1.25rem' }}>
            <span style={{ fontSize: '0.82rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Scanned Address:</span>
            <div style={{ color: '#f8fafc', fontFamily: 'monospace', fontSize: '0.95rem', wordBreak: 'break-all', marginTop: '0.2rem' }}>
              {result.url || url}
            </div>
          </div>

          {/* 2. What happened? */}
          <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '10px', padding: '1.25rem', marginBottom: '1rem' }}>
            <h4 style={{ color: '#f8fafc', fontSize: '1.05rem', margin: '0 0 0.5rem' }}>
              What happened?
            </h4>
            <p style={{ color: '#cbd5e1', fontSize: '0.94rem', lineHeight: 1.6, margin: 0 }}>
              {isDangerous
                ? `Our security model analyzed this link and identified it as a credential phishing website (${result.attack_class || 'phishing'}). It appears designed to imitate a legitimate entity to deceive visitors.`
                : isSuspicious
                ? 'This website shows unusual structural indicators, brand name variations, or unverified hosting patterns that warrant caution.'
                : 'Our URL classification model checked this address against structural indicators, known brand imitations, and malicious domain patterns. No malicious behavior was detected.'}
            </p>
            {result.indicators && result.indicators.length > 0 && (
              <div style={{ marginTop: '0.6rem', fontSize: '0.84rem', color: '#94a3b8' }}>
                <strong>Detected Indicators: </strong>
                <code>{result.indicators.join(' • ')}</code>
              </div>
            )}
          </div>

          {/* 3. Why is it risky? (Shown when dangerous or suspicious) */}
          {(isDangerous || isSuspicious) && (
            <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '10px', padding: '1.25rem', marginBottom: '1rem' }}>
              <h4 style={{ color: '#fca5a5', fontSize: '1.05rem', margin: '0 0 0.5rem' }}>
                Why is it risky?
              </h4>
              <p style={{ color: '#cbd5e1', fontSize: '0.94rem', lineHeight: 1.6, margin: 0 }}>
                {isDangerous
                  ? 'If you open this page or submit data, cybercriminals could steal your login credentials, personal identification, or banking details. Some phishing pages also attempt to silently download malicious software onto your device.'
                  : 'Suspicious domains often redirect visitors to unverified landing pages or attempt aggressive data collection without proper encryption.'}
              </p>
            </div>
          )}

          {/* 4. What should I do now? */}
          <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '10px', padding: '1.25rem', marginBottom: '1rem' }}>
            <h4 style={{ color: isDangerous ? '#fca5a5' : '#86efac', fontSize: '1.05rem', margin: '0 0 0.5rem' }}>
              What should I do now?
            </h4>
            {isDangerous ? (
              <ul style={{ margin: 0, paddingLeft: '1.25rem', color: '#cbd5e1', lineHeight: 1.7, fontSize: '0.92rem' }}>
                <li><strong>Do not enter your password</strong> or account details.</li>
                <li><strong>Never provide payment information</strong>, card numbers, or OTP codes.</li>
                <li>Close the browser tab immediately.</li>
                <li>If you already entered passwords on this page, immediately navigate to the real official website and reset your password.</li>
                <li>If payment information was exposed, contact your bank or card issuer right away.</li>
              </ul>
            ) : isSuspicious ? (
              <ul style={{ margin: 0, paddingLeft: '1.25rem', color: '#cbd5e1', lineHeight: 1.7, fontSize: '0.92rem' }}>
                <li>Do not download files or grant browser permissions.</li>
                <li>Verify the domain name by typing the trusted web address directly into your address bar.</li>
              </ul>
            ) : (
              <ul style={{ margin: 0, paddingLeft: '1.25rem', color: '#cbd5e1', lineHeight: 1.7, fontSize: '0.92rem' }}>
                <li>You can proceed to use this website normally.</li>
                <li>Always confirm that your browser displays a secure lock icon (HTTPS) before entering private account information.</li>
              </ul>
            )}
          </div>

          {/* 5. Recommended solution & 6. Prevention suggestions */}
          <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: '10px', padding: '1.25rem' }}>
            <h4 style={{ color: '#38bdf8', fontSize: '1.05rem', margin: '0 0 0.5rem' }}>
              Prevention suggestions:
            </h4>
            <ul style={{ margin: 0, paddingLeft: '1.25rem', color: '#cbd5e1', lineHeight: 1.7, fontSize: '0.92rem' }}>
              <li><strong>Check the web address carefully:</strong> Look closely at the domain name for misspellings, hyphens, or unusual endings (such as <code>.xyz</code>, <code>-login.com</code>).</li>
              <li><strong>Avoid login links from text messages or emails:</strong> Always type the known web address directly or use official mobile apps.</li>
              <li><strong>Enable two-factor authentication (2FA):</strong> Multi-factor verification protects your account even if credentials are intercepted.</li>
            </ul>
          </div>
        </div>
      )}
    </div>
  );
};
