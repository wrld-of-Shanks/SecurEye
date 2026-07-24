import React, { useState } from 'react';
import { Code, Search, AlertTriangle, CheckCircle } from 'lucide-react';
import { scanCode } from '../services/api';

const CodeScanner = () => {
  const [code, setCode] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleScan = async () => {
    if (!code.trim()) {
      setError('Please enter some code to scan');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const scanResult = await scanCode(code);
      setResult(scanResult);
    } catch (err) {
      setError(err.message || 'Failed to scan code');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical':
        return '#ef4444';
      case 'high':
        return '#f97316';
      case 'medium':
        return '#eab308';
      case 'low':
        return '#3b82f6';
      default:
        return '#6b7280';
    }
  };

  return (
    <div className="code-scanner">
      <h2>
        <Code className="icon" />
        Code Vulnerability Scanner
      </h2>
      
      <div className="scanner-input">
        <textarea
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder="Paste your JavaScript code here..."
          rows={12}
        />
        <button
          onClick={handleScan}
          disabled={loading || !code.trim()}
          className="scan-button"
        >
          {loading ? (
            <>Scanning...</>
          ) : (
            <>
              <Search className="icon" />
              Scan Code
            </>
          )}
        </button>
      </div>

      {error && (
        <div className="error-message">
          <AlertTriangle className="icon" />
          {error}
        </div>
      )}

      {result && (
        <div className="scan-result">
          <div className="result-header">
            <h3>Scan Results</h3>
            <div
              className="severity-badge"
              style={{ backgroundColor: getSeverityColor(result.severity) }}
            >
              {result.severity}
            </div>
          </div>
          
          <div className="result-body">
            <div className="result-field">
              <strong>Prediction:</strong>
              <span className="prediction-value">{result.prediction}</span>
            </div>
            
            <div className="result-field">
              <strong>CWE:</strong>
              <span>{result.explanation?.cwe || 'N/A'}</span>
            </div>
            
            <div className="result-field">
              <strong>Confidence:</strong>
              <span className="confidence-value">
                {(result.confidence * 100).toFixed(1)}%
              </span>
            </div>
            
            <div className="result-field">
              <strong>Status:</strong>
              <span>{result.status}</span>
            </div>
          </div>

          {result.explanation && (
            <div className="explanation-section">
              <h4>Explanation</h4>
              <p>{result.explanation.description}</p>
              
              {result.explanation.remediation?.length > 0 && (
                <div className="remediation">
                  <strong>Remediation:</strong>
                  <ul>
                    {result.explanation.remediation.map((item, idx) => (
                      <li key={idx}>{item}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {result.top_predictions && result.top_predictions.length > 0 && (
            <div className="top-predictions">
              <h4>Top Predictions</h4>
              <ul>
                {result.top_predictions.map((pred, idx) => (
                  <li key={idx}>
                    <span className="pred-class">{pred.class}</span>
                    <span className="pred-cwe">{pred.cwe}</span>
                    <span className="pred-confidence">
                      {(pred.confidence * 100).toFixed(1)}%
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {result.suggested_fix && (
            <div className="fix-section">
              <h4>Suggested Fix</h4>
              <pre className="fix-code">{result.suggested_fix}</pre>
              <p className="fix-disclaimer">
                This is a suggested fix and should be reviewed before applying.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default CodeScanner;
