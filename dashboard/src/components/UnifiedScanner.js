import React, { useState } from 'react';
import { Search, Code, GitBranch, Globe, AlertTriangle, CheckCircle, Loader, ChevronDown } from 'lucide-react';
import { scanCode, scanRepo, dastScan, getScanJob } from '../services/api';
import FindingCard from './FindingCard';

const detectInputType = (input) => {
  const trimmed = input.trim();
  if (/^https?:\/\/github\.com\//i.test(trimmed) || /^git@github\.com:/i.test(trimmed)) {
    return 'repo';
  }
  if (/^https?:\/\//i.test(trimmed)) {
    return 'dast';
  }
  if (trimmed.length > 0) {
    return 'code';
  }
  return null;
};

const TYPE_CONFIG = {
  code: { icon: Code, label: 'Code', color: '#3b82f6', hint: 'Paste JavaScript, Python, Java, etc.' },
  repo: { icon: GitBranch, label: 'Repository', color: '#f59e0b', hint: 'GitHub repository URL' },
  dast: { icon: Globe, label: 'Website', color: '#ef4444', hint: 'Live website URL to scan' },
};

const UnifiedScanner = ({ onNewEvent }) => {
  const [input, setInput] = useState('');
  const [detectedType, setDetectedType] = useState(null);
  const [dastMode, setDastMode] = useState('passive');
  const [verboseEvidence, setVerboseEvidence] = useState(false);
  const [result, setResult] = useState(null);
  const [repoResult, setRepoResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleInputChange = (e) => {
    const val = e.target.value;
    setInput(val);
    setDetectedType(detectInputType(val));
    if (result || repoResult || error) {
      setResult(null);
      setRepoResult(null);
      setError(null);
    }
  };

  const handleScan = async () => {
    const type = detectInputType(input);
    if (!type) return;

    setLoading(true);
    setError(null);
    setResult(null);
    setRepoResult(null);

    try {
      if (type === 'code') {
        const data = await scanCode(input);
        setResult(data);
      } else if (type === 'repo') {
        const data = await scanRepo(input);
        setRepoResult(data);
        setTimeout(pollJob, 3000);
      } else if (type === 'dast') {
        const data = await dastScan(input, dastMode, verboseEvidence);
        setResult(data);
      }
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Scan failed');
    } finally {
      setLoading(false);
    }
  };

  const pollJob = async () => {
    if (!repoResult?.job_id) return;
    try {
      const data = await getScanJob(repoResult.job_id);
      if (data.job?.status === 'scanning' || data.job?.status === 'cloning') {
        setTimeout(pollJob, 3000);
      }
      setRepoResult(prev => ({ ...prev, _jobData: data }));
    } catch (err) {
      console.error('Poll failed:', err);
    }
  };

  const handleKeyDown = (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      handleScan();
    }
  };

  const config = detectedType ? TYPE_CONFIG[detectedType] : null;
  const Icon = config?.icon;

  return (
    <div className="unified-scanner">
      <div className="scanner-input-area">
        <div className="input-row">
          <textarea
            value={input}
            onChange={handleInputChange}
            onKeyDown={handleKeyDown}
            placeholder={detectedType
              ? TYPE_CONFIG[detectedType].hint
              : 'Paste code, GitHub repo URL, or website URL...'
            }
            rows={detectedType === 'code' ? 10 : 2}
            className={`scanner-textarea ${detectedType ? 'has-type' : ''}`}
          />
          {detectedType && (
            <div className="type-indicator" style={{ borderColor: config.color }}>
              <Icon className="icon-xs" style={{ color: config.color }} />
              <span style={{ color: config.color }}>{config.label}</span>
            </div>
          )}
        </div>

        <div className="scanner-controls">
          <div className="scanner-controls-left">
            {detectedType && (
              <span className="detected-label" style={{ color: config.color }}>
                <Icon className="icon-xs" /> {config.label} detected
              </span>
            )}
            {!detectedType && input.length === 0 && (
              <span className="scanner-hint">
                <Search className="icon-xs" /> Auto-detects input type
              </span>
            )}
          </div>

          <div className="scanner-controls-right">
            {detectedType === 'dast' && (
              <>
                <select value={dastMode} onChange={(e) => setDastMode(e.target.value)} className="mode-select-sm">
                  <option value="passive">Passive</option>
                  <option value="active">Active</option>
                </select>
                <label className="verbose-toggle-sm">
                  <input type="checkbox" checked={verboseEvidence} onChange={(e) => setVerboseEvidence(e.target.checked)} />
                  Verbose
                </label>
              </>
            )}
            <button
              onClick={handleScan}
              disabled={loading || !detectedType}
              className="scan-btn"
            >
              {loading ? (
                <><Loader className="icon-xs spin" /> Scanning...</>
              ) : (
                <><Search className="icon-xs" /> Scan</>
              )}
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div className="scan-error">
          <AlertTriangle className="icon-sm" /> {error}
        </div>
      )}

      {result && detectedType === 'code' && (
        <div className="scan-results">
          {result.prediction === 'not_vulnerable' ? (
            <div className="scan-clean">
              <CheckCircle className="icon" />
              <span>No vulnerabilities detected</span>
            </div>
          ) : (
            <>
              <FindingCard event={{
                event_type: 'code',
                prediction: result.prediction,
                confidence: result.confidence,
                severity: result.severity || result.explanation?.severity || 'info',
                status: result.status,
                explanation: result.explanation,
                suggested_fix: result.suggested_fix
              }} showType={false} />

              {result.top_predictions && result.top_predictions.length > 1 && (
                <div className="top-predictions">
                  <h4>Other Possibilities</h4>
                  <ul>
                    {result.top_predictions.slice(1).map((pred, idx) => (
                      <li key={idx}>
                        <span className="pred-class">{pred.class.replace(/_/g, ' ')}</span>
                        <span className="pred-cwe">{pred.cwe}</span>
                        <span className="pred-confidence">{(pred.confidence * 100).toFixed(0)}%</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {result && detectedType === 'dast' && (
        <div className="scan-results">
          <div className="result-header">
            <span className="result-target">{result.target_url}</span>
            <div className="result-meta">
              <span className={`mode-badge ${result.mode}`}>{result.mode}</span>
              <span className="result-count">{result.finding_count} findings</span>
            </div>
          </div>
          {result.findings.length === 0 ? (
            <div className="scan-clean">
              <CheckCircle className="icon" />
              <span>No issues found</span>
            </div>
          ) : (
            <div className="events-list">
              {result.findings.map((f, i) => (
                <FindingCard key={f.event_id || i} event={{
                  ...f,
                  event_type: 'dast',
                  mode: result.mode,
                  timestamp: new Date().toISOString()
                }} showType={true} />
              ))}
            </div>
          )}
        </div>
      )}

      {repoResult && (
        <div className="scan-results">
          <div className="result-header">
            <span className="result-target">{repoResult.repo_url}</span>
            <div className="result-meta">
              <span className={`status-badge status-${repoResult.status}`}>{repoResult.status}</span>
              {repoResult.job_id && <span className="result-count">Job {repoResult.job_id.slice(-6)}</span>}
            </div>
          </div>

          {repoResult._jobData && (
            <>
              {repoResult._jobData.job.status === 'completed' && repoResult._jobData.job.finding_count === 0 && (
                <div className="scan-clean">
                  <CheckCircle className="icon" />
                  <span>No vulnerabilities found in {repoResult._jobData.job.file_count} files</span>
                </div>
              )}

              {repoResult._jobData.job.status === 'failed' && repoResult._jobData.job.error && (
                <div className="scan-error">
                  <AlertTriangle className="icon-sm" /> {repoResult._jobData.job.error}
                </div>
              )}

              {repoResult._jobData.findings && Object.keys(repoResult._jobData.findings).length > 0 && (
                <div className="events-list">
                  {Object.entries(repoResult._jobData.findings).map(([filePath, findings]) => (
                    <div key={filePath} className="file-group">
                      <h4 className="file-path">{filePath}</h4>
                      {findings.map((f, i) => (
                        <FindingCard key={f._id || i} event={f} showType={false} />
                      ))}
                    </div>
                  ))}
                </div>
              )}

              {(repoResult._jobData.job.status === 'scanning' || repoResult._jobData.job.status === 'cloning') && (
                <div className="scan-loading">
                  <Loader className="icon-sm spin" /> Scanning {repoResult._jobData.job.file_count} files...
                </div>
              )}
            </>
          )}

          {!repoResult._jobData && (
            <div className="scan-loading">
              <Loader className="icon-sm spin" /> Cloning repository...
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default UnifiedScanner;
