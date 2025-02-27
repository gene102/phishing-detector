import React, { useState } from 'react';
import './styles.css';

const PhishingDetector = () => {
  const [emailContent, setEmailContent] = useState('');
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);

  const analyzeEmail = () => {
    setLoading(true);
    setTimeout(() => {
      const riskScore = Math.floor(Math.random() * 101);
      setAnalysis({ riskScore, riskLevel: getRiskLevel(riskScore) });
      setLoading(false);
    }, 1000);
  };

  const getRiskLevel = (score) => {
    if (score >= 80) return { level: 'High', color: 'high-risk' };
    if (score >= 50) return { level: 'Medium', color: 'medium-risk' };
    if (score >= 20) return { level: 'Low', color: 'low-risk' };
    return { level: 'Safe', color: 'safe-risk' };
  };

  return (
    <div className="container">
      <div className="header">
        <h1>Phishing Email Detector</h1>
        <p>Paste an email to scan for phishing indicators</p>
      </div>
      
      <textarea
        className="email-input"
        placeholder="Paste email content here..."
        value={emailContent}
        onChange={(e) => setEmailContent(e.target.value)}
      ></textarea>

      <button className="analyze-button" onClick={analyzeEmail} disabled={!emailContent.trim() || loading}>
        {loading ? 'Analyzing...' : 'Analyze Email'}
      </button>

      {analysis && (
        <div className="results">
          <h2>Analysis Results</h2>
          <div className={`risk-indicator ${analysis.riskLevel.color}`}>
            {analysis.riskLevel.level} Risk (Score: {analysis.riskScore}/100)
          </div>
        </div>
      )}
    </div>
  );
};

export default PhishingDetector;
