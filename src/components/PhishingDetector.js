import React, { useState } from 'react';
import './styles.css';

const PhishingDetector = () => {
  const [emailContent, setEmailContent] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);

  const phishingDomains = ['coldwellbankermoves.com', 'bankofamerica-secure.com', 'paypa1.com', 'microsoft-verify.com', 'google-docs.cc', 'secure-banking.co'];
  const freeEmailProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com'];
  const trustedSenders = ['support@bankofamerica.com', 'security@microsoft.com', 'no-reply@paypal.com'];

  const parseEmailHeaders = (content) => {
    const headers = {};
    const headerSection = content.split(/\n\s*\n/)[0];
    
    const fromMatch = headerSection.match(/From:(.+?)(?=\n[A-Za-z-]+:|$)/s);
    if (fromMatch) {
      headers.from = fromMatch[1].trim();
      const emailMatch = headers.from.match(/<([^>]+)>/);
      if (emailMatch) {
        headers.senderEmail = emailMatch[1];
        headers.senderDomain = emailMatch[1].split('@')[1];
      }
    }
    
    const replyToMatch = headerSection.match(/Reply-To:(.+?)(?=\n[A-Za-z-]+:|$)/s);
    if (replyToMatch) headers.replyTo = replyToMatch[1].trim();
    
    return headers;
  };

  const analyzeEmail = () => {
    setLoading(true);
    setTimeout(() => {
      const analysis = performAnalysis(emailContent);
      setResults(analysis);
      setLoading(false);
    }, 1200);
  };

  const performAnalysis = (content) => {
    const indicators = [];
    let riskScore = 0;
    const headers = parseEmailHeaders(content);
    
    if (headers.senderEmail && !trustedSenders.includes(headers.senderEmail)) {
      indicators.push({
        type: "Untrusted Sender",
        description: `Email is from an untrusted sender: ${headers.senderEmail}`,
        severity: "High",
        category: "Sender"
      });
      riskScore += 30;
    }
    
    if (headers.senderDomain) {
      if (phishingDomains.includes(headers.senderDomain)) {
        indicators.push({
          type: "Known Phishing Sender",
          description: `Email is from a known phishing domain: ${headers.senderDomain}`,
          severity: "Critical",
          category: "Sender"
        });
        riskScore += 40;
      }
      
      if (freeEmailProviders.includes(headers.senderDomain)) {
        indicators.push({
          type: "Free Email Provider",
          description: `Email is from a free email provider (${headers.senderDomain}), which is often used in phishing attempts`,
          severity: "Medium",
          category: "Sender"
        });
        riskScore += 20;
      }
    }
    
    riskScore = Math.min(100, Math.max(0, riskScore));
    
    let riskLevel;
    if (riskScore >= 85) {
      riskLevel = { level: "Critical" };
    } else if (riskScore >= 70) {
      riskLevel = { level: "High" };
    } else if (riskScore >= 45) {
      riskLevel = { level: "Medium" };
    } else if (riskScore >= 20) {
      riskLevel = { level: "Low" };
    } else {
      riskLevel = { level: "Safe" };
    }
    
    return {
      riskScore,
      riskLevel,
      indicators,
      headers
    };
  };

  return (
    <div className="container">
      <div className="header">
        <h1 className="title">Phishing Email Detector</h1>
      </div>
      <textarea
        className="email-textarea"
        placeholder="Paste full email content here including headers (From:, Reply-To:, etc.)"
        value={emailContent}
        onChange={(e) => setEmailContent(e.target.value)}
      ></textarea>
      <button 
        className="analyze-button"
        onClick={analyzeEmail}
        disabled={!emailContent.trim() || loading}
      >
        Analyze Email
      </button>
      {results && (
        <div>
          <h2>Analysis Results</h2>
          <p>Risk Level: {results.riskLevel.level} (Score: {results.riskScore}/100)</p>
          <h3>Indicators:</h3>
          <ul>
            {results.indicators.map((indicator, index) => (
              <li key={index}>{indicator.type} - {indicator.description}</li>
            ))}
          </ul>
          <h3>Email Headers:</h3>
          <p>From: {results.headers.from}</p>
          <p>Sender Email: {results.headers.senderEmail}</p>
          <p>Sender Domain: {results.headers.senderDomain}</p>
          <p>Reply-To: {results.headers.replyTo}</p>
        </div>
      )}
    </div>
  );
};

export default PhishingDetector;
