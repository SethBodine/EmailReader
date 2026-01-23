import React, { useState } from 'react';
import { Mail, FileText, Shield, CheckCircle, XCircle, AlertCircle, Info, Download, Upload } from 'lucide-react';

const EmailAnalyzer = () => {
  const [activeTab, setActiveTab] = useState('headers');
  const [headerInput, setHeaderInput] = useState('');
  const [file, setFile] = useState(null);
  const [headerAnalysis, setHeaderAnalysis] = useState(null);
  const [parsedEmail, setParsedEmail] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  // Parse and analyze email headers
  const analyzeHeaders = (headerText) => {
    setError(null);
    setHeaderAnalysis(null);

    try {
      const lines = (headerText || headerInput).split('\n');
      const headers = {};
      let currentHeader = null;
      let currentValue = '';

      lines.forEach(line => {
        if (line.match(/^[\w-]+:/)) {
          if (currentHeader) {
            if (!headers[currentHeader]) headers[currentHeader] = [];
            headers[currentHeader].push(currentValue.trim());
          }
          const colonIndex = line.indexOf(':');
          currentHeader = line.substring(0, colonIndex).trim().toLowerCase();
          currentValue = line.substring(colonIndex + 1);
        } else if (currentHeader && line.match(/^\s/)) {
          currentValue += ' ' + line.trim();
        }
      });

      if (currentHeader) {
        if (!headers[currentHeader]) headers[currentHeader] = [];
        headers[currentHeader].push(currentValue.trim());
      }

      const analysis = performHeaderAnalysis(headers);
      setHeaderAnalysis(analysis);
      return analysis;
    } catch (e) {
      setError('Failed to parse headers: ' + e.message);
      return null;
    }
  };

  const performHeaderAnalysis = (headers) => {
    const result = {
      authentication: [],
      spam: [],
      routing: [],
      validation: [],
      warnings: [],
      summary: {
        good: 0,
        bad: 0,
        warning: 0
      }
    };

    // SPF Analysis
    if (headers['received-spf']) {
      headers['received-spf'].forEach(spf => {
        const status = spf.toLowerCase();
        const isPass = status.includes('pass');
        const isFail = status.includes('fail');
        
        result.authentication.push({
          type: 'SPF',
          value: spf,
          status: isPass ? 'pass' : isFail ? 'fail' : 'neutral',
          explanation: getSPFExplanation(spf),
          impact: isPass ? 'GOOD' : isFail ? 'BAD' : 'WARNING',
          userGuidance: isPass 
            ? '✓ This is good - the sender is authorized to send from this domain. Email is less likely to be spam.'
            : isFail 
            ? '✗ This is bad - the sender is NOT authorized to send from this domain. Email might be spoofed or spam.'
            : '⚠ This is neutral - the domain owner has not set up proper SPF records. Treat with caution.',
          details: parseSPFDetails(spf)
        });
        
        if (isPass) result.summary.good++;
        else if (isFail) result.summary.bad++;
        else result.summary.warning++;
      });
    } else {
      result.warnings.push({ 
        type: 'SPF', 
        message: 'No SPF record found - email authentication cannot be verified',
        impact: 'WARNING',
        userGuidance: '⚠ This is concerning - legitimate senders should have SPF configured. Be cautious with this email.'
      });
      result.summary.warning++;
    }

    // DKIM Analysis
    if (headers['dkim-signature']) {
      headers['dkim-signature'].forEach(dkim => {
        const dkimDetails = parseDKIMSignature(dkim);
        result.authentication.push({
          type: 'DKIM',
          value: dkim.substring(0, 100) + '...',
          status: 'present',
          explanation: 'DKIM signature found - verifies email authenticity and prevents tampering',
          impact: 'GOOD',
          userGuidance: '✓ This is good - the email has a digital signature proving it has not been modified in transit.',
          details: dkimDetails
        });
        result.summary.good++;
      });
    } else {
      result.warnings.push({ 
        type: 'DKIM', 
        message: 'No DKIM signature found - email integrity cannot be verified',
        impact: 'WARNING',
        userGuidance: '⚠ This is concerning - legitimate email senders should sign their emails. The email might not be authentic.'
      });
      result.summary.warning++;
    }

    // DMARC via Authentication-Results
    if (headers['authentication-results']) {
      headers['authentication-results'].forEach(auth => {
        const dmarcInfo = parseDMARCResult(auth);
        if (dmarcInfo.found) {
          result.authentication.push({
            type: 'DMARC',
            value: auth,
            status: dmarcInfo.pass ? 'pass' : 'fail',
            explanation: getDMARCExplanation(dmarcInfo.pass ? 'pass' : 'fail'),
            impact: dmarcInfo.pass ? 'GOOD' : 'BAD',
            userGuidance: dmarcInfo.pass
              ? '✓ This is excellent - email passed both SPF and DKIM checks. Very likely to be legitimate.'
              : '✗ This is bad - DMARC alignment failed. The email may be forged or from a compromised account.',
            details: dmarcInfo
          });
          
          if (dmarcInfo.pass) result.summary.good++;
          else result.summary.bad++;
        }
      });
    }

    // ARC (Authenticated Received Chain)
    if (headers['arc-authentication-results']) {
      result.authentication.push({
        type: 'ARC',
        value: headers['arc-authentication-results'][0].substring(0, 100) + '...',
        status: 'present',
        explanation: 'ARC chain present - preserves authentication results through forwarding',
        impact: 'GOOD',
        userGuidance: '✓ This is good - authentication is preserved even if the email was forwarded through mailing lists.'
      });
      result.summary.good++;
    }

    // Spam Score Analysis - Enhanced
    if (headers['x-spam-status']) {
      const spamDetails = parseSpamStatus(headers['x-spam-status'][0]);
      const score = spamDetails.score || 0;
      const isGood = score < 5;
      const isWarning = score >= 5 && score < 10;
      const isBad = score >= 10;
      
      result.spam.push({
        type: 'Spam Analysis',
        value: headers['x-spam-status'][0],
        status: isGood ? 'good' : isWarning ? 'warning' : 'bad',
        explanation: `Spam score: ${score.toFixed(1)}. Threshold: ${spamDetails.threshold || 'N/A'}`,
        impact: isGood ? 'GOOD' : isWarning ? 'WARNING' : 'BAD',
        userGuidance: isGood
          ? `✓ This is good - spam score of ${score.toFixed(1)} is low. Email appears legitimate.`
          : isWarning
          ? `⚠ This is suspicious - spam score of ${score.toFixed(1)} is elevated. Review content carefully before trusting.`
          : `✗ This is bad - spam score of ${score.toFixed(1)} is very high. Email is very likely spam or malicious.`,
        details: spamDetails
      });
      
      if (isGood) result.summary.good++;
      else if (isWarning) result.summary.warning++;
      else result.summary.bad++;
    }

    if (headers['x-spam-score']) {
      const score = parseFloat(headers['x-spam-score'][0]);
      if (!headers['x-spam-status']) {
        const isGood = score < 5;
        const isWarning = score >= 5 && score < 10;
        const isBad = score >= 10;
        
        result.spam.push({
          type: 'Spam Score',
          value: headers['x-spam-score'][0],
          status: isGood ? 'good' : isWarning ? 'warning' : 'bad',
          explanation: `Score: ${score}. Lower is better. <5 is normal, 5-10 is suspicious, >10 is likely spam`,
          impact: isGood ? 'GOOD' : isWarning ? 'WARNING' : 'BAD',
          userGuidance: isGood
            ? `✓ This is good - spam score of ${score} is low. Email appears legitimate.`
            : isWarning
            ? `⚠ This is suspicious - spam score of ${score} is elevated. Review content carefully before trusting.`
            : `✗ This is bad - spam score of ${score} is very high. Email is very likely spam or malicious.`
        });
        
        if (isGood) result.summary.good++;
        else if (isWarning) result.summary.warning++;
        else result.summary.bad++;
      }
    }

    if (headers['x-spam-flag']) {
      const flag = headers['x-spam-flag'][0].toLowerCase();
      const isFlagged = flag.includes('yes');
      
      result.spam.push({
        type: 'Spam Flag',
        value: headers['x-spam-flag'][0],
        status: isFlagged ? 'bad' : 'good',
        explanation: isFlagged ? 'Marked as spam' : 'Not marked as spam',
        impact: isFlagged ? 'BAD' : 'GOOD',
        userGuidance: isFlagged
          ? '✗ This is bad - email is explicitly marked as spam. Likely dangerous.'
          : '✓ This is good - email is not flagged as spam.'
      });
      
      if (isFlagged) result.summary.bad++;
      else result.summary.good++;
    }

    // Content filtering
    if (headers['x-virus-scanned']) {
      result.spam.push({
        type: 'Virus Scan',
        value: headers['x-virus-scanned'][0],
        status: 'good',
        explanation: 'Email was scanned for viruses',
        impact: 'GOOD',
        userGuidance: '✓ This is good - email was scanned by antivirus software. No viruses detected.'
      });
      result.summary.good++;
    }

    // Routing Analysis
    if (headers['received']) {
      result.routing.push({
        type: 'Mail Hops',
        value: `${headers['received'].length} hops`,
        hops: headers['received'].reverse(),
        explanation: `Email passed through ${headers['received'].length} mail servers. Fewer hops indicates more direct delivery.`
      });
    }

    // Return-Path analysis
    if (headers['return-path']) {
      result.routing.push({
        type: 'Return-Path',
        value: headers['return-path'][0],
        status: 'present',
        explanation: 'Specifies where bounced emails should be sent'
      });
    }

    // Basic Validation
    const requiredHeaders = ['from', 'date', 'message-id'];
    requiredHeaders.forEach(h => {
      if (headers[h]) {
        result.validation.push({
          type: h.toUpperCase(),
          value: headers[h][0],
          status: 'present'
        });
      } else {
        result.validation.push({
          type: h.toUpperCase(),
          value: null,
          status: 'missing'
        });
      }
    });

    // Subject validation
    if (headers['subject']) {
      result.validation.push({
        type: 'SUBJECT',
        value: headers['subject'][0],
        status: 'present'
      });
    }

    return result;
  };

  const parseSPFDetails = (spf) => {
    const details = {
      result: null,
      clientIP: null,
      envelopeFrom: null,
      helo: null,
      receiver: null
    };

    const resultMatch = spf.match(/\b(pass|fail|softfail|neutral|none|temperror|permerror)\b/i);
    if (resultMatch) details.result = resultMatch[1];

    const ipMatch = spf.match(/client-ip=([^\s;]+)/i);
    if (ipMatch) details.clientIP = ipMatch[1];

    const envelopeMatch = spf.match(/envelope-from=([^\s;]+)/i);
    if (envelopeMatch) details.envelopeFrom = envelopeMatch[1];

    const heloMatch = spf.match(/helo=([^\s;]+)/i);
    if (heloMatch) details.helo = heloMatch[1];

    const receiverMatch = spf.match(/receiver=([^\s;]+)/i);
    if (receiverMatch) details.receiver = receiverMatch[1];

    return details;
  };

  const parseDKIMSignature = (dkim) => {
    const details = {
      version: null,
      algorithm: null,
      domain: null,
      selector: null,
      headers: null,
      bodyHash: null
    };

    const vMatch = dkim.match(/v=([^;]+)/);
    if (vMatch) details.version = vMatch[1].trim();

    const aMatch = dkim.match(/a=([^;]+)/);
    if (aMatch) details.algorithm = aMatch[1].trim();

    const dMatch = dkim.match(/d=([^;]+)/);
    if (dMatch) details.domain = dMatch[1].trim();

    const sMatch = dkim.match(/s=([^;]+)/);
    if (sMatch) details.selector = sMatch[1].trim();

    const hMatch = dkim.match(/h=([^;]+)/);
    if (hMatch) details.headers = hMatch[1].trim();

    const bhMatch = dkim.match(/bh=([^;]+)/);
    if (bhMatch) details.bodyHash = bhMatch[1].trim().substring(0, 20) + '...';

    return details;
  };

  const parseDMARCResult = (authResults) => {
    const info = {
      found: false,
      pass: false,
      policy: null,
      reason: null
    };

    if (authResults.toLowerCase().includes('dmarc')) {
      info.found = true;
      info.pass = authResults.toLowerCase().includes('dmarc=pass');
      
      const policyMatch = authResults.match(/policy\.(\w+)/i);
      if (policyMatch) info.policy = policyMatch[1];

      const reasonMatch = authResults.match(/reason=([^\s;]+)/i);
      if (reasonMatch) info.reason = reasonMatch[1];
    }

    return info;
  };

  const parseSpamStatus = (spamStatus) => {
    const details = {
      isSpam: false,
      score: null,
      threshold: null,
      tests: [],
      autolearn: null
    };

    details.isSpam = spamStatus.toLowerCase().includes('yes');

    const scoreMatch = spamStatus.match(/score=([-\d.]+)/i);
    if (scoreMatch) details.score = parseFloat(scoreMatch[1]);

    const thresholdMatch = spamStatus.match(/required=([-\d.]+)/i);
    if (thresholdMatch) details.threshold = parseFloat(thresholdMatch[1]);

    const testsMatch = spamStatus.match(/tests=([^\s]+)/i);
    if (testsMatch) {
      details.tests = testsMatch[1].split(',').filter(t => t.length > 0);
    }

    const autolearnMatch = spamStatus.match(/autolearn=(\w+)/i);
    if (autolearnMatch) details.autolearn = autolearnMatch[1];

    return details;
  };

  const getSPFExplanation = (spf) => {
    const lower = spf.toLowerCase();
    if (lower.includes('pass')) return 'SPF check passed - sender is authorized to send from this domain';
    if (lower.includes('fail')) return 'SPF check failed - sender is NOT authorized (possible spoofing)';
    if (lower.includes('softfail')) return 'SPF soft fail - sender may be unauthorized (borderline case)';
    if (lower.includes('neutral')) return 'SPF neutral - domain owner has not published a policy';
    if (lower.includes('none')) return 'SPF none - no SPF record exists for this domain';
    return 'SPF status unclear';
  };

  const getDMARCExplanation = (status) => {
    return status === 'pass' 
      ? 'DMARC alignment successful - email passed both SPF and DKIM authentication'
      : 'DMARC alignment failed - email may be spoofed or misconfigured';
  };

  // Parse EML or MSG file
  const handleFileUpload = async (e) => {
    setError(null);
    setParsedEmail(null);
    setHeaderAnalysis(null);
    setLoading(true);
    
    const uploadedFile = e.target.files[0];
    if (!uploadedFile) {
      setLoading(false);
      return;
    }

    setFile(uploadedFile);

    try {
      const fileName = uploadedFile.name.toLowerCase();
      
      if (fileName.endsWith('.eml')) {
        await parseEmlFile(uploadedFile);
      } else if (fileName.endsWith('.msg')) {
        await parseMsgFile(uploadedFile);
      } else {
        throw new Error('Unsupported file type. Please upload .eml or .msg files only.');
      }
    } catch (e) {
      setError('Failed to parse file: ' + e.message);
    } finally {
      setLoading(false);
    }
  };

  const parseEmlFile = async (file) => {
    const text = await file.text();
    const PostalMime = (await import('https://cdn.jsdelivr.net/npm/postal-mime@2.7.3/+esm')).default;
    const parser = new PostalMime();
    const email = await parser.parse(text);
    
    setParsedEmail({
      type: 'eml',
      data: email
    });

    // Auto-analyze headers from EML
    if (email.headers && email.headers.length > 0) {
      const headerText = email.headers.map(h => `${h.key}: ${h.value}`).join('\n');
      setHeaderInput(headerText);
      analyzeHeaders(headerText);
    }
  };

  const parseMsgFile = async (file) => {
    const arrayBuffer = await file.arrayBuffer();
    
    // Load MSGReader library via jsDelivr with correct version
    if (!window.MSGReader) {
      try {
        const script = document.createElement('script');
        // Use the correct alpha version with jsDelivr
        script.src = 'https://cdn.jsdelivr.net/npm/@kenjiuno/msgreader@1.27.1-alpha.1/lib/index.js';
        
        await new Promise((resolve, reject) => {
          script.onload = () => {
            // Give it a moment for the module to initialize
            setTimeout(() => {
              if (window.MSGReader || (window.exports && window.exports.default)) {
                resolve();
              } else {
                reject(new Error('MSG reader loaded but constructor not found'));
              }
            }, 100);
          };
          script.onerror = () => reject(new Error('Failed to load MSG reader from CDN'));
          document.head.appendChild(script);
        });
      } catch (loadError) {
        throw new Error(`Cannot load MSG parser: ${loadError.message}. Please convert MSG to EML format (File > Save As > .eml in Outlook) or check your internet connection.`);
      }
    }
    
    try {
      // Try different possible exports
      const MsgReader = window.MSGReader || (window.exports && window.exports.default) || window.MsgReader;
      
      if (!MsgReader) {
        throw new Error('MSG reader library not available. Please use EML format instead.');
      }
      
      const msgReader = new MsgReader(arrayBuffer);
      const msgData = msgReader.getFileData();
    
      // Convert MSG format to normalized format
      const normalized = {
        from: {
          name: msgData.senderName || '',
          address: msgData.senderEmail || msgData.senderSmtpAddress || msgData.sentRepresentingSmtpAddress || ''
        },
        to: msgData.recipients?.filter(r => r.recipType === 'to').map(r => ({
          name: r.name || '',
          address: r.email || r.smtpAddress || ''
        })) || [],
        cc: msgData.recipients?.filter(r => r.recipType === 'cc').map(r => ({
          name: r.name || '',
          address: r.email || r.smtpAddress || ''
        })) || [],
        subject: msgData.subject || '',
        date: msgData.clientSubmitTime || msgData.creationTime || msgData.deliveryTime || '',
        messageId: msgData.internetMessageId || '',
        text: msgData.body || '',
        html: msgData.bodyHTML || null,
        headers: msgData.headers ? parseHeaderString(msgData.headers) : [],
        attachments: msgData.attachments?.map(att => {
          const attachment = msgReader.getAttachment(att);
          return {
            filename: attachment.fileName || 'attachment',
            mimeType: attachment.mimeType || 'application/octet-stream',
            content: attachment.content
          };
        }) || []
      };
      
      setParsedEmail({
        type: 'msg',
        data: normalized
      });

      // Auto-analyze headers from MSG
      if (normalized.headers && normalized.headers.length > 0) {
        const headerText = normalized.headers.map(h => `${h.key}: ${h.value}`).join('\n');
        setHeaderInput(headerText);
        analyzeHeaders(headerText);
      }
    } catch (parseError) {
      throw new Error(`Failed to parse MSG file: ${parseError.message}`);
    }
  };

  const parseHeaderString = (headerString) => {
    const lines = headerString.split(/\r?\n/);
    const headers = [];
    let currentKey = null;
    let currentValue = '';

    lines.forEach(line => {
      if (line.match(/^[\w-]+:/)) {
        if (currentKey) {
          headers.push({ key: currentKey, value: currentValue.trim() });
        }
        const colonIndex = line.indexOf(':');
        currentKey = line.substring(0, colonIndex).trim();
        currentValue = line.substring(colonIndex + 1);
      } else if (currentKey && line.match(/^\s/)) {
        currentValue += ' ' + line.trim();
      }
    });

    if (currentKey) {
      headers.push({ key: currentKey, value: currentValue.trim() });
    }

    return headers;
  };

  const downloadAttachment = (attachment) => {
    const blob = new Blob([attachment.content], { type: attachment.mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = attachment.filename || 'attachment';
    a.click();
    URL.revokeObjectURL(url);
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="bg-white rounded-lg shadow-lg p-8 mb-6">
          <div className="flex items-center gap-3 mb-4">
            <Mail className="w-10 h-10 text-blue-600" />
            <div>
              <h1 className="text-3xl font-bold text-slate-800">Email Analysis Tool</h1>
              <p className="text-slate-600">Decode headers • Parse EML/MSG files • Analyze authentication & spam</p>
            </div>
          </div>

          {/* Tabs */}
          <div className="flex gap-4 border-b border-slate-200">
            <button
              onClick={() => setActiveTab('headers')}
              className={`px-6 py-3 font-medium transition-colors ${
                activeTab === 'headers'
                  ? 'text-blue-600 border-b-2 border-blue-600'
                  : 'text-slate-600 hover:text-slate-800'
              }`}
            >
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5" />
                Header Decoder
              </div>
            </button>
            <button
              onClick={() => setActiveTab('converter')}
              className={`px-6 py-3 font-medium transition-colors ${
                activeTab === 'converter'
                  ? 'text-blue-600 border-b-2 border-blue-600'
                  : 'text-slate-600 hover:text-slate-800'
              }`}
            >
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5" />
                EML/MSG Converter
              </div>
            </button>
          </div>
        </div>

        {/* Error Display */}
        {error && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6 flex items-start gap-3">
            <XCircle className="w-5 h-5 text-red-600 mt-0.5 flex-shrink-0" />
            <div>
              <h3 className="font-semibold text-red-900">Error</h3>
              <p className="text-red-700 text-sm">{error}</p>
            </div>
          </div>
        )}

        {/* Header Decoder Tab */}
        {activeTab === 'headers' && (
          <div className="space-y-6">
            <div className="bg-white rounded-lg shadow-lg p-6">
              <h2 className="text-xl font-bold text-slate-800 mb-4">Paste Email Headers</h2>
              <div className="mb-4 p-4 bg-blue-50 border border-blue-200 rounded-lg">
                <h3 className="font-semibold text-blue-900 mb-2 flex items-center gap-2">
                  <Info className="w-5 h-5" />
                  How to interpret results
                </h3>
                <div className="text-sm text-blue-800 space-y-1">
                  <p><strong className="text-green-700">✓ Good indicators:</strong> These are positive signs that the email is legitimate and safe.</p>
                  <p><strong className="text-amber-700">⚠ Warnings:</strong> These suggest caution - the email may be legitimate but lacks proper authentication.</p>
                  <p><strong className="text-red-700">✗ Bad indicators:</strong> These are red flags - the email is likely spam, phishing, or spoofed.</p>
                  <p className="pt-2 border-t border-blue-300 mt-2"><strong>Pro tip:</strong> Legitimate companies always configure SPF, DKIM, and DMARC. Missing authentication is a major warning sign.</p>
                </div>
              </div>
              <textarea
                className="w-full h-64 p-4 border border-slate-300 rounded-lg font-mono text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Received: from mail.example.com&#10;From: sender@example.com&#10;To: recipient@example.com&#10;Subject: Test Email&#10;Date: Thu, 22 Jan 2026 10:30:00 +0000&#10;Received-SPF: pass&#10;DKIM-Signature: v=1; a=rsa-sha256; ...&#10;X-Spam-Score: 2.5&#10;X-Spam-Status: No"
                value={headerInput}
                onChange={(e) => setHeaderInput(e.target.value)}
              />
              <button
                onClick={() => analyzeHeaders()}
                className="mt-4 px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium"
              >
                Analyze Headers
              </button>
            </div>

            {/* Header Analysis Results */}
            {headerAnalysis && (
              <div className="space-y-6">
                {/* Overall Summary */}
                <div className="bg-white rounded-lg shadow-lg p-6">
                  <h2 className="text-xl font-bold text-slate-800 mb-4">Overall Assessment</h2>
                  <div className="grid grid-cols-3 gap-4">
                    <div className="p-4 bg-green-50 border-2 border-green-200 rounded-lg text-center">
                      <div className="text-3xl font-bold text-green-600">{headerAnalysis.summary.good}</div>
                      <div className="text-sm text-green-800 font-medium">Good Indicators</div>
                      <div className="text-xs text-green-600 mt-1">✓ Positive signs</div>
                    </div>
                    <div className="p-4 bg-amber-50 border-2 border-amber-200 rounded-lg text-center">
                      <div className="text-3xl font-bold text-amber-600">{headerAnalysis.summary.warning}</div>
                      <div className="text-sm text-amber-800 font-medium">Warnings</div>
                      <div className="text-xs text-amber-600 mt-1">⚠ Needs attention</div>
                    </div>
                    <div className="p-4 bg-red-50 border-2 border-red-200 rounded-lg text-center">
                      <div className="text-3xl font-bold text-red-600">{headerAnalysis.summary.bad}</div>
                      <div className="text-sm text-red-800 font-medium">Bad Indicators</div>
                      <div className="text-xs text-red-600 mt-1">✗ Major concerns</div>
                    </div>
                  </div>
                  <div className="mt-4 p-4 bg-slate-50 rounded-lg">
                    <p className="text-sm text-slate-700">
                      <strong>What this means:</strong> {
                        headerAnalysis.summary.bad > 0
                          ? '🚨 This email has serious red flags. Be very cautious - it may be spam or malicious.'
                          : headerAnalysis.summary.warning > 2
                          ? '⚠️ This email has some concerns. Review carefully before trusting the content or clicking links.'
                          : headerAnalysis.summary.good >= 3
                          ? '✅ This email appears legitimate with good authentication. Generally safe to trust.'
                          : '📋 Limited information available. Use additional judgment to assess trustworthiness.'
                      }
                    </p>
                  </div>
                </div>

                {/* Authentication */}
                {headerAnalysis.authentication.length > 0 && (
                  <div className="bg-white rounded-lg shadow-lg p-6">
                    <h2 className="text-xl font-bold text-slate-800 mb-4 flex items-center gap-2">
                      <Shield className="w-6 h-6 text-blue-600" />
                      Email Authentication
                    </h2>
                    <div className="space-y-4">
                      {headerAnalysis.authentication.map((auth, idx) => (
                        <div key={idx} className={`p-4 rounded-lg border-2 ${
                          auth.status === 'pass' ? 'bg-green-50 border-green-200' :
                          auth.status === 'fail' ? 'bg-red-50 border-red-200' :
                          'bg-blue-50 border-blue-200'
                        }`}>
                          <div className="flex items-start justify-between mb-2">
                            <div className="flex items-center gap-2">
                              {auth.status === 'pass' && <CheckCircle className="w-5 h-5 text-green-600" />}
                              {auth.status === 'fail' && <XCircle className="w-5 h-5 text-red-600" />}
                              {auth.status === 'present' && <Info className="w-5 h-5 text-blue-600" />}
                              {auth.status === 'neutral' && <AlertCircle className="w-5 h-5 text-amber-600" />}
                              <span className="font-bold text-lg">{auth.type}</span>
                            </div>
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                              auth.status === 'pass' ? 'bg-green-100 text-green-800' :
                              auth.status === 'fail' ? 'bg-red-100 text-red-800' :
                              auth.status === 'neutral' ? 'bg-amber-100 text-amber-800' :
                              'bg-blue-100 text-blue-800'
                            }`}>
                              {auth.status.toUpperCase()}
                            </span>
                          </div>
                          <p className="text-sm text-slate-700 mb-2">{auth.explanation}</p>
                          {auth.userGuidance && (
                            <div className={`p-3 rounded mt-3 ${
                              auth.impact === 'GOOD' ? 'bg-green-100 border border-green-300' :
                              auth.impact === 'BAD' ? 'bg-red-100 border border-red-300' :
                              'bg-amber-100 border border-amber-300'
                            }`}>
                              <p className="text-sm font-medium">{auth.userGuidance}</p>
                            </div>
                          )}
                          {auth.details && (
                            <div className="mt-3 p-3 bg-white rounded border border-slate-200">
                              <p className="text-xs font-semibold text-slate-700 mb-2">Technical Details:</p>
                              <div className="text-xs text-slate-600 space-y-1 font-mono">
                                {auth.type === 'SPF' && auth.details.result && (
                                  <>
                                    {auth.details.result && <p>Result: {auth.details.result}</p>}
                                    {auth.details.clientIP && <p>Client IP: {auth.details.clientIP}</p>}
                                    {auth.details.envelopeFrom && <p>Envelope From: {auth.details.envelopeFrom}</p>}
                                    {auth.details.helo && <p>HELO: {auth.details.helo}</p>}
                                  </>
                                )}
                                {auth.type === 'DKIM' && auth.details.domain && (
                                  <>
                                    {auth.details.domain && <p>Domain: {auth.details.domain}</p>}
                                    {auth.details.selector && <p>Selector: {auth.details.selector}</p>}
                                    {auth.details.algorithm && <p>Algorithm: {auth.details.algorithm}</p>}
                                    {auth.details.headers && <p>Signed Headers: {auth.details.headers}</p>}
                                  </>
                                )}
                                {auth.type === 'DMARC' && auth.details.policy && (
                                  <>
                                    {auth.details.policy && <p>Policy: {auth.details.policy}</p>}
                                    {auth.details.reason && <p>Reason: {auth.details.reason}</p>}
                                  </>
                                )}
                              </div>
                            </div>
                          )}
                          <p className="text-xs text-slate-600 font-mono break-all bg-white p-2 rounded mt-2">{auth.value}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Spam Analysis */}
                {headerAnalysis.spam.length > 0 && (
                  <div className="bg-white rounded-lg shadow-lg p-6">
                    <h2 className="text-xl font-bold text-slate-800 mb-4">Spam Analysis</h2>
                    <div className="space-y-4">
                      {headerAnalysis.spam.map((spam, idx) => (
                        <div key={idx} className={`p-4 rounded-lg border-2 ${
                          spam.status === 'good' ? 'bg-green-50 border-green-200' :
                          spam.status === 'warning' ? 'bg-yellow-50 border-yellow-200' :
                          'bg-red-50 border-red-200'
                        }`}>
                          <div className="flex items-center justify-between mb-2">
                            <span className="font-bold">{spam.type}</span>
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                              spam.status === 'good' ? 'bg-green-100 text-green-800' :
                              spam.status === 'warning' ? 'bg-yellow-100 text-yellow-800' :
                              'bg-red-100 text-red-800'
                            }`}>
                              {spam.status.toUpperCase()}
                            </span>
                          </div>
                          <p className="text-sm text-slate-700 mb-2">{spam.explanation}</p>
                          {spam.userGuidance && (
                            <div className={`p-3 rounded mt-3 ${
                              spam.impact === 'GOOD' ? 'bg-green-100 border border-green-300' :
                              spam.impact === 'BAD' ? 'bg-red-100 border border-red-300' :
                              'bg-amber-100 border border-amber-300'
                            }`}>
                              <p className="text-sm font-medium">{spam.userGuidance}</p>
                            </div>
                          )}
                          {spam.details && spam.details.tests && spam.details.tests.length > 0 && (
                            <div className="mt-3 p-3 bg-white rounded border border-slate-200">
                              <p className="text-xs font-semibold text-slate-700 mb-2">Spam Tests Triggered:</p>
                              <div className="flex flex-wrap gap-2">
                                {spam.details.tests.map((test, testIdx) => (
                                  <span key={testIdx} className="px-2 py-1 bg-slate-100 text-slate-700 rounded text-xs font-mono">
                                    {test}
                                  </span>
                                ))}
                              </div>
                              {spam.details.autolearn && (
                                <p className="text-xs text-slate-600 mt-2">Auto-learn: {spam.details.autolearn}</p>
                              )}
                            </div>
                          )}
                          <p className="text-xs text-slate-600 font-mono mt-2">{spam.value}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Routing */}
                {headerAnalysis.routing.length > 0 && (
                  <div className="bg-white rounded-lg shadow-lg p-6">
                    <h2 className="text-xl font-bold text-slate-800 mb-4">Email Routing</h2>
                    <div className="space-y-4">
                      {headerAnalysis.routing.map((route, idx) => (
                        <div key={idx}>
                          <div className="flex items-center gap-2 mb-3">
                            <Info className="w-5 h-5 text-blue-600" />
                            <span className="font-bold">{route.type}: {route.value}</span>
                          </div>
                          <p className="text-sm text-slate-700 mb-3">{route.explanation}</p>
                          {route.hops && (
                            <div className="space-y-2">
                              {route.hops.map((hop, hopIdx) => (
                                <div key={hopIdx} className="p-3 bg-slate-50 rounded border border-slate-200">
                                  <div className="flex items-center gap-2 mb-1">
                                    <span className="bg-blue-100 text-blue-800 px-2 py-1 rounded text-xs font-bold">
                                      Hop {hopIdx + 1}
                                    </span>
                                  </div>
                                  <p className="text-xs text-slate-600 font-mono">{hop}</p>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Warnings */}
                {headerAnalysis.warnings.length > 0 && (
                  <div className="bg-white rounded-lg shadow-lg p-6">
                    <h2 className="text-xl font-bold text-slate-800 mb-4 flex items-center gap-2">
                      <AlertCircle className="w-6 h-6 text-amber-600" />
                      Warnings
                    </h2>
                    <div className="space-y-3">
                      {headerAnalysis.warnings.map((warning, idx) => (
                        <div key={idx} className="p-4 bg-amber-50 border-2 border-amber-200 rounded-lg">
                          <div className="flex items-center gap-2 mb-2">
                            <span className="font-bold text-amber-900">{warning.type}</span>
                            <span className="text-sm text-amber-700">- {warning.message}</span>
                          </div>
                          {warning.userGuidance && (
                            <div className="p-3 bg-amber-100 border border-amber-300 rounded mt-2">
                              <p className="text-sm font-medium text-amber-900">{warning.userGuidance}</p>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* EML/MSG Converter Tab */}
        {activeTab === 'converter' && (
          <div className="space-y-6">
            <div className="bg-white rounded-lg shadow-lg p-6">
              <h2 className="text-xl font-bold text-slate-800 mb-4">Upload Email File</h2>
              <div className="mb-4 p-4 bg-blue-50 border border-blue-200 rounded-lg">
                <h3 className="font-semibold text-blue-900 mb-2 flex items-center gap-2">
                  <Info className="w-5 h-5" />
                  Supported Formats
                </h3>
                <div className="text-sm text-blue-800 space-y-2">
                  <p><strong>✓ EML files</strong> - Direct parsing with full header analysis</p>
                  <p><strong>✓ MSG files</strong> - Automatically converted to EML then parsed</p>
                  <p className="pt-2 border-t border-blue-300 mt-2">
                    <strong>How it works:</strong> MSG files are converted to EML format in your browser (no server upload), then analyzed. All processing happens locally for privacy.
                  </p>
                </div>
              </div>
              <p className="text-slate-600 mb-4">
                <span className="text-blue-600 font-medium">Headers will be automatically analyzed after upload.</span>
              </p>
              <div className="flex items-center gap-4">
                <label className="flex-1">
                  <div className="flex items-center justify-center w-full h-32 border-2 border-dashed border-slate-300 rounded-lg hover:border-blue-500 cursor-pointer transition-colors bg-slate-50 hover:bg-blue-50">
                    <div className="text-center">
                      <Upload className="w-8 h-8 text-slate-400 mx-auto mb-2" />
                      <p className="text-sm text-slate-600">
                        Click to upload <strong>.eml</strong> or <strong>.msg</strong> file
                      </p>
                      <p className="text-xs text-slate-500 mt-1">
                        MSG files auto-converted in browser
                      </p>
                      {file && <p className="text-xs text-blue-600 mt-2">{file.name}</p>}
                    </div>
                  </div>
                  <input
                    type="file"
                    accept=".eml,.msg"
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                </label>
              </div>
              {loading && (
                <div className="mt-4 text-center text-slate-600">
                  <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-slate-300 border-t-blue-600"></div>
                  <p className="mt-2">Parsing email...</p>
                </div>
              )}
            </div>

            {/* Email Parse Results */}
            {parsedEmail && (
              <div className="space-y-6">
                {/* File Type Badge */}
                <div className="bg-white rounded-lg shadow-lg p-4">
                  <div className="flex items-center gap-2">
                    <span className="px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-sm font-medium">
                      {parsedEmail.type.toUpperCase()}
                    </span>
                    <span className="text-slate-600 text-sm">
                      {parsedEmail.type.includes('converted') 
                        ? 'MSG file converted to EML and parsed - headers analyzed automatically'
                        : 'Successfully parsed - headers analyzed automatically'}
                    </span>
                  </div>
                </div>

                {/* Basic Info */}
                <div className="bg-white rounded-lg shadow-lg p-6">
                  <h2 className="text-xl font-bold text-slate-800 mb-4">Email Information</h2>
                  <div className="space-y-3">
                    <div className="grid grid-cols-4 gap-4">
                      <div className="font-semibold text-slate-700">From:</div>
                      <div className="col-span-3 text-slate-900">
                        {parsedEmail.data.from?.name ? `${parsedEmail.data.from.name} <${parsedEmail.data.from.address}>` : parsedEmail.data.from?.address}
                      </div>
                    </div>
                    <div className="grid grid-cols-4 gap-4">
                      <div className="font-semibold text-slate-700">To:</div>
                      <div className="col-span-3 text-slate-900">
                        {parsedEmail.data.to?.map(t => t.name ? `${t.name} <${t.address}>` : t.address).join(', ')}
                      </div>
                    </div>
                    {parsedEmail.data.cc && parsedEmail.data.cc.length > 0 && (
                      <div className="grid grid-cols-4 gap-4">
                        <div className="font-semibold text-slate-700">CC:</div>
                        <div className="col-span-3 text-slate-900">
                          {parsedEmail.data.cc.map(c => c.name ? `${c.name} <${c.address}>` : c.address).join(', ')}
                        </div>
                      </div>
                    )}
                    <div className="grid grid-cols-4 gap-4">
                      <div className="font-semibold text-slate-700">Subject:</div>
                      <div className="col-span-3 text-slate-900 font-medium">{parsedEmail.data.subject}</div>
                    </div>
                    <div className="grid grid-cols-4 gap-4">
                      <div className="font-semibold text-slate-700">Date:</div>
                      <div className="col-span-3 text-slate-900">{parsedEmail.data.date}</div>
                    </div>
                    {parsedEmail.data.messageId && (
                      <div className="grid grid-cols-4 gap-4">
                        <div className="font-semibold text-slate-700">Message-ID:</div>
                        <div className="col-span-3 text-slate-600 font-mono text-sm">{parsedEmail.data.messageId}</div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Email Content */}
                {(parsedEmail.data.text || parsedEmail.data.html) && (
                  <div className="bg-white rounded-lg shadow-lg p-6">
                    <h2 className="text-xl font-bold text-slate-800 mb-4">Email Content</h2>
                    {parsedEmail.data.html ? (
                      <div>
                        <div className="mb-2 text-sm text-slate-600">HTML Content:</div>
                        <div className="p-4 bg-slate-50 rounded border border-slate-200 max-h-96 overflow-y-auto">
                          <iframe 
                            srcDoc={parsedEmail.data.html} 
                            className="w-full h-96 border-0"
                            sandbox="allow-same-origin"
                            title="Email HTML Content"
                          />
                        </div>
                      </div>
                    ) : parsedEmail.data.text ? (
                      <div>
                        <div className="mb-2 text-sm text-slate-600">Plain Text:</div>
                        <div className="p-4 bg-slate-50 rounded border border-slate-200 whitespace-pre-wrap max-h-96 overflow-y-auto">
                          {parsedEmail.data.text}
                        </div>
                      </div>
                    ) : null}
                  </div>
                )}

                {/* Attachments */}
                {parsedEmail.data.attachments && parsedEmail.data.attachments.length > 0 && (
                  <div className="bg-white rounded-lg shadow-lg p-6">
                    <h2 className="text-xl font-bold text-slate-800 mb-4">
                      Attachments ({parsedEmail.data.attachments.length})
                    </h2>
                    <div className="space-y-3">
                      {parsedEmail.data.attachments.map((att, idx) => (
                        <div key={idx} className="p-4 bg-slate-50 rounded border border-slate-200 flex items-center justify-between">
                          <div>
                            <div className="font-semibold text-slate-800">{att.filename || 'Unnamed'}</div>
                            <div className="text-sm text-slate-600">
                              {att.mimeType} • {formatBytes(att.content.byteLength || att.content.length)}
                            </div>
                          </div>
                          <button
                            onClick={() => downloadAttachment(att)}
                            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors flex items-center gap-2"
                          >
                            <Download className="w-4 h-4" />
                            Download
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Headers */}
                {parsedEmail.data.headers && parsedEmail.data.headers.length > 0 && (
                  <div className="bg-white rounded-lg shadow-lg p-6">
                    <h2 className="text-xl font-bold text-slate-800 mb-4">Raw Headers</h2>
                    <p className="text-sm text-slate-600 mb-3">
                      These headers have been automatically analyzed. Switch to the <strong>Header Decoder</strong> tab to view the detailed analysis.
                    </p>
                    <div className="space-y-2 max-h-96 overflow-y-auto">
                      {parsedEmail.data.headers.map((header, idx) => (
                        <div key={idx} className="p-3 bg-slate-50 rounded border border-slate-200">
                          <div className="font-semibold text-slate-700 text-sm">{header.key}:</div>
                          <div className="text-slate-600 text-sm font-mono break-all">{header.value}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default EmailAnalyzer;
