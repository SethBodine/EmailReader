import React, { useState, useEffect, useCallback } from 'react';
import { Upload, AlertCircle, CheckCircle, XCircle, Mail, FileText, Shield } from 'lucide-react';
import PostalMime from 'postal-mime';
import MSGReader from '@kenjiuno/msgreader';
import { Buffer } from 'buffer';

// Make Buffer available globally for MSGReader
window.Buffer = Buffer;

// Discord webhook URL from environment variable (set at build time)
const DISCORD_WEBHOOK_URL = import.meta.env.VITE_DISCORD_WEBHOOK_URL;

const EmailReader = () => {
  const [activeTab, setActiveTab] = useState('headers');
  const [headerInput, setHeaderInput] = useState('');
  const [headerAnalysis, setHeaderAnalysis] = useState(null);
  const [emailData, setEmailData] = useState(null);
  const [fileType, setFileType] = useState(null);
  const [autoAnalyze, setAutoAnalyze] = useState(false);

  // Telemetry function to send data to Discord
  const sendTelemetry = async (data) => {
    // Only send if webhook URL is configured
    if (!DISCORD_WEBHOOK_URL) {
      console.log('Discord webhook not configured, skipping telemetry');
      return;
    }

    try {
      // Get user's IP address via Cloudflare's edge trace (no third-party, already CSP-whitelisted)
      let userIP = 'Unknown';
      try {
        const traceResponse = await fetch('https://cloudflare.com/cdn-cgi/trace');
        const traceText = await traceResponse.text();
        const ipMatch = traceText.match(/^ip=(.+)$/m);
        if (ipMatch) userIP = ipMatch[1].trim();
      } catch {
        // IP lookup failed silently — telemetry continues without it
      }

      // Build Discord embed
      const embed = {
        title: '📧 Email Analysis Event',
        color: data.overall === 'good' ? 0x00ff00 : data.overall === 'bad' ? 0xff0000 : 0xffaa00,
        fields: [
          {
            name: '🌐 IP Address',
            value: userIP,
            inline: true
          },
          {
            name: '📁 File Type',
            value: data.fileType ? data.fileType.toUpperCase() : 'Manual Headers',
            inline: true
          },
          {
            name: '📊 Overall Assessment',
            value: data.overall === 'good' ? '✅ Good' : data.overall === 'bad' ? '❌ Bad' : '⚠️ Caution',
            inline: true
          },
          {
            name: '📤 From',
            value: data.from || 'N/A',
            inline: false
          },
          {
            name: '📥 To',
            value: data.to || 'N/A',
            inline: false
          },
          {
            name: '🔐 SPF',
            value: getStatusEmoji(data.spf),
            inline: true
          },
          {
            name: '🔑 DKIM',
            value: getStatusEmoji(data.dkim),
            inline: true
          },
          {
            name: '🛡️ DMARC',
            value: getStatusEmoji(data.dmarc),
            inline: true
          },
          {
            name: '🔗 ARC',
            value: getStatusEmoji(data.arc),
            inline: true
          },
          {
            name: '🎯 Spam Score',
            value: data.spamScore ? `${data.spamScore.level.toUpperCase()} (${data.spamScore.score})` : 'N/A',
            inline: true
          }
        ],
        timestamp: new Date().toISOString(),
        footer: {
          text: 'Email Security Analyser'
        }
      };

      // Send to Discord
      await fetch(DISCORD_WEBHOOK_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          embeds: [embed]
        })
      });

      console.log('Telemetry sent successfully');
    } catch (error) {
      console.error('Failed to send telemetry:', error);
      // Don't show error to user - telemetry should be silent
    }
  };

  const getStatusEmoji = (status) => {
    if (!status) return 'N/A';
    switch(status) {
      case 'pass': return '✅ Pass';
      case 'fail': return '❌ Fail';
      case 'warning': return '⚠️ Warning';
      case 'none': return '⚪ None';
      default: return 'N/A';
    }
  };

  // Auto-analyze when headers are populated from file upload
  useEffect(() => {
    if (autoAnalyze && headerInput) {
      analyzeHeaders();
      setAutoAnalyze(false);
    }
  }, [autoAnalyze]);

  // Parse headers into array format (key insight from working code!)
  const parseHeadersToObject = useCallback((headerText) => {
    const lines = headerText.split(/\r?\n/);
    const headers = {};
    let currentHeader = null;
    let currentValue = '';

    lines.forEach(line => {
      if (line.match(/^[\w-]+:/)) {
        // Save previous header
        if (currentHeader) {
          if (!headers[currentHeader]) headers[currentHeader] = [];
          headers[currentHeader].push(currentValue.trim());
        }
        // Start new header
        const colonIndex = line.indexOf(':');
        currentHeader = line.substring(0, colonIndex).trim().toLowerCase();
        currentValue = line.substring(colonIndex + 1);
      } else if (currentHeader && line.match(/^\s/)) {
        // Continuation line
        currentValue += ' ' + line.trim();
      }
    });

    // Save last header
    if (currentHeader) {
      if (!headers[currentHeader]) headers[currentHeader] = [];
      headers[currentHeader].push(currentValue.trim());
    }

    return headers;
  }, []);

  // Header Analysis Functions
  const analyzeHeaders = useCallback(() => {
    if (!headerInput.trim()) {
      alert('Please paste email headers first');
      return;
    }

    const headers = parseHeadersToObject(headerInput);
    console.log('Parsed headers:', headers);

    const analysis = {
      spf: analyzeAuth(headers, 'spf'),
      dkim: analyzeAuth(headers, 'dkim'),
      dmarc: analyzeAuth(headers, 'dmarc'),
      arc: analyzeAuth(headers, 'arc'),
      spamScore: detectSpamScore(headers),
      routing: extractRouting(headers),
      overall: 'unknown'
    };

    analysis.overall = calculateOverall(analysis);
    setHeaderAnalysis(analysis);

    // Extract from/to from headers for manual entry
    let fromEmail = 'Missing';
    let toEmail = 'Missing';
    
    if (headers['from'] && headers['from'][0]) {
      fromEmail = headers['from'][0];
    }
    if (headers['to'] && headers['to'][0]) {
      toEmail = headers['to'][0];
    }

    // Send telemetry
    sendTelemetry({
      fileType: fileType,
      from: emailData?.from || fromEmail,
      to: emailData?.to || toEmail,
      overall: analysis.overall,
      spf: analysis.spf.status,
      dkim: analysis.dkim.status,
      dmarc: analysis.dmarc.status,
      arc: analysis.arc.status,
      spamScore: analysis.spamScore
    });
  }, [headerInput, parseHeadersToObject, fileType, emailData]);

  const analyzeAuth = (headers, type) => {
    switch(type) {
      case 'spf':
        // Check received-spf header (array)
        if (headers['received-spf']) {
          const spfResults = headers['received-spf'];
          for (const spf of spfResults) {
            const spfLower = spf.toLowerCase();
            if (spfLower.includes('pass')) {
              return { 
                status: 'pass', 
                message: 'SPF verification passed',
                value: spf
              };
            } else if (spfLower.includes('fail') && !spfLower.includes('softfail')) {
              return { 
                status: 'fail', 
                message: 'SPF verification failed - sender not authorised',
                value: spf
              };
            } else if (spfLower.includes('softfail')) {
              return { 
                status: 'warning', 
                message: 'SPF soft fail - questionable sender',
                value: spf
              };
            } else if (spfLower.includes('neutral')) {
              return { 
                status: 'warning', 
                message: 'SPF neutral - no policy',
                value: spf
              };
            }
          }
        }
        // Also check authentication-results for spf
        if (headers['authentication-results']) {
          for (const auth of headers['authentication-results']) {
            const authLower = auth.toLowerCase();
            if (authLower.includes('spf=pass')) {
              return { 
                status: 'pass', 
                message: 'SPF verification passed',
                value: auth
              };
            } else if (authLower.includes('spf=fail')) {
              return { 
                status: 'fail', 
                message: 'SPF verification failed - sender not authorised',
                value: auth
              };
            }
          }
        }
        return { status: 'none', message: 'No SPF record found', value: null };
      
      case 'dkim':
        // Check for DKIM signature presence
        if (headers['dkim-signature']) {
          const dkimSig = headers['dkim-signature'][0];
          // Check authentication-results for verification status
          if (headers['authentication-results']) {
            for (const auth of headers['authentication-results']) {
              const authLower = auth.toLowerCase();
              if (authLower.includes('dkim=pass')) {
                return { 
                  status: 'pass', 
                  message: 'DKIM signature valid',
                  value: dkimSig.substring(0, 100) + '...'
                };
              } else if (authLower.includes('dkim=fail')) {
                return { 
                  status: 'fail', 
                  message: 'DKIM signature invalid - message may be altered',
                  value: dkimSig.substring(0, 100) + '...'
                };
              }
            }
          }
          // DKIM signature present but no verification result
          return { 
            status: 'warning', 
            message: 'DKIM signature present but not verified',
            value: dkimSig.substring(0, 100) + '...'
          };
        }
        return { status: 'none', message: 'No DKIM signature found', value: null };
      
      case 'dmarc':
        // Check authentication-results for DMARC
        if (headers['authentication-results']) {
          for (const auth of headers['authentication-results']) {
            const authLower = auth.toLowerCase();
            if (authLower.includes('dmarc=pass')) {
              return { 
                status: 'pass', 
                message: 'DMARC policy satisfied',
                value: auth
              };
            } else if (authLower.includes('dmarc=fail')) {
              return { 
                status: 'fail', 
                message: 'DMARC policy not satisfied',
                value: auth
              };
            } else if (authLower.includes('dmarc=bestguesspass')) {
              return { 
                status: 'warning', 
                message: 'DMARC best guess pass (no policy)',
                value: auth
              };
            }
          }
        }
        return { status: 'none', message: 'No DMARC policy found', value: null };
      
      case 'arc':
        // Check for ARC headers
        if (headers['arc-authentication-results'] || headers['arc-seal']) {
          const arcValue = headers['arc-authentication-results']?.[0] || headers['arc-seal']?.[0];
          if (headers['authentication-results']) {
            for (const auth of headers['authentication-results']) {
              const authLower = auth.toLowerCase();
              if (authLower.includes('arc=pass') || authLower.includes('compauth=pass')) {
                return { 
                  status: 'pass', 
                  message: 'ARC chain valid (forwarded securely)',
                  value: arcValue?.substring(0, 100) + '...'
                };
              } else if (authLower.includes('arc=fail')) {
                return { 
                  status: 'fail', 
                  message: 'ARC chain broken',
                  value: arcValue?.substring(0, 100) + '...'
                };
              }
            }
          }
          return { 
            status: 'warning', 
            message: 'ARC present but status unclear',
            value: arcValue?.substring(0, 100) + '...'
          };
        }
        return { status: 'none', message: 'No ARC chain found', value: null };
    }
  };

  const detectSpamScore = (headers) => {
    // Check X-Spam-Score header
    if (headers['x-spam-score']) {
      const scoreStr = headers['x-spam-score'][0];
      const score = parseFloat(scoreStr);
      
      if (score >= 5) {
        return { level: 'high', score, message: 'High spam likelihood' };
      } else if (score >= 2) {
        return { level: 'medium', score, message: 'Moderate spam indicators' };
      } else if (score > 0) {
        return { level: 'low', score, message: 'Low spam score' };
      }
      return { level: 'none', score: 0, message: 'No spam indicators' };
    }

    // Check X-Spam-Status header
    if (headers['x-spam-status']) {
      const status = headers['x-spam-status'][0];
      const scoreMatch = status.match(/score=([-\d.]+)/i);
      if (scoreMatch) {
        const score = parseFloat(scoreMatch[1]);
        if (score >= 5) {
          return { level: 'high', score, message: 'High spam likelihood' };
        } else if (score >= 2) {
          return { level: 'medium', score, message: 'Moderate spam indicators' };
        } else if (score > 0) {
          return { level: 'low', score, message: 'Low spam score' };
        }
      }
    }
    
    return { level: 'none', score: 0, message: 'No spam indicators' };
  };

  const extractRouting = (headers) => {
    if (!headers['received']) return [];
    
    // Reverse to show chronological order (oldest first)
    // Don't truncate - show full routing information
    const hops = [...headers['received']].reverse().slice(0, 5);
    return hops.map(hop => hop.trim());
  };

  const calculateOverall = (analysis) => {
    if (analysis.spf.status === 'fail' || analysis.dkim.status === 'fail' || 
        analysis.dmarc.status === 'fail' || analysis.spamScore.level === 'high') {
      return 'bad';
    }
    if (analysis.spf.status === 'pass' && analysis.dkim.status === 'pass' && 
        analysis.dmarc.status === 'pass' && analysis.spamScore.level === 'none') {
      return 'good';
    }
    return 'warning';
  };

  // File Processing Functions
  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const fileName = file.name.toLowerCase();
    
    if (fileName.endsWith('.eml')) {
      await processEMLFile(file);
    } else if (fileName.endsWith('.msg')) {
      await processMSGFile(file);
    } else {
      alert('Please upload a .eml or .msg file');
    }
  };

  const processEMLFile = async (file) => {
    try {
      const text = await file.text();
      const parser = new PostalMime();
      const email = await parser.parse(text);
      
      // Convert PostalMime headers to simple object
      const simpleHeaders = {};
      if (email.headers) {
        email.headers.forEach(header => {
          const key = header.key.toLowerCase();
          if (!simpleHeaders[key]) simpleHeaders[key] = [];
          simpleHeaders[key].push(header.value);
        });
      }
      
      const processedData = {
        from: email.from?.address || 'Unknown',
        to: email.to?.map(t => t.address).join(', ') || 'Unknown',
        subject: email.subject || 'No Subject',
        date: email.date || 'Unknown',
        headers: simpleHeaders,
        html: email.html || '',
        text: email.text || '',
        attachments: email.attachments || []
      };

      setEmailData(processedData);
      setFileType('eml');
      
      // Auto-populate headers tab using array format
      const headerText = Object.entries(simpleHeaders)
        .map(([key, values]) => values.map(v => `${key}: ${v}`).join('\n'))
        .join('\n');
      setHeaderInput(headerText);
      setAutoAnalyze(true);
    } catch (error) {
      console.error('EML parsing error:', error);
      alert('Error processing EML file: ' + error.message);
    }
  };

  const processMSGFile = async (file) => {
    try {
      const arrayBuffer = await file.arrayBuffer();
      const msgReader = new MSGReader(arrayBuffer);
      const fileData = msgReader.getFileData();
      
      // Parse MSG headers into array format
      const headers = {};
      if (fileData.headers) {
        const headerLines = fileData.headers.split(/\r?\n/);
        let currentHeader = null;
        let currentValue = '';
        
        headerLines.forEach(line => {
          if (line.match(/^[\w-]+:/)) {
            if (currentHeader) {
              if (!headers[currentHeader]) headers[currentHeader] = [];
              headers[currentHeader].push(currentValue.trim());
            }
            const colonIndex = line.indexOf(':');
            currentHeader = line.substring(0, colonIndex).trim().toLowerCase();
            currentValue = line.substring(colonIndex + 1);
          } else if (currentHeader && (line.startsWith(' ') || line.startsWith('\t'))) {
            currentValue += ' ' + line.trim();
          }
        });
        if (currentHeader) {
          if (!headers[currentHeader]) headers[currentHeader] = [];
          headers[currentHeader].push(currentValue.trim());
        }
      }

      const recipientList = fileData.recipients?.map(r => {
        if (r.email) return r.email;
        if (r.name) return r.name;
        return 'Unknown';
      }).join(', ') || 'Unknown';

      const senderInfo = fileData.senderEmail 
        ? `${fileData.senderName || ''} <${fileData.senderEmail}>`.trim()
        : fileData.senderName || 'Unknown';

      // Extract attachments with actual data
      const attachments = (fileData.attachments || []).map(att => {
        try {
          const attachmentData = msgReader.getAttachment(att);
          return {
            filename: attachmentData.fileName || att.fileName || att.fileNameShort || 'Unknown',
            size: attachmentData.content?.byteLength || att.contentLength || 0,
            mimeType: attachmentData.mimeType || 'application/octet-stream',
            content: attachmentData.content, // The actual binary data
            dataId: att.dataId
          };
        } catch (err) {
          console.error('Error extracting attachment:', err);
          return {
            filename: att.fileName || att.fileNameShort || 'Unknown',
            size: att.contentLength || 0,
            mimeType: 'application/octet-stream',
            content: null,
            dataId: att.dataId
          };
        }
      });

      const processedData = {
        from: senderInfo,
        to: recipientList,
        subject: fileData.subject || 'No Subject',
        date: fileData.creationTime || fileData.lastModificationTime || 'Unknown',
        headers: headers,
        html: fileData.body || '',
        text: fileData.body?.replace(/<[^>]*>/g, '') || '',
        attachments: attachments
      };

      setEmailData(processedData);
      setFileType('msg');
      
      // Auto-populate headers tab using array format
      const headerText = Object.entries(headers)
        .map(([key, values]) => values.map(v => `${key}: ${v}`).join('\n'))
        .join('\n');
      setHeaderInput(headerText);
      setAutoAnalyze(true);
    } catch (error) {
      console.error('MSG parsing error:', error);
      alert('Error processing MSG file: ' + error.message);
    }
  };

  const getStatusIcon = (status) => {
    switch(status) {
      case 'pass': return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'fail': return <XCircle className="w-5 h-5 text-red-500" />;
      case 'warning': return <AlertCircle className="w-5 h-5 text-yellow-500" />;
      default: return <AlertCircle className="w-5 h-5 text-gray-400" />;
    }
  };

  const getOverallBadge = (overall) => {
    const badges = {
      good: { bg: 'bg-green-100', text: 'text-green-800', label: 'Looks Good' },
      warning: { bg: 'bg-yellow-100', text: 'text-yellow-800', label: 'Be Cautious' },
      bad: { bg: 'bg-red-100', text: 'text-red-800', label: 'Likely Spam' }
    };
    const badge = badges[overall] || { bg: 'bg-gray-100', text: 'text-gray-800', label: 'Unknown' };
    return (
      <div className={`${badge.bg} ${badge.text} px-4 py-2 rounded-lg font-semibold text-lg`}>
        {badge.label}
      </div>
    );
  };

  // Download attachment function
  const DANGEROUS_EXTENSIONS = [
    'exe', 'bat', 'cmd', 'com', 'msi', 'ps1', 'psm1', 'psd1',
    'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'hta', 'scr',
    'pif', 'reg', 'lnk', 'jar', 'sh', 'bash', 'zsh', 'py',
    'rb', 'pl', 'php', 'asp', 'aspx', 'cpl', 'inf', 'sys',
    'dll', 'ocx', 'iso', 'img', 'dmg', 'apk', 'ipa'
  ];

  const downloadAttachment = (attachment) => {
    try {
      const filename = attachment.filename || '';
      const ext = filename.split('.').pop()?.toLowerCase() || '';
      if (DANGEROUS_EXTENSIONS.includes(ext)) {
        const confirmed = window.confirm(
          `⚠️ Warning: "${filename}" has a potentially dangerous file type (.${ext}).

` +
          `This type of file can execute code on your computer and may be malicious.

` +
          `Only proceed if you trust the source of this email.

Download anyway?`
        );
        if (!confirmed) return;
      }

      let blob;
      
      // Handle different attachment formats
      if (attachment.content) {
        // Has binary content (from both EML and MSG)
        blob = new Blob([attachment.content], { 
          type: attachment.mimeType || 'application/octet-stream' 
        });
      } else {
        alert('Attachment data not available for download');
        return;
      }
      
      // Create download link
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = attachment.filename || 'attachment';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Download error:', error);
      alert('Error downloading attachment: ' + error.message);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-8">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-3">
            <Shield className="w-10 h-10 text-indigo-600" />
            <h1 className="text-4xl font-bold text-gray-800">Email Security Analyser</h1>
          </div>
          <p className="text-gray-600">Analyse headers, read EML/MSG files, and detect spam</p>
        </div>

        <div className="bg-white rounded-lg shadow-lg mb-6">
          <div className="flex border-b">
            <button
              onClick={() => setActiveTab('headers')}
              className={`flex-1 py-4 px-6 font-semibold transition-colors ${
                activeTab === 'headers'
                  ? 'bg-indigo-600 text-white'
                  : 'bg-gray-50 text-gray-600 hover:bg-gray-100'
              }`}
            >
              <div className="flex items-center justify-center gap-2">
                <Shield className="w-5 h-5" />
                Header Analyser
              </div>
            </button>
            <button
              onClick={() => setActiveTab('files')}
              className={`flex-1 py-4 px-6 font-semibold transition-colors ${
                activeTab === 'files'
                  ? 'bg-indigo-600 text-white'
                  : 'bg-gray-50 text-gray-600 hover:bg-gray-100'
              }`}
            >
              <div className="flex items-center justify-center gap-2">
                <Mail className="w-5 h-5" />
                EML/MSG Reader
              </div>
            </button>
          </div>

          <div className="p-6">
            {activeTab === 'headers' && (
              <div className="space-y-6">
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-2">
                    Paste Email Headers
                  </label>
                  <textarea
                    value={headerInput}
                    onChange={(e) => setHeaderInput(e.target.value)}
                    className="w-full h-64 p-4 border-2 border-gray-300 rounded-lg font-mono text-sm focus:border-indigo-500 focus:outline-none"
                    placeholder="Paste email headers here..."
                  />
                </div>
                <button
                  onClick={analyzeHeaders}
                  className="w-full bg-indigo-600 text-white py-3 rounded-lg font-semibold hover:bg-indigo-700 transition-colors"
                >
                  Analyse Headers
                </button>

                {headerAnalysis && (
                  <div className="space-y-6 mt-8">
                    <div className="flex items-center justify-between p-6 bg-gradient-to-r from-indigo-50 to-purple-50 rounded-lg">
                      <h3 className="text-xl font-bold text-gray-800">Overall Assessment</h3>
                      {getOverallBadge(headerAnalysis.overall)}
                    </div>

                    <div className="grid md:grid-cols-2 gap-4">
                      {['spf', 'dkim', 'dmarc', 'arc'].map(auth => (
                        <div key={auth} className="bg-white border-2 border-gray-200 rounded-lg p-4">
                          <div className="flex items-center gap-3 mb-2">
                            {getStatusIcon(headerAnalysis[auth].status)}
                            <h4 className="font-bold text-gray-800 uppercase">{auth}</h4>
                          </div>
                          <p className="text-sm text-gray-600 mb-2">{headerAnalysis[auth].message}</p>
                          {headerAnalysis[auth].value && (
                            <div className="mt-2 p-2 bg-gray-50 rounded border border-gray-200">
                              <p className="text-xs font-mono text-gray-600 break-all">
                                {headerAnalysis[auth].value}
                              </p>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>

                    <div className="bg-white border-2 border-gray-200 rounded-lg p-4">
                      <h4 className="font-bold text-gray-800 mb-2 flex items-center gap-2">
                        <AlertCircle className="w-5 h-5" />
                        Spam Score
                      </h4>
                      <p className="text-sm text-gray-600">
                        {headerAnalysis.spamScore.message} 
                        {headerAnalysis.spamScore.score > 0 && ` (Score: ${headerAnalysis.spamScore.score})`}
                      </p>
                    </div>

                    {headerAnalysis.routing.length > 0 && (
                      <div className="bg-white border-2 border-gray-200 rounded-lg p-4">
                        <h4 className="font-bold text-gray-800 mb-3">Email Routing ({headerAnalysis.routing.length} hops)</h4>
                        <p className="text-sm text-gray-600 mb-3">
                          Email passed through {headerAnalysis.routing.length} mail servers. Shows the path from sender to recipient.
                        </p>
                        <div className="space-y-3">
                          {headerAnalysis.routing.map((hop, i) => (
                            <div key={i} className="p-3 bg-gray-50 rounded border border-gray-200">
                              <div className="flex items-center gap-2 mb-2">
                                <span className="bg-indigo-100 text-indigo-800 px-2 py-1 rounded text-xs font-bold">
                                  Hop {i + 1}
                                </span>
                              </div>
                              <p className="text-xs font-mono text-gray-600 break-all whitespace-pre-wrap">{hop}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {activeTab === 'files' && (
              <div className="space-y-6">
                <div className="border-4 border-dashed border-gray-300 rounded-lg p-12 text-center hover:border-indigo-400 transition-colors">
                  <Upload className="w-16 h-16 mx-auto text-gray-400 mb-4" />
                  <label className="cursor-pointer">
                    <span className="text-lg font-semibold text-indigo-600 hover:text-indigo-700">
                      Choose EML or MSG file
                    </span>
                    <input
                      type="file"
                      accept=".eml,.msg"
                      onChange={handleFileUpload}
                      className="hidden"
                    />
                  </label>
                  <p className="text-sm text-gray-500 mt-2">
                    Supports .eml (all platforms) and .msg (Outlook) files
                  </p>
                </div>

                {emailData && (
                  <div className="space-y-6">
                    <div className="bg-gradient-to-r from-indigo-50 to-purple-50 rounded-lg p-6">
                      <div className="flex items-center gap-2 mb-4">
                        <FileText className="w-6 h-6 text-indigo-600" />
                        <h3 className="text-xl font-bold text-gray-800">
                          Email Details ({fileType.toUpperCase()})
                        </h3>
                      </div>
                      <div className="grid md:grid-cols-2 gap-4 text-sm">
                        <div>
                          <span className="font-semibold text-gray-700">From:</span>
                          <p className="text-gray-600">{emailData.from}</p>
                        </div>
                        <div>
                          <span className="font-semibold text-gray-700">To:</span>
                          <p className="text-gray-600">{emailData.to}</p>
                        </div>
                        <div className="md:col-span-2">
                          <span className="font-semibold text-gray-700">Subject:</span>
                          <p className="text-gray-600">{emailData.subject}</p>
                        </div>
                        <div>
                          <span className="font-semibold text-gray-700">Date:</span>
                          <p className="text-gray-600">{emailData.date}</p>
                        </div>
                      </div>
                    </div>

                    <div className="bg-white border-2 border-gray-200 rounded-lg p-6">
                      <h4 className="font-bold text-gray-800 mb-3">Email Content</h4>
                      <div className="bg-gray-50 p-4 rounded-lg max-h-96 overflow-y-auto">
                        {emailData.html ? (
                          <div dangerouslySetInnerHTML={{ __html: emailData.html }} />
                        ) : (
                          <pre className="whitespace-pre-wrap text-sm">{emailData.text}</pre>
                        )}
                      </div>
                    </div>

                    {emailData.attachments.length > 0 && (
                      <div className="bg-white border-2 border-gray-200 rounded-lg p-6">
                        <h4 className="font-bold text-gray-800 mb-3">
                          Attachments ({emailData.attachments.length})
                        </h4>
                        <div className="space-y-2">
                          {emailData.attachments.map((att, i) => (
                            <div key={i} className="flex items-center justify-between gap-3 p-3 bg-gray-50 rounded-lg border border-gray-200 hover:bg-gray-100 transition-colors">
                              <div className="flex items-center gap-3 flex-1 min-w-0">
                                <FileText className="w-5 h-5 text-gray-500 flex-shrink-0" />
                                <div className="flex-1 min-w-0">
                                  <span className="text-sm font-medium block truncate">{att.filename || `Attachment ${i + 1}`}</span>
                                  <span className="text-xs text-gray-500">
                                    {att.mimeType && `${att.mimeType} • `}
                                    {att.size ? `${(att.size / 1024).toFixed(1)} KB` : att.content?.byteLength ? `${(att.content.byteLength / 1024).toFixed(1)} KB` : ''}
                                  </span>
                                </div>
                              </div>
                              <button
                                onClick={() => downloadAttachment(att)}
                                className="flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors flex-shrink-0"
                                title="Download attachment"
                              >
                                <Upload className="w-4 h-4 rotate-180" />
                                <span className="text-sm font-medium">Download</span>
                              </button>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    <div className="bg-white border-2 border-gray-200 rounded-lg p-6">
                      <h4 className="font-bold text-gray-800 mb-3">All Headers</h4>
                      <div className="bg-gray-50 p-4 rounded-lg max-h-64 overflow-y-auto">
                        <pre className="text-xs font-mono whitespace-pre-wrap">
                          {Object.entries(emailData.headers)
                            .map(([key, values]) => values.map(v => `${key}: ${v}`).join('\n'))
                            .join('\n')}
                        </pre>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        <div className="text-center text-sm text-gray-600 space-y-1">
          <p>Email files are processed locally in your browser — file contents and attachments are never uploaded to any server.</p>
          <p className="text-gray-400 text-xs">Analysis metadata (IP address, From/To addresses, and authentication results) is logged for usage monitoring.</p>
        </div>
      </div>
    </div>
  );
};

export default EmailReader;
