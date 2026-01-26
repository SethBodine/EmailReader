import React, { useState, useEffect, useCallback } from 'react';
import { Upload, AlertCircle, CheckCircle, XCircle, Mail, FileText, Shield } from 'lucide-react';
import PostalMime from 'postal-mime';
import MSGReader from '@kenjiuno/msgreader';
import { Buffer } from 'buffer';

// Make Buffer available globally for MSGReader
window.Buffer = Buffer;

const EmailReader = () => {
  const [activeTab, setActiveTab] = useState('headers');
  const [headerInput, setHeaderInput] = useState('');
  const [headerAnalysis, setHeaderAnalysis] = useState(null);
  const [emailData, setEmailData] = useState(null);
  const [fileType, setFileType] = useState(null);
  const [autoAnalyze, setAutoAnalyze] = useState(false);

  // Auto-analyze when headers are populated from file upload
  useEffect(() => {
    if (autoAnalyze && headerInput) {
      analyzeHeaders();
      setAutoAnalyze(false);
    }
  }, [autoAnalyze]);

  // Header Analysis Functions
  const analyzeHeaders = useCallback(() => {
    if (!headerInput.trim()) {
      alert('Please paste email headers first');
      return;
    }

    const lines = headerInput.split(/\r?\n/);
    const headers = {};
    
    let currentHeader = '';
    lines.forEach(line => {
      // Skip empty lines
      if (!line.trim()) return;
      
      if (line.match(/^[\w-]+:/)) {
        const match = line.match(/^([\w-]+):\s*(.*)$/);
        if (match) {
          currentHeader = match[1].toLowerCase();
          // If header already exists, convert to array
          if (headers[currentHeader]) {
            if (Array.isArray(headers[currentHeader])) {
              headers[currentHeader].push(match[2]);
            } else {
              headers[currentHeader] = [headers[currentHeader], match[2]];
            }
          } else {
            headers[currentHeader] = match[2];
          }
        }
      } else if (currentHeader && (line.startsWith(' ') || line.startsWith('\t'))) {
        // Continuation of previous header
        if (Array.isArray(headers[currentHeader])) {
          const lastIndex = headers[currentHeader].length - 1;
          headers[currentHeader][lastIndex] += ' ' + line.trim();
        } else {
          headers[currentHeader] += ' ' + line.trim();
        }
      }
    });

    console.log('Parsed headers:', headers); // Debug log

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
  }, [headerInput]);

  const analyzeAuth = (headers, type) => {
    const authResults = headers['authentication-results'] || '';
    const received = headers['received-spf'] || '';
    
    switch(type) {
      case 'spf':
        if (authResults.includes('spf=pass') || received.includes('Pass')) {
          return { status: 'pass', message: 'SPF verification passed' };
        } else if (authResults.includes('spf=fail') || received.includes('Fail')) {
          return { status: 'fail', message: 'SPF verification failed - sender not authorised' };
        } else if (authResults.includes('spf=softfail')) {
          return { status: 'warning', message: 'SPF soft fail - questionable sender' };
        }
        return { status: 'none', message: 'No SPF record found' };
      
      case 'dkim':
        if (authResults.includes('dkim=pass')) {
          return { status: 'pass', message: 'DKIM signature valid' };
        } else if (authResults.includes('dkim=fail')) {
          return { status: 'fail', message: 'DKIM signature invalid - message may be altered' };
        }
        return { status: 'none', message: 'No DKIM signature found' };
      
      case 'dmarc':
        if (authResults.includes('dmarc=pass')) {
          return { status: 'pass', message: 'DMARC policy satisfied' };
        } else if (authResults.includes('dmarc=fail')) {
          return { status: 'fail', message: 'DMARC policy not satisfied' };
        }
        return { status: 'none', message: 'No DMARC policy found' };
      
      case 'arc':
        if (authResults.includes('arc=pass')) {
          return { status: 'pass', message: 'ARC chain valid (forwarded securely)' };
        } else if (authResults.includes('arc=fail')) {
          return { status: 'fail', message: 'ARC chain broken' };
        }
        return { status: 'none', message: 'No ARC chain found' };
    }
  };

  const detectSpamScore = (headers) => {
    const spamScore = headers['x-spam-score'] || headers['x-spam-status'] || '';
    const score = parseFloat(spamScore.match(/score=([\d.]+)/)?.[1] || '0');
    
    if (score >= 5) {
      return { level: 'high', score, message: 'High spam likelihood' };
    } else if (score >= 2) {
      return { level: 'medium', score, message: 'Moderate spam indicators' };
    } else if (score > 0) {
      return { level: 'low', score, message: 'Low spam score' };
    }
    return { level: 'none', score: 0, message: 'No spam indicators' };
  };

  const extractRouting = (headers) => {
    const received = headers['received'] || '';
    
    // Handle both string and array received headers
    let receivedText = '';
    if (Array.isArray(received)) {
      receivedText = received.join('\nReceived: ');
    } else {
      receivedText = received;
    }
    
    const hops = receivedText.split(/Received:/i).filter(r => r.trim()).slice(0, 5);
    return hops.map(hop => hop.trim().substring(0, 100) + '...');
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
      
      // Convert PostalMime headers format to simple key-value pairs
      const simpleHeaders = {};
      if (email.headers) {
        email.headers.forEach(header => {
          const key = header.key.toLowerCase();
          const value = header.value;
          
          // If header already exists, convert to array
          if (simpleHeaders[key]) {
            if (Array.isArray(simpleHeaders[key])) {
              simpleHeaders[key].push(value);
            } else {
              simpleHeaders[key] = [simpleHeaders[key], value];
            }
          } else {
            simpleHeaders[key] = value;
          }
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
      
      // Auto-populate headers tab - convert header objects to strings
      const headerText = Object.entries(simpleHeaders)
        .map(([key, value]) => {
          // Handle array values (like multiple Received headers)
          if (Array.isArray(value)) {
            return value.map(v => `${key}: ${v}`).join('\n');
          }
          // Handle string values
          return `${key}: ${value}`;
        })
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
      
      // Extract headers from MSG - headers is a string with \r\n separators
      const headers = {};
      if (fileData.headers) {
        const headerLines = fileData.headers.split(/\r?\n/);
        let currentHeader = '';
        
        headerLines.forEach(line => {
          // Check if it's a new header (starts with a word followed by colon)
          if (line.match(/^[\w-]+:/)) {
            const match = line.match(/^([\w-]+):\s*(.*)$/);
            if (match) {
              currentHeader = match[1].toLowerCase();
              headers[currentHeader] = match[2];
            }
          } else if (currentHeader && (line.startsWith(' ') || line.startsWith('\t'))) {
            // Continuation of previous header
            headers[currentHeader] += ' ' + line.trim();
          }
        });
      }

      // Build recipient list from recipients array
      const recipientList = fileData.recipients?.map(r => {
        if (r.email) return r.email;
        if (r.name) return r.name;
        return 'Unknown';
      }).join(', ') || 'Unknown';

      // Construct sender info
      const senderInfo = fileData.senderEmail 
        ? `${fileData.senderName || ''} <${fileData.senderEmail}>`.trim()
        : fileData.senderName || 'Unknown';

      const processedData = {
        from: senderInfo,
        to: recipientList,
        subject: fileData.subject || 'No Subject',
        date: fileData.creationTime || fileData.lastModificationTime || 'Unknown',
        headers: headers,
        html: fileData.body || '',
        text: fileData.body?.replace(/<[^>]*>/g, '') || '',
        attachments: (fileData.attachments || []).map(att => ({
          filename: att.fileName || att.fileNameShort || 'Unknown',
          size: att.contentLength || 0,
          dataId: att.dataId
        }))
      };

      setEmailData(processedData);
      setFileType('msg');
      
      // Auto-populate headers tab - convert header objects to strings
      const headerText = Object.entries(headers)
        .map(([key, value]) => {
          // Handle array values
          if (Array.isArray(value)) {
            return value.map(v => `${key}: ${v}`).join('\n');
          }
          // Handle object values
          if (typeof value === 'object' && value !== null) {
            return `${key}: ${JSON.stringify(value)}`;
          }
          // Handle string values
          return `${key}: ${value}`;
        })
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

        {/* Tabs */}
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
            {/* Header Analysis Tab */}
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
                          <p className="text-sm text-gray-600">{headerAnalysis[auth].message}</p>
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
                        <h4 className="font-bold text-gray-800 mb-3">Email Routing</h4>
                        <div className="space-y-2">
                          {headerAnalysis.routing.map((hop, i) => (
                            <div key={i} className="text-xs font-mono bg-gray-50 p-2 rounded">
                              {hop}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* File Reader Tab */}
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
                            <div key={i} className="flex items-center gap-3 p-3 bg-gray-50 rounded-lg">
                              <FileText className="w-5 h-5 text-gray-500" />
                              <span className="text-sm font-medium">{att.filename || `Attachment ${i + 1}`}</span>
                              <span className="text-xs text-gray-500 ml-auto">
                                {att.size ? `${(att.size / 1024).toFixed(1)} KB` : ''}
                              </span>
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
                            .map(([key, value]) => {
                              // Handle array values
                              if (Array.isArray(value)) {
                                return value.map(v => `${key}: ${v}`).join('\n');
                              }
                              // Handle object values
                              if (typeof value === 'object' && value !== null) {
                                return `${key}: ${JSON.stringify(value)}`;
                              }
                              // Handle string values
                              return `${key}: ${value}`;
                            })
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

        <div className="text-center text-sm text-gray-600">
          <p>This tool processes files locally in your browser. No data is sent to any server.</p>
        </div>
      </div>
    </div>
  );
};

export default EmailReader;
