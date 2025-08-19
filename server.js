const express = require('express');
const { NodeVM } = require('vm2');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy for Vercel
app.set('trust proxy', 1);

// Middleware
app.use(cors());

// Enhanced JSON parser specifically for Make.com compatibility
app.use('/api/', express.raw({ type: 'application/json', limit: '1mb' }));
app.use('/api/', (req, res, next) => {
  if (Buffer.isBuffer(req.body)) {
    const bodyString = req.body.toString('utf8');
    
    try {
      // Try standard JSON parsing first
      req.body = JSON.parse(bodyString);
      console.log('Standard JSON parsing successful');
    } catch (error) {
      console.log('Standard JSON parsing failed, attempting repair...');
      
      try {
        // Emergency extraction method - directly extract the code field
        // This handles cases where Make.com sends malformed JSON
        const codeMatch = bodyString.match(/"code"\s*:\s*"((?:[^"\\]|\\.)*)"/);
        const timeoutMatch = bodyString.match(/"timeout"\s*:\s*(\d+)/);
        
        if (codeMatch) {
          // Unescape the code string
          let code = codeMatch[1];
          // Handle escaped characters
          code = code.replace(/\\"/g, '"')
                    .replace(/\\'/g, "'")
                    .replace(/\\n/g, '\n')
                    .replace(/\\r/g, '\r')
                    .replace(/\\t/g, '\t')
                    .replace(/\\\\/g, '\\');
          
          req.body = {
            code: code,
            timeout: timeoutMatch ? parseInt(timeoutMatch[1]) : 5000,
            context: {}
          };
          
          console.log('Emergency extraction successful');
          console.log('Code length:', code.length);
        } else {
          // Try another extraction pattern for unescaped JSON
          // This handles cases where the code might not be properly quoted
          const startIdx = bodyString.indexOf('"code"');
          if (startIdx !== -1) {
            const colonIdx = bodyString.indexOf(':', startIdx);
            const openQuote = bodyString.indexOf('"', colonIdx);
            
            if (openQuote !== -1) {
              // Find the matching close quote, accounting for escaped quotes
              let closeQuote = -1;
              let i = openQuote + 1;
              while (i < bodyString.length) {
                if (bodyString[i] === '"' && bodyString[i-1] !== '\\') {
                  closeQuote = i;
                  break;
                }
                i++;
              }
              
              if (closeQuote !== -1) {
                let code = bodyString.substring(openQuote + 1, closeQuote);
                // Unescape
                code = code.replace(/\\"/g, '"')
                          .replace(/\\'/g, "'")
                          .replace(/\\n/g, '\n')
                          .replace(/\\r/g, '\r')
                          .replace(/\\t/g, '\t')
                          .replace(/\\\\/g, '\\');
                
                const timeoutMatch = bodyString.match(/"timeout"\s*:\s*(\d+)/);
                
                req.body = {
                  code: code,
                  timeout: timeoutMatch ? parseInt(timeoutMatch[1]) : 5000,
                  context: {}
                };
                
                console.log('Alternative extraction successful');
              } else {
                throw new Error('Could not find closing quote for code field');
              }
            } else {
              throw new Error('Could not find opening quote for code field');
            }
          } else {
            throw new Error('Could not find code field in request');
          }
        }
      } catch (extractionError) {
        console.error('All parsing attempts failed:', extractionError);
        
        // Last resort: try to be helpful with the error message
        return res.status(400).json({
          error: 'Invalid JSON',
          message: 'Could not parse the request. Make sure to properly escape quotes in your JavaScript code.',
          suggestion: 'In Make.com, try using single quotes instead of double quotes in your JavaScript code, or use the Set Variable module to store your code first.',
          details: extractionError.message,
          timestamp: new Date().toISOString()
        });
      }
    }
  } else if (typeof req.body === 'string') {
    // Handle string body (shouldn't happen with raw parser, but just in case)
    try {
      req.body = JSON.parse(req.body);
    } catch (error) {
      return res.status(400).json({
        error: 'Invalid JSON',
        message: 'Request body is not valid JSON',
        timestamp: new Date().toISOString()
      });
    }
  }
  
  next();
});

// Standard JSON parser for other routes
app.use(express.json({ limit: '1mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// API Key authentication middleware
const authenticateApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || req.query.api_key;
  
  if (!apiKey) {
    return res.status(401).json({ 
      error: 'API key required',
      message: 'Please provide an API key in the X-API-Key header or api_key query parameter'
    });
  }
  
  // In production, validate against a database or environment variable
  const validApiKeys = process.env.VALID_API_KEYS?.split(',') || ['demo-key-123'];
  
  if (!validApiKeys.includes(apiKey)) {
    return res.status(401).json({ 
      error: 'Invalid API key',
      message: 'The provided API key is not valid'
    });
  }
  
  next();
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    version: '1.1.0' // Updated version
  });
});

// JavaScript execution endpoint
app.post('/api/execute', authenticateApiKey, async (req, res) => {
  try {
    const { code, timeout = 5000, context = {} } = req.body;
    
    if (!code) {
      return res.status(400).json({
        error: 'Missing code parameter',
        message: 'Please provide JavaScript code to execute'
      });
    }
    
    if (typeof code !== 'string') {
      return res.status(400).json({
        error: 'Invalid code parameter',
        message: 'Code must be a string'
      });
    }
    
    if (code.length > 10000) {
      return res.status(400).json({
        error: 'Code too long',
        message: 'Code must be less than 10,000 characters'
      });
    }
    
    // Clean up line breaks - normalize all line breaks to \n
    const cleanCode = code.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    
    // Create a secure sandbox
    const vm = new NodeVM({
      console: 'redirect',
      sandbox: context,
      timeout: Math.min(timeout, 10000), // Max 10 seconds
      allowAsync: false,
      wrapper: 'none',
      strict: true
    });
    
    let output = [];
    let errors = [];
    
    // Capture console output
    vm.on('console.log', (...args) => {
      const message = args.map(arg => {
        if (typeof arg === 'object') {
          try {
            return JSON.stringify(arg);
          } catch {
            return String(arg);
          }
        }
        return String(arg);
      }).join(' ');
      output.push({ type: 'log', message });
    });
    
    vm.on('console.error', (...args) => {
      const message = args.map(arg => String(arg)).join(' ');
      errors.push({ type: 'error', message });
    });
    
    vm.on('console.warn', (...args) => {
      const message = args.map(arg => String(arg)).join(' ');
      output.push({ type: 'warn', message });
    });
    
    const startTime = Date.now();
    let result;
    
    try {
      // Smart code execution that handles various cases
      let executableCode = cleanCode.trim();
      
      // If it's a simple expression (no semicolons, no statements), wrap it
      if (!executableCode.includes(';') && !executableCode.includes('\n') && 
          !executableCode.match(/^(var|let|const|if|for|while|function|console\.|{)/)) {
        executableCode = `return (${executableCode});`;
      } else {
        // For multi-line code, intelligently determine how to execute it
        
        // First, try to detect if the code already has a return statement at the top level
        const hasExplicitReturn = /^(?:(?!function)[\s\S])*?^[ \t]*return\s+/m.test(executableCode);
        
        if (hasExplicitReturn) {
          // Code already has explicit return, execute as-is
          // No modification needed
        } else {
          // Try to identify what the last meaningful line is
          const lines = executableCode.split('\n').map(line => line.trim()).filter(line => line && !line.startsWith('//'));
          
          if (lines.length > 0) {
            const lastLine = lines[lines.length - 1];
            
            // If last line is a variable reference, object literal, or simple expression
            if (lastLine.match(/^[a-zA-Z_$][\w.$]*;?$/) ||           // variable or property access
                lastLine.match(/^{[\s\S]*};?$/) ||                   // object literal
                lastLine.match(/^\[[\s\S]*\];?$/) ||                 // array literal
                lastLine.match(/^["'`][\s\S]*["'`];?$/) ||           // string literal
                lastLine.match(/^\d+(\.\d+)?;?$/) ||                 // number literal
                lastLine.match(/^(true|false|null|undefined);?$/)) { // boolean/null/undefined
              
              // Remove semicolon if present and add return
              const cleanLastLine = lastLine.replace(/;$/, '');
              const otherLines = lines.slice(0, -1);
              executableCode = [...otherLines, `return (${cleanLastLine});`].join('\n');
            } else {
              // For complex expressions or statements, wrap everything in an IIFE
              executableCode = `
                (() => {
                  ${executableCode}
                })()
              `;
            }
          }
        }
      }
      
      result = vm.run(executableCode);
    } catch (vmError) {
      return res.status(400).json({
        error: 'Execution error',
        message: vmError.message,
        output,
        errors,
        executionTime: Date.now() - startTime
      });
    }
    
    const executionTime = Date.now() - startTime;
    
    // Serialize the result safely
    let serializedResult;
    try {
      serializedResult = JSON.parse(JSON.stringify(result));
    } catch (serializationError) {
      serializedResult = String(result);
    }
    
    res.json({
      success: true,
      result: serializedResult,
      output,
      errors,
      executionTime,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('API Error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'An unexpected error occurred',
      details: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Function execution endpoint with predefined functions
app.post('/api/function', authenticateApiKey, async (req, res) => {
  try {
    const { functionName, parameters = {}, timeout = 5000 } = req.body;
    
    if (!functionName) {
      return res.status(400).json({
        error: 'Missing functionName parameter',
        message: 'Please provide a function name to execute'
      });
    }
    
    // Predefined utility functions
    const functions = {
      // Math utilities
      calculate: (expression) => {
        const vm = new NodeVM({ timeout: 2000 });
        return vm.run(`
          const Math = require('math');
          ${expression}
        `);
      },
      
      // String manipulation
      transformText: (text, operation) => {
        const operations = {
          uppercase: (str) => str.toUpperCase(),
          lowercase: (str) => str.toLowerCase(),
          reverse: (str) => str.split('').reverse().join(''),
          removeSpaces: (str) => str.replace(/\s+/g, ''),
          capitalize: (str) => str.charAt(0).toUpperCase() + str.slice(1).toLowerCase(),
          slugify: (str) => str.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
        };
        
        return operations[operation] ? operations[operation](text) : text;
      },
      
      // Array utilities
      processArray: (array, operation) => {
        const operations = {
          sum: (arr) => arr.reduce((a, b) => a + b, 0),
          average: (arr) => arr.reduce((a, b) => a + b, 0) / arr.length,
          max: (arr) => Math.max(...arr),
          min: (arr) => Math.min(...arr),
          unique: (arr) => [...new Set(arr)],
          sort: (arr) => [...arr].sort(),
          reverse: (arr) => [...arr].reverse()
        };
        
        return operations[operation] ? operations[operation](array) : array;
      },
      
      // Date utilities
      formatDate: (date, format = 'ISO') => {
        const d = new Date(date);
        const formats = {
          ISO: () => d.toISOString(),
          US: () => d.toLocaleDateString('en-US'),
          EU: () => d.toLocaleDateString('en-GB'),
          timestamp: () => d.getTime(),
          readable: () => d.toLocaleDateString('en-US', { 
            year: 'numeric', 
            month: 'long', 
            day: 'numeric' 
          })
        };
        
        return formats[format] ? formats[format]() : d.toString();
      }
    };
    
    if (!functions[functionName]) {
      return res.status(400).json({
        error: 'Function not found',
        message: `Available functions: ${Object.keys(functions).join(', ')}`,
        availableFunctions: Object.keys(functions)
      });
    }
    
    const startTime = Date.now();
    const result = functions[functionName](...Object.values(parameters));
    const executionTime = Date.now() - startTime;
    
    res.json({
      success: true,
      functionName,
      parameters,
      result,
      executionTime,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    res.status(400).json({
      error: 'Function execution error',
      message: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// List available functions
app.get('/api/functions', authenticateApiKey, (req, res) => {
  const functions = {
    calculate: {
      description: 'Execute mathematical expressions',
      parameters: ['expression'],
      example: { expression: 'Math.sqrt(16) + 5' }
    },
    transformText: {
      description: 'Transform text using various operations',
      parameters: ['text', 'operation'],
      operations: ['uppercase', 'lowercase', 'reverse', 'removeSpaces', 'capitalize', 'slugify'],
      example: { text: 'Hello World', operation: 'uppercase' }
    },
    processArray: {
      description: 'Process arrays with various operations',
      parameters: ['array', 'operation'],
      operations: ['sum', 'average', 'max', 'min', 'unique', 'sort', 'reverse'],
      example: { array: [1, 2, 3, 4, 5], operation: 'sum' }
    },
    formatDate: {
      description: 'Format dates in various formats',
      parameters: ['date', 'format'],
      formats: ['ISO', 'US', 'EU', 'timestamp', 'readable'],
      example: { date: '2025-01-01', format: 'readable' }
    }
  };
  
  res.json({
    success: true,
    functions,
    totalFunctions: Object.keys(functions).length
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({
    error: 'Internal server error',
    message: 'An unexpected error occurred'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not found',
    message: 'The requested endpoint does not exist',
    availableEndpoints: [
      'GET /health',
      'POST /api/execute',
      'POST /api/function',
      'GET /api/functions'
    ]
  });
});

app.listen(PORT, () => {
  console.log(`🚀 JavaScript Execution API running on port ${PORT}`);
  console.log(`📝 Health check: http://localhost:${PORT}/health`);
  console.log(`🔧 API Documentation: http://localhost:${PORT}/api/functions`);
});

module.exports = app;
