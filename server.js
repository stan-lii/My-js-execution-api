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

// FIXED: Proper middleware order and conflict resolution
app.use((req, res, next) => {
  if (!req.path.startsWith('/api/')) {
    return next();
  }
  
  express.json({ limit: '1mb' })(req, res, (err) => {
    if (err || !req.body) {
      console.log('Standard JSON failed, using raw parser...');
      express.raw({ type: 'application/json', limit: '1mb' })(req, res, next);
    } else {
      console.log('Standard JSON parsing successful');
      next();
    }
  });
});

// Enhanced Make.com JSON repair middleware
app.use('/api/', (req, res, next) => {
  if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
    console.log('Body already parsed, skipping repair');
    return next();
  }
  
  if (Buffer.isBuffer(req.body)) {
    const bodyString = req.body.toString('utf8');
    console.log('Attempting to repair malformed JSON from Make.com...');
    
    try {
      const extractedBody = {};
      
      // Extract code field
      const codeMatch = bodyString.match(/"code"\s*:\s*"((?:[^"\\]|\\.)*)"/);
      if (codeMatch) {
        extractedBody.code = codeMatch[1]
          .replace(/\\"/g, '"')
          .replace(/\\'/g, "'")
          .replace(/\\n/g, '\n')
          .replace(/\\r/g, '\r')
          .replace(/\\t/g, '\t')
          .replace(/\\\\/g, '\\');
      }
      
      // Extract timeout field
      const timeoutMatch = bodyString.match(/"timeout"\s*:\s*(\d+)/);
      extractedBody.timeout = timeoutMatch ? parseInt(timeoutMatch[1]) : 5000;
      
      // Extract context field
      let context = {};
      const contextMatch = bodyString.match(/"context"\s*:\s*({[\s\S]*?})(?=\s*[,}])/);
      if (contextMatch) {
        try {
          context = JSON.parse(contextMatch[1]);
          console.log('Context extracted successfully:', Object.keys(context));
        } catch (e) {
          console.log('Context parsing failed, trying input extraction...');
          const inputMatch = bodyString.match(/"input"\s*:\s*({[\s\S]*?})(?=\s*[,}])/);
          if (inputMatch) {
            try {
              const inputValue = JSON.parse(inputMatch[1]);
              context = { input: inputValue };
              console.log('Input extracted successfully');
            } catch (e2) {
              console.log('Input extraction failed, using empty context');
              context = {};
            }
          }
        }
      }
      
      extractedBody.context = context;
      req.body = extractedBody;
      
      console.log('Emergency extraction successful');
      console.log('Final context keys:', Object.keys(context));
      
    } catch (extractionError) {
      console.error('All parsing attempts failed:', extractionError);
      return res.status(400).json({
        error: 'Invalid JSON',
        message: 'Could not parse the malformed JSON from Make.com',
        suggestion: 'Use the Set Variable module in Make.com to store complex data',
        details: extractionError.message,
        timestamp: new Date().toISOString()
      });
    }
  }
  
  next();
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
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
  
  const validApiKeys = process.env.VALID_API_KEYS?.split(',') || ['demo-key-123'];
  
  if (!validApiKeys.includes(apiKey)) {
    return res.status(401).json({ 
      error: 'Invalid API key',
      message: 'The provided API key is not valid'
    });
  }
  
  next();
};

// Common JavaScript execution function
async function executeJavaScript(code, timeout = 5000, context = {}, res) {
  console.log('=== EXECUTION REQUEST ===');
  console.log('Code length:', code ? code.length : 0);
  console.log('Timeout:', timeout);
  console.log('Context keys:', Object.keys(context));
  
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
  
  const cleanCode = code.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  
  const vm = new NodeVM({
    console: 'redirect',
    sandbox: context,
    timeout: Math.min(timeout, 10000),
    allowAsync: false,
    wrapper: 'none',
    strict: true
  });
  
  let output = [];
  let errors = [];
  
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
    let executableCode = cleanCode.trim();
    
    if (!executableCode.includes(';') && !executableCode.includes('\n') && 
        !executableCode.match(/^(var|let|const|if|for|while|function|console\.|{)/)) {
      executableCode = `return (${executableCode});`;
    } else {
      const hasExplicitReturn = /^(?:(?!function)[\s\S])*?^[ \t]*return\s+/m.test(executableCode);
      
      if (!hasExplicitReturn) {
        const lines = executableCode.split('\n').map(line => line.trim()).filter(line => line && !line.startsWith('//'));
        
        if (lines.length > 0) {
          const lastLine = lines[lines.length - 1];
          
          if (lastLine.match(/^[a-zA-Z_$][\w.$]*;?$/) ||
              lastLine.match(/^{[\s\S]*};?$/) ||
              lastLine.match(/^\[[\s\S]*\];?$/) ||
              lastLine.match(/^["'`][\s\S]*["'`];?$/) ||
              lastLine.match(/^\d+(\.\d+)?;?$/) ||
              lastLine.match(/^(true|false|null|undefined);?$/)) {
            
            const cleanLastLine = lastLine.replace(/;$/, '');
            const otherLines = lines.slice(0, -1);
            executableCode = [...otherLines, `return (${cleanLastLine});`].join('\n');
          } else {
            executableCode = `(() => { ${executableCode} })()`;
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
  
  let serializedResult;
  try {
    serializedResult = JSON.parse(JSON.stringify(result));
  } catch (serializationError) {
    serializedResult = String(result);
  }
  
  console.log('=== EXECUTION COMPLETE ===');
  console.log('Execution time:', executionTime + 'ms');
  console.log('Result type:', typeof result);
  console.log('Output messages:', output.length);
  
  res.json({
    success: true,
    result: serializedResult,
    output,
    errors,
    executionTime,
    timestamp: new Date().toISOString()
  });
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    version: '2.1.0'
  });
});

// Main JavaScript execution endpoint
app.post('/api/execute', authenticateApiKey, async (req, res) => {
  try {
    const { code, timeout = 5000, context = {} } = req.body;
    return executeJavaScript(code, timeout, context, res);
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

// Query parameter endpoint for Make.com compatibility
app.get('/api/execute-query', authenticateApiKey, async (req, res) => {
  try {
    const { code, timeout = 5000, input_data } = req.query;
    
    console.log('=== QUERY EXECUTION REQUEST ===');
    console.log('Code length:', code ? code.length : 0);
    console.log('Input data:', input_data ? 'provided' : 'none');
    
    if (!code) {
      return res.status(400).json({
        error: 'Missing code parameter',
        message: 'Please provide JavaScript code in the "code" query parameter'
      });
    }
    
    let context = {};
    if (input_data) {
      try {
        context.input = JSON.parse(decodeURIComponent(input_data));
        console.log('Input data parsed successfully');
      } catch (parseError) {
        console.log('Input data parsing failed:', parseError.message);
        context.input = input_data;
      }
    }
    
    const decodedCode = decodeURIComponent(code);
    return executeJavaScript(decodedCode, parseInt(timeout), context, res);
    
  } catch (error) {
    console.error('Query API Error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'An unexpected error occurred',
      details: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Form-encoded endpoint for Make.com compatibility
app.post('/api/execute-form', authenticateApiKey, express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const { code, timeout = 5000, input_data } = req.body;
    
    console.log('=== FORM EXECUTION REQUEST ===');
    console.log('Code length:', code ? code.length : 0);
    console.log('Input data:', input_data ? 'provided' : 'none');
    
    let context = {};
    if (input_data) {
      try {
        context.input = JSON.parse(input_data);
        console.log('Input data parsed successfully from form');
      } catch (parseError) {
        console.log('Input data parsing failed:', parseError.message);
        context.input = input_data;
      }
    }
    
    return executeJavaScript(code, parseInt(timeout), context, res);
    
  } catch (error) {
    console.error('Form API Error:', error);
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
    
    const functions = {
      calculate: (expression) => {
        const vm = new NodeVM({ timeout: 2000 });
        return vm.run(`const Math = require('math'); ${expression}`);
      },
      
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
      'GET /api/execute-query',
      'POST /api/execute-form', 
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
