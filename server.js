const express = require('express');
const { NodeVM } = require('vm2');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy for Vercel
app.set('trust proxy', 1);

// CORS
app.use(cors());

// Rate limiting - applied early
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Body parsing middleware - simple and reliable
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.raw({ type: 'application/json', limit: '1mb' }));

// Enhanced JSON repair middleware for Make.com
app.use('/api/', (req, res, next) => {
  // Only process if body is a Buffer (raw body)
  if (Buffer.isBuffer(req.body)) {
    const bodyString = req.body.toString('utf8');
    console.log('Repairing malformed JSON from Make.com...');
    
    try {
      // Try standard JSON parse first
      req.body = JSON.parse(bodyString);
      console.log('Standard JSON repair successful');
      return next();
    } catch (error) {
      console.log('Standard parse failed, attempting emergency extraction...');
      
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
        
        // Extract timeout
        const timeoutMatch = bodyString.match(/"timeout"\s*:\s*(\d+)/);
        extractedBody.timeout = timeoutMatch ? parseInt(timeoutMatch[1]) : 5000;
        
        // Extract context
        let context = {};
        const contextMatch = bodyString.match(/"context"\s*:\s*({[\s\S]*?})(?=\s*[,}])/);
        if (contextMatch) {
          try {
            context = JSON.parse(contextMatch[1]);
            console.log('Context extracted:', Object.keys(context));
          } catch (contextError) {
            // Try to extract input field directly
            const inputMatch = bodyString.match(/"input"\s*:\s*({[\s\S]*?})(?=\s*[,}])/);
            if (inputMatch) {
              try {
                const inputValue = JSON.parse(inputMatch[1]);
                context = { input: inputValue };
                console.log('Input field extracted');
              } catch (inputError) {
                context = {};
              }
            }
          }
        }
        
        extractedBody.context = context;
        req.body = extractedBody;
        
        console.log('Emergency extraction successful');
        
      } catch (extractionError) {
        console.error('All JSON parsing failed:', extractionError);
        return res.status(400).json({
          error: 'Invalid JSON',
          message: 'Could not parse request body',
          timestamp: new Date().toISOString()
        });
      }
    }
  }
  
  next();
});

// API Key authentication middleware
const authenticateApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || req.query.api_key;
  
  if (!apiKey) {
    return res.status(401).json({ 
      error: 'API key required',
      message: 'Please provide an API key in the X-API-Key header or api_key query parameter'
    });
  }
  
  const validApiKeys = process.env.VALID_API_KEYS?.split(',') || [
    'demo-key-123', 
    'js-exec-7K9mP3nR8vW2qL5xY1zC4tA6'
  ];
  
  if (!validApiKeys.includes(apiKey)) {
    return res.status(401).json({ 
      error: 'Invalid API key',
      message: 'The provided API key is not valid'
    });
  }
  
  next();
};

// FIXED: JavaScript execution function defined BEFORE routes that use it
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
  
  // Clean up line breaks
  const cleanCode = code.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  
  // Create secure sandbox
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
    let executableCode = cleanCode.trim();
    
    // Handle simple expressions
    if (!executableCode.includes(';') && !executableCode.includes('\n') && 
        !executableCode.match(/^(var|let|const|if|for|while|function|console\.|{)/)) {
      executableCode = `return (${executableCode});`;
    } else {
      // Check for explicit return
      const hasExplicitReturn = /^(?:(?!function)[\s\S])*?^[ \t]*return\s+/m.test(executableCode);
      
      if (!hasExplicitReturn) {
        const lines = executableCode.split('\n').map(line => line.trim()).filter(line => line && !line.startsWith('//'));
        
        if (lines.length > 0) {
          const lastLine = lines[lines.length - 1];
          
          // Check if last line is a simple expression
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
            // Wrap in IIFE
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
  
  // Serialize result
  let serializedResult;
  try {
    serializedResult = JSON.parse(JSON.stringify(result));
  } catch (serializationError) {
    serializedResult = String(result);
  }
  
  console.log('=== EXECUTION COMPLETE ===');
  console.log('Execution time:', executionTime + 'ms');
  
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
    return await executeJavaScript(code, timeout, context, res);
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

// Query parameter endpoint (Make.com workaround)
app.get('/api/execute-query', authenticateApiKey, async (req, res) => {
  try {
    const { code, timeout = 5000, input_data } = req.query;
    
    console.log('=== QUERY EXECUTION ===');
    console.log('Code length:', code ? code.length : 0);
    
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
        console.log('Input parsing failed:', parseError.message);
        context.input = input_data;
      }
    }
    
    const decodedCode = decodeURIComponent(code);
    return await executeJavaScript(decodedCode, parseInt(timeout), context, res);
    
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

// Form data endpoint (Make.com workaround)
app.post('/api/execute-form', authenticateApiKey, async (req, res) => {
  try {
    const { code, timeout = 5000, input_data } = req.body;
    
    console.log('=== FORM EXECUTION ===');
    console.log('Code length:', code ? code.length : 0);
    
    if (!code) {
      return res.status(400).json({
        error: 'Missing code parameter',
        message: 'Please provide JavaScript code'
      });
    }
    
    let context = {};
    if (input_data) {
      try {
        context.input = JSON.parse(input_data);
        console.log('Form input parsed successfully');
      } catch (parseError) {
        console.log('Form input parsing failed:', parseError.message);
        context.input = input_data;
      }
    }
    
    return await executeJavaScript(code, parseInt(timeout), context, res);
    
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

// Function execution endpoint
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
        return vm.run(`Math.${expression}`);
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
      example: { expression: 'sqrt(16) + 5' }
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

// Global error handling middleware
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
