const axios = require('axios');

const GEMINI_API_URL = 'https://generativelanguage.googleapis.com/v1beta/interactions';

const RESPONSE_SCHEMA = {
  type: 'object',
  properties: {
    explanation: { type: 'string' },
    impact: { type: 'string' },
    remediation: { type: 'string' },
    codeExample: { type: 'string' },
    confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
  },
  required: ['explanation', 'impact', 'remediation', 'codeExample', 'confidence'],
  additionalProperties: false,
};

function buildPrompt(finding) {
  return `You are a secure-coding assistant for a MERN application. Analyze this scanner finding conservatively.

Category: ${finding.category}
Severity: ${finding.severity}
Title: ${finding.title}
Description: ${finding.description || 'N/A'}
File: ${finding.file || 'N/A'}
Line: ${finding.line || 'N/A'}
OWASP: ${finding.owaspRef || 'N/A'}
Detection engine: ${finding.engine || 'N/A'}

Explain only what can reasonably be concluded from the supplied finding. Do not invent evidence. If the scanner result is heuristic, make that clear. Give practical remediation guidance for a MERN developer. Keep the response concise.`;
}

function parseJsonText(text) {
  const raw = String(text || '').trim();
  const cleaned = raw
    .replace(/^```(?:json)?\s*/i, '')
    .replace(/\s*```$/i, '')
    .trim();

  try {
    return JSON.parse(cleaned);
  } catch (_) {
    const start = cleaned.indexOf('{');
    const end = cleaned.lastIndexOf('}');
    if (start >= 0 && end > start) return JSON.parse(cleaned.slice(start, end + 1));
    throw new Error('AI provider returned invalid JSON.');
  }
}

function providerErrorMessage(err) {
  const data = err.response?.data;
  return (
    data?.error?.message ||
    data?.error?.status ||
    data?.message ||
    err.message ||
    'Unknown AI provider error'
  );
}

function extractOutputText(data) {
  // Interactions API responses currently expose model output in `steps`.
  const stepText = Array.isArray(data?.steps)
    ? data.steps
        .filter((step) => step?.type === 'model_output')
        .flatMap((step) => Array.isArray(step.content) ? step.content : [])
        .filter((part) => part?.type === 'text')
        .map((part) => part.text || '')
        .join('')
        .trim()
    : '';

  if (stepText) return stepText;

  // Keep compatibility with response shapes used by older Gemini endpoints.
  const outputText = Array.isArray(data?.outputs)
    ? data.outputs
        .flatMap((output) => Array.isArray(output?.content) ? output.content : [])
        .filter((part) => part?.type === 'text')
        .map((part) => part.text || '')
        .join('')
        .trim()
    : '';

  if (outputText) return outputText;

  return String(data?.output_text || '').trim();
}

async function analyzeFinding(finding) {
  const apiKey = String(process.env.GEMINI_API_KEY || '').trim();
  if (!apiKey) {
    const error = new Error('AI assistance is not configured. Set GEMINI_API_KEY on the backend.');
    error.code = 'AI_NOT_CONFIGURED';
    error.statusCode = 503;
    throw error;
  }

  let model = String(process.env.GEMINI_MODEL || 'gemini-3.8-flash').trim();
  if (model.startsWith('models/')) model = model.slice('models/'.length);

  const payload = {
    model,
    input: buildPrompt(finding),
    store: false,
    response_format: {
      type: 'text',
      mime_type: 'application/json',
      schema: RESPONSE_SCHEMA,
    },
    generation_config: {
      temperature: 0.2,
      max_output_tokens: 1200,
    },
  };

  try {
    const response = await axios.post(GEMINI_API_URL, payload, {
      timeout: Number(process.env.GEMINI_TIMEOUT_MS || 60000),
      headers: {
        'Content-Type': 'application/json',
        'x-goog-api-key': apiKey,
        'x-goog-api-client': 'securedev/1.0',
      },
    });

    const text = extractOutputText(response.data);
    if (!text) {
      const status = response.data?.status || 'unknown';
      const error = new Error(`AI provider returned no text (status: ${status}).`);
      error.code = 'AI_EMPTY_RESPONSE';
      error.statusCode = 502;
      throw error;
    }

    let result;
    try {
      result = parseJsonText(text);
    } catch (parseErr) {
      const error = new Error(parseErr.message);
      error.code = 'AI_INVALID_RESPONSE';
      error.statusCode = 502;
      throw error;
    }

    return {
      explanation: String(result.explanation || ''),
      impact: String(result.impact || ''),
      remediation: String(result.remediation || ''),
      codeExample: String(result.codeExample || ''),
      confidence: ['high', 'medium', 'low'].includes(result.confidence) ? result.confidence : 'medium',
    };
  } catch (err) {
    if (
      err.code === 'AI_EMPTY_RESPONSE' ||
      err.code === 'AI_INVALID_RESPONSE' ||
      err.code === 'AI_NOT_CONFIGURED'
    ) {
      throw err;
    }

    // Axios network errors have no HTTP response. Preserve that distinction so
    // the UI gets a useful message instead of the generic "AI analysis failed".
    if (!err.response) {
      console.error(`[ai] Gemini network request failed code=${err.code || 'UNKNOWN'} message=${err.message}`);
      const error = new Error(`Unable to reach Gemini API: ${err.message}`);
      error.code = 'AI_NETWORK_ERROR';
      error.statusCode = 502;
      throw error;
    }

    const statusCode = Number(err.response.status) || 502;
    const message = providerErrorMessage(err);
    console.error(`[ai] Gemini request failed (${statusCode}) model=${model}: ${message}`);

    const error = new Error(`Gemini API error: ${message}`);
    error.code = 'AI_PROVIDER_ERROR';
    error.statusCode = statusCode;
    throw error;
  }
}

module.exports = { analyzeFinding, buildPrompt, parseJsonText };
