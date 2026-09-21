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

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function normalizeModel(value) {
  const model = String(value || '').trim();
  return model.startsWith('models/') ? model.slice('models/'.length) : model;
}

function getModelCandidates() {
  const primary = normalizeModel(process.env.GEMINI_MODEL || 'gemini-3.8-flash');
  const configuredFallbacks = String(
    process.env.GEMINI_FALLBACK_MODELS || 'gemini-3.7-flash,gemini-3.6-flash'
  )
    .split(',')
    .map(normalizeModel)
    .filter(Boolean);

  return [...new Set([primary, ...configuredFallbacks])];
}

function buildPrompt(finding) {
  return `You are a secure-coding assistant for a MERN application. Analyze this scanner finding conservatively.\n\nCategory: ${finding.category}\nSeverity: ${finding.severity}\nTitle: ${finding.title}\nDescription: ${finding.description || 'N/A'}\nFile: ${finding.file || 'N/A'}\nLine: ${finding.line || 'N/A'}\nOWASP: ${finding.owaspRef || 'N/A'}\nDetection engine: ${finding.engine || 'N/A'}\n\nExplain only what can reasonably be concluded from the supplied finding. Do not invent evidence. If the scanner result is heuristic, make that clear. Give practical remediation guidance for a MERN developer. Keep the response concise.`;
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
  // Interactions API returns model output in steps. Keep compatibility with
  // both the current step format and older output shapes.
  const stepText = Array.isArray(data?.steps)
    ? data.steps
        .filter((step) => step?.type === 'model_output')
        .flatMap((step) => (Array.isArray(step.content) ? step.content : []))
        .filter((part) => part?.type === 'text')
        .map((part) => part.text || '')
        .join('')
        .trim()
    : '';

  if (stepText) return stepText;

  const outputText = Array.isArray(data?.outputs)
    ? data.outputs
        .flatMap((output) => (Array.isArray(output?.content) ? output.content : []))
        .filter((part) => part?.type === 'text')
        .map((part) => part.text || '')
        .join('')
        .trim()
    : '';

  if (outputText) return outputText;

  return String(data?.output_text || '').trim();
}

function shouldRetry(statusCode) {
  return [429, 500, 502, 503, 504].includes(Number(statusCode));
}

async function requestGemini({ apiKey, model, input }) {
  const payload = {
    model,
    input,
    store: false,
    response_format: {
      type: 'text',
      mime_type: 'application/json',
      schema: RESPONSE_SCHEMA,
    },
    // Gemini 3.x uses thinking_level rather than the old temperature-style
    // controls. Low is enough for a focused single-finding explanation and
    // keeps latency/cost reasonable.
    generation_config: {
      thinking_level: 'low',
      max_output_tokens: 1200,
    },
  };

  const maxAttempts = 3;
  let lastError;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      return await axios.post(GEMINI_API_URL, payload, {
        timeout: Number(process.env.GEMINI_TIMEOUT_MS || 60000),
        headers: {
          'Content-Type': 'application/json',
          'x-goog-api-key': apiKey,
          'x-goog-api-client': 'securedev/1.0',
        },
      });
    } catch (err) {
      lastError = err;

      const statusCode = Number(err.response?.status || 0);
      if (!shouldRetry(statusCode) || attempt === maxAttempts) break;

      // Gemini documents exponential backoff for transient 429/5xx errors.
      const delay = Math.min(8000, 1000 * (2 ** (attempt - 1)));
      console.warn(`[ai] Gemini ${model} returned ${statusCode}; retrying in ${delay}ms (attempt ${attempt + 1}/${maxAttempts})`);
      await sleep(delay);
    }
  }

  throw lastError;
}

async function analyzeFinding(finding) {
  const apiKey = String(process.env.GEMINI_API_KEY || '').trim();
  if (!apiKey) {
    const error = new Error('AI assistance is not configured. Set GEMINI_API_KEY on the backend.');
    error.code = 'AI_NOT_CONFIGURED';
    error.statusCode = 503;
    throw error;
  }

  const models = getModelCandidates();
  const input = buildPrompt(finding);
  let lastProviderError = null;

  for (let modelIndex = 0; modelIndex < models.length; modelIndex += 1) {
    const model = models[modelIndex];

    try {
      const response = await requestGemini({ apiKey, model, input });
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

      if (!err.response) {
        console.error(`[ai] Gemini network request failed model=${model} code=${err.code || 'UNKNOWN'} message=${err.message}`);
        const error = new Error(`Unable to reach Gemini API: ${err.message}`);
        error.code = 'AI_NETWORK_ERROR';
        error.statusCode = 502;
        throw error;
      }

      const statusCode = Number(err.response.status) || 502;
      const message = providerErrorMessage(err);
      console.error(`[ai] Gemini request failed (${statusCode}) model=${model}: ${message}`);

      lastProviderError = { statusCode, message, model };

      // A 503 overloaded/high-demand response is transient. After retries on
      // the primary model, try a stable Flash fallback before giving up.
      // 429 is also retryable, but normally remains on the same key/quota and
      // is therefore not silently hidden from the caller unless a fallback works.
      if (modelIndex < models.length - 1 && [429, 500, 502, 503, 504].includes(statusCode)) {
        console.warn(`[ai] Falling back from ${model} to ${models[modelIndex + 1]} after provider status ${statusCode}`);
        continue;
      }

      break;
    }
  }

  const error = new Error(`Gemini API error: ${lastProviderError?.message || 'Unknown provider error'}`);
  error.code = 'AI_PROVIDER_ERROR';
  error.statusCode = lastProviderError?.statusCode || 502;
  throw error;
}

module.exports = { analyzeFinding, buildPrompt, parseJsonText };
