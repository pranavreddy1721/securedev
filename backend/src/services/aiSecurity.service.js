const axios = require('axios');

const GEMINI_API_URL = 'https://generativelanguage.googleapis.com/v1beta/models';

function buildPrompt(finding) {
  return `You are a secure-coding assistant for a MERN application. Analyze this scanner finding conservatively.\n\nCategory: ${finding.category}\nSeverity: ${finding.severity}\nTitle: ${finding.title}\nDescription: ${finding.description || 'N/A'}\nFile: ${finding.file || 'N/A'}\nLine: ${finding.line || 'N/A'}\nOWASP: ${finding.owaspRef || 'N/A'}\nDetection engine: ${finding.engine}\n\nReturn ONLY valid JSON with this exact shape:\n{\n  "explanation": "short plain-English explanation of why this is a security concern",\n  "impact": "realistic security impact",\n  "remediation": "specific remediation steps for a MERN developer",\n  "codeExample": "short safe code example or an empty string when a code example is not appropriate",\n  "confidence": "high|medium|low"\n}\nDo not invent evidence that is not present in the finding. Clearly distinguish a heuristic indication from a confirmed vulnerability.`;
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
    // Be tolerant if the provider adds a short sentence around an otherwise
    // valid JSON object. The prompt still explicitly asks for JSON only.
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

async function analyzeFinding(finding) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    const error = new Error('AI assistance is not configured. Set GEMINI_API_KEY on the backend.');
    error.code = 'AI_NOT_CONFIGURED';
    error.statusCode = 503;
    throw error;
  }

  // Google currently documents Gemini 3.8 Flash for generateContent.
  // Keep GEMINI_MODEL configurable so Render can switch models without code changes.
  let model = String(process.env.GEMINI_MODEL || 'gemini-3.8-flash').trim();
  if (model.startsWith('models/')) model = model.slice('models/'.length);

  try {
    const response = await axios.post(
      `${GEMINI_API_URL}/${encodeURIComponent(model)}:generateContent`,
      {
        contents: [{ parts: [{ text: buildPrompt(finding) }] }],
        generationConfig: {
          responseMimeType: 'application/json',
          temperature: 0.2,
          maxOutputTokens: 1200,
        },
      },
      {
        timeout: Number(process.env.GEMINI_TIMEOUT_MS || 30000),
        headers: {
          'Content-Type': 'application/json',
          'x-goog-api-key': apiKey,
        },
      }
    );

    const candidate = response.data?.candidates?.[0];
    const text = candidate?.content?.parts?.map((part) => part.text || '').join('').trim() || '';

    if (!text) {
      const finishReason = candidate?.finishReason || 'UNKNOWN';
      const error = new Error(`AI provider returned no text (finish reason: ${finishReason}).`);
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
    if (err.code === 'AI_EMPTY_RESPONSE' || err.code === 'AI_INVALID_RESPONSE') throw err;

    const statusCode = Number(err.response?.status) || 502;
    const message = providerErrorMessage(err);

    // Log the provider response without ever logging the API key.
    console.error(`[ai] Gemini request failed (${statusCode}) model=${model}: ${message}`);

    const error = new Error(`Gemini API error: ${message}`);
    error.code = 'AI_PROVIDER_ERROR';
    error.statusCode = statusCode;
    throw error;
  }
}

module.exports = { analyzeFinding, buildPrompt, parseJsonText };
