const axios = require('axios');

const GEMINI_API_URL = 'https://generativelanguage.googleapis.com/v1beta/models';

function buildPrompt(finding) {
  return `You are a secure-coding assistant for a MERN application. Analyze this scanner finding conservatively.

Category: ${finding.category}
Severity: ${finding.severity}
Title: ${finding.title}
Description: ${finding.description || 'N/A'}
File: ${finding.file || 'N/A'}
Line: ${finding.line || 'N/A'}
OWASP: ${finding.owaspRef || 'N/A'}
Detection engine: ${finding.engine}

Return ONLY valid JSON with this exact shape:
{
  "explanation": "short plain-English explanation of why this is a security concern",
  "impact": "realistic security impact",
  "remediation": "specific remediation steps for a MERN developer",
  "codeExample": "short safe code example or an empty string when a code example is not appropriate",
  "confidence": "high|medium|low"
}
Do not invent evidence that is not present in the finding. Clearly distinguish a heuristic indication from a confirmed vulnerability.`;
}

function parseJsonText(text) {
  const cleaned = String(text || '').replace(/^```json\s*/i, '').replace(/\s*```$/i, '').trim();
  return JSON.parse(cleaned);
}

async function analyzeFinding(finding) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    const error = new Error('AI assistance is not configured. Set GEMINI_API_KEY on the backend.');
    error.code = 'AI_NOT_CONFIGURED';
    throw error;
  }

  const model = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
  const response = await axios.post(
    `${GEMINI_API_URL}/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`,
    {
      contents: [{ parts: [{ text: buildPrompt(finding) }] }],
      generationConfig: { temperature: 0.1, responseMimeType: 'application/json' },
    },
    { timeout: Number(process.env.GEMINI_TIMEOUT_MS || 30000) }
  );

  const text = response.data?.candidates?.[0]?.content?.parts?.map((part) => part.text || '').join('') || '';
  if (!text) throw new Error('AI provider returned an empty response.');

  const result = parseJsonText(text);
  return {
    explanation: String(result.explanation || ''),
    impact: String(result.impact || ''),
    remediation: String(result.remediation || ''),
    codeExample: String(result.codeExample || ''),
    confidence: ['high', 'medium', 'low'].includes(result.confidence) ? result.confidence : 'medium',
  };
}

module.exports = { analyzeFinding };
