const axios = require('axios');

const GEMINI_API_URL = 'https://generativelanguage.googleapis.com/v1beta/models';

function buildPrompt(finding) {
  return `You are a secure-coding assistant for a MERN application. Analyze this scanner finding conservatively.\n\nCategory: ${finding.category}\nSeverity: ${finding.severity}\nTitle: ${finding.title}\nDescription: ${finding.description || 'N/A'}\nFile: ${finding.file || 'N/A'}\nLine: ${finding.line || 'N/A'}\nOWASP: ${finding.owaspRef || 'N/A'}\nDetection engine: ${finding.engine}\n\nReturn ONLY valid JSON with this exact shape:\n{\n  "explanation": "short plain-English explanation of why this is a security concern",\n  "impact": "realistic security impact",\n  "remediation": "specific remediation steps for a MERN developer",\n  "codeExample": "short safe code example or an empty string when a code example is not appropriate",\n  "confidence": "high|medium|low"\n}\nDo not invent evidence that is not present in the finding. Clearly distinguish a heuristic indication from a confirmed vulnerability.`;
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

  // Gemini 3.5 Flash is a current stable model suited to coding/security workflows.
  // Keep GEMINI_MODEL configurable so the deployment can switch models without a code change.
  const model = process.env.GEMINI_MODEL || 'gemini-3.5-flash';
  const response = await axios.post(
    `${GEMINI_API_URL}/${encodeURIComponent(model)}:generateContent`,
    {
      contents: [{ parts: [{ text: buildPrompt(finding) }] }],
      generationConfig: {
        responseMimeType: 'application/json',
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

module.exports = { analyzeFinding, buildPrompt, parseJsonText };
