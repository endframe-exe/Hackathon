const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export async function checkHealth() {
  const response = await fetch(`${API_BASE_URL}/api/health`);
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }
  return response.json();
}

export async function analyzeUrl(url) {
  const response = await fetch(`${API_BASE_URL}/api/analyze/url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: url.trim() }),
  });
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.detail || `URL analysis failed with status: ${response.status}`);
  }
  return response.json();
}

export async function analyzeMessage({ message, sender = null, subject = null }) {
  const response = await fetch(`${API_BASE_URL}/api/analyze/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      message: message.trim(),
      sender: sender ? sender.trim() : null,
      subject: subject ? subject.trim() : null
    }),
  });
  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.detail || `Message analysis failed with status: ${response.status}`);
  }
  return response.json();
}

export async function getHistory(limit = 20, offset = 0) {
  const response = await fetch(`${API_BASE_URL}/api/history?limit=${limit}&offset=${offset}`);
  if (!response.ok) {
    throw new Error(`History fetch failed with status: ${response.status}`);
  }
  return response.json();
}
