let configuration;
export async function api(path, options = {}) {
  const headers = {...options.headers};
  if (options.method && options.method !== 'GET') headers['X-PacketPilot-Token'] = configuration?.csrf || '';
  if (options.body && !(options.body instanceof FormData)) headers['Content-Type'] = 'application/json';
  let response;
  try { response = await fetch(path, {...options, headers}); } catch { throw new Error('The backend is unavailable. Your draft and saved answers are unchanged.'); }
  let data;
  try { data = await response.json(); } catch { throw new Error('The backend returned an unreadable response. Nothing was automatically repeated.'); }
  if (!response.ok) { const error = new Error(typeof data.detail === 'string' ? data.detail : 'Check the supplied details and try again.'); error.status = response.status; throw error; }
  if (path === '/api/config') configuration = data;
  return data;
}
export const post = (path, value) => api(path, {method: 'POST', body: JSON.stringify(value)});
