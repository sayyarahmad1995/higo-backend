export function adminApi(fetcher = fetch) {
  let token = '';
  async function request(path, body, bearer = token) {
    const headers = {};
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const response = await fetcher(`/api/v1/${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: 'no-store',
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) {
      const error = new Error(`Request failed (${response.status}).`);
      error.status = response.status;
      throw error;
    }
    return response.status === 204 ? null : response.json();
  }
  return {
    async login(phone, password) {
      const session = await request('auth/login', {phone, password}, '');
      token = session.access_token;
      try { return await request('admin/onboarding'); }
      catch (error) { await this.logout(); throw error; }
    },
    async logout() {
      const previous = token;
      token = '';
      if (previous) await request('auth/logout', {}, previous).catch(() => {});
    },
    queue: () => request('admin/onboarding'),
    document: (target, side) => request('admin/onboarding/document', {...target, side}),
    decision: (target, decision, reason) => request('admin/onboarding/decision', {...target, decision, reason}),
  };
}
