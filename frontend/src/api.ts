export type Api = {
  token: string | null;
  request<T = any>(path: string, options?: RequestInit): Promise<T>;
  text(path: string): Promise<string>;
};

export function createApi(token: string | null): Api {
  async function send(path: string, options: RequestInit = {}) {
    const headers = new Headers(options.headers);
    if (token) headers.set("Authorization", `Bearer ${token}`);
    if (options.body && !(options.body instanceof FormData) && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }
    const response = await fetch(path, { ...options, headers });
    const text = await response.text();
    if (!response.ok) {
      let detail = response.statusText;
      try {
        const data = JSON.parse(text);
        if (typeof data.detail === "string") detail = data.detail;
      } catch {
        detail = text || response.statusText;
      }
      throw new Error(detail);
    }
    return text;
  }
  return {
    token,
    async request<T = any>(path: string, options: RequestInit = {}): Promise<T> {
      const text = await send(path, options);
      return text ? JSON.parse(text) : null;
    },
    text: send,
  };
}
