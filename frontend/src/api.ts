// Authenticated same-origin JSON client for the loopback API.

interface ApiErrorBody {
  detail?: unknown;
}

export async function api<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers ?? {}),
    },
  });
  if (!response.ok) {
    let message =
      `Request failed with status ${response.status}.`;
    try {
      const body = (await response.json()) as ApiErrorBody;
      if (typeof body.detail === "string") {
        message = body.detail;
      } else if (body.detail !== undefined) {
        message = JSON.stringify(body.detail);
      }
    } catch {
      // Retain the bounded generic message.
    }
    throw new Error(message);
  }
  return (await response.json()) as T;
}