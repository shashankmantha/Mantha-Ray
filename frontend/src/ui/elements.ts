

export function element<T extends HTMLElement>(
  id: string,
): T {
  const found = document.getElementById(id);
  if (found === null) {
    throw new Error(
      `Required element '${id}' was not found.`,
    );
  }
  return found as T;
}