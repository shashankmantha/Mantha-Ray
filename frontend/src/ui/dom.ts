// Write to the page only when something actually changed. The app window
// (Qt's Chromium) keeps drawing memory for every change it repaints, so
// rewriting unchanged text or classes on every update leaks over a long scan.

export function setText(node: Node, text: string): void {
  if (node.textContent !== text) {
    node.textContent = text;
  }
}

export function setClassName(element: Element, value: string): void {
  if (element.className !== value) {
    element.className = value;
  }
}

export function setAttribute(element: Element, name: string, value: string): void {
  if (element.getAttribute(name) !== value) {
    element.setAttribute(name, value);
  }
}
