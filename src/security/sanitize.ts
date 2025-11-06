import DOMPurify from "dompurify";

/** Sanitize any string before dangerously setting HTML (avoid if you can). */
export function sanitize(html: string) {
  return DOMPurify.sanitize(html, { USE_PROFILES: { html: true } });
}