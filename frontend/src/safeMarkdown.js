import { marked } from 'marked'
import DOMPurify from 'dompurify'

// Renders untrusted markdown (AI responses) as sanitized HTML. Marked v12
// passes raw HTML through by default, so a malicious/MITM'd provider could
// return <script> or javascript: URLs; DOMPurify strips those before render.
export function renderMarkdown(text) {
  return DOMPurify.sanitize(marked.parse(text || ''))
}
