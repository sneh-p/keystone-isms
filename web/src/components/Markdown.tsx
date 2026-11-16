import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { safeHref } from "@/lib/safe-url";

/**
 * Renders Markdown from users, templates and AI output (SC-XSS-001, SC-LLM-006):
 * no raw HTML (react-markdown escapes it), links only with safe schemes, and images are never
 * loaded (a remote image URL could carry data out in its query string); their alt text is shown.
 */
export function Markdown({ children }: { children: string }) {
  return (
    <div className="prose-policy text-sm">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          a: ({ href, children }) => {
            const safe = safeHref(href);
            return safe ? <a href={safe} target="_blank" rel="noreferrer noopener" className="text-primary underline">{children}</a> : <span>{children}</span>;
          },
          img: ({ alt }) => (alt ? <span className="text-muted-foreground">[image: {alt}]</span> : null),
        }}
      >
        {children}
      </ReactMarkdown>
    </div>
  );
}
