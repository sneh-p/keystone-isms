import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

/** Renders Markdown safely: raw HTML is not allowed (react-markdown escapes it by default). */
export function Markdown({ children }: { children: string }) {
  return (
    <div className="prose-policy text-sm">
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={{ a: ({ href, children }) => <a href={href} target="_blank" rel="noreferrer noopener" className="text-primary underline">{children}</a> }}>
        {children}
      </ReactMarkdown>
    </div>
  );
}
