// Bastion brand emblem — a thin square frame with a centered "B", matching
// /public/icon.svg.  Uses currentColor so it tints with surrounding text /
// `text-emerald-400` etc.  Keep it monoline + bold for legibility at 16-24px.

type Props = {
  size?: number;        // px, square. defaults to 1em (inherits font-size).
  className?: string;
  title?: string;
};

export default function BastionMark({ size, className, title = "Bastion" }: Props) {
  const dim = size ? `${size}px` : "1em";
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 32 32"
      width={dim}
      height={dim}
      role="img"
      aria-label={title}
      className={className}
    >
      <title>{title}</title>
      {/* outer frame */}
      <rect
        x="2.5" y="2.5" width="27" height="27" rx="3"
        fill="none" stroke="currentColor" strokeWidth="2"
      />
      {/* centered bold B */}
      <text
        x="16" y="22"
        textAnchor="middle"
        fontFamily="ui-monospace, SFMono-Regular, Consolas, monospace"
        fontSize="18"
        fontWeight="700"
        fill="currentColor"
      >B</text>
    </svg>
  );
}
