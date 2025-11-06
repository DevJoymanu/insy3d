import { type ReactNode } from "react";

type SecurityBannerProps = {
  heading?: string;
  children: ReactNode;
  tone?: "info" | "warning";
};

const palette = {
  info: {
    background: "#eef4ff",
    border: "#c7d2fe",
    heading: "#1d4ed8",
    body: "#1e3a8a"
  },
  warning: {
    background: "#fff7ed",
    border: "#fed7aa",
    heading: "#c2410c",
    body: "#9a3412"
  }
} as const;

export default function SecurityBanner({
  heading = "Security Notice",
  children,
  tone = "info"
}: SecurityBannerProps) {
  const colors = palette[tone];

  return (
    <section
      aria-label={heading}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 12,
        padding: "12px 16px",
        marginBottom: 16,
        borderRadius: 8,
        background: colors.background,
        border: `1px solid ${colors.border}`,
        color: colors.body,
        fontSize: 14,
        lineHeight: 1.5
      }}
    >
      <div style={{ fontWeight: 600, color: colors.heading }}>{heading}</div>
      <div style={{ flex: 1 }}>{children}</div>
    </section>
  );
}
