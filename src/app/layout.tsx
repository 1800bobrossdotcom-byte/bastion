import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "BASTION // local sensor",
  description: "Defensive monitoring console",
  manifest: "/manifest.webmanifest",
  themeColor: "#00ff66",
  icons: { icon: "/icon.svg" },
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className="h-full">
      <body className="min-h-full">{children}</body>
    </html>
  );
}
