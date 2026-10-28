import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "TradeOps Sentinel · Incident Command",
  description:
    "Deterministic FIX incident reconstruction and verified trading operations investigation.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
