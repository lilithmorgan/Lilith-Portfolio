import "./globals.css"
import { Space_Mono } from "next/font/google"
import type React from "react"
import Script from "next/script"
import { Metadata } from 'next'

const spaceMono = Space_Mono({
  subsets: ["latin"],
  weight: ["400", "700"],
  variable: "--font-space-mono",
})

export const metadata: Metadata = {
  title: {
    default: 'Mikaela Lilith Morgan - Elite Cybersecurity Specialist',
    template: '%s | Lilith Security'
  },
  description: '15+ years elite cybersecurity experience. Cybersecurity & Cyberwarfare Specialist providing advanced security solutions with absolute discretion.',
  metadataBase: new URL(process.env.NEXT_PUBLIC_SITE_URL || 'https://lilith-security.com'),
  keywords: ['cybersecurity specialist', 'cyberwarfare expert', 'penetration testing', 'threat modeling', 'incident response', 'security architecture'],
  authors: [{ name: 'Mikaela Lilith Morgan' }],
  creator: 'Mikaela Lilith Morgan (Lilith)',
  openGraph: {
    title: 'Mikaela Lilith Morgan - Elite Cybersecurity Specialist',
    description: '15+ years elite cybersecurity experience. Cybersecurity & Cyberwarfare Specialist providing advanced security solutions with absolute discretion.',
    url: 'https://lilith-security.com',
    siteName: 'Lilith Security',
    locale: 'en_US',
    type: 'website',
    images: [
      {
        url: '/og-image.png', // Create a default OG image in public folder
        width: 1200,
        height: 630,
        alt: 'Mikaela Lilith Morgan - Elite Cybersecurity Specialist',
      }
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Mikaela Lilith Morgan - Elite Cybersecurity Specialist',
    description: '15+ years elite cybersecurity experience. Cybersecurity & Cyberwarfare Specialist providing advanced security solutions with absolute discretion.',
    creator: '@Li_Lilith_Li',
    images: ['/og-image.png'],
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-video-preview': -1,
      'max-image-preview': 'large',
      'max-snippet': -1,
    },
  },
  verification: {
    google: 'your-google-verification-code',
  },
  alternates: {
    canonical: 'https://lilith-security.com',
  },
  icons: {
    icon: [{ rel: 'icon', url: '/favicon.ico', sizes: 'any' }],
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className={spaceMono.className}>
        {children}
        <Script
          id="schema-org"
          type="application/ld+json"
          dangerouslySetInnerHTML={{
            __html: JSON.stringify({
              "@context": "https://schema.org",
              "@type": "Person",
              name: "Mikaela Lilith Morgan",
              alternateName: "Lilith",
              jobTitle: "Elite Cybersecurity & Cyberwarfare Specialist",
              url: "https://www.lilith-security.com",
              sameAs: [
                "https://github.com/lilithmorgan",
                "https://x.com/Li_Lilith_Li"
              ],
              alumniOf: {
                "@type": "CollegeOrUniversity",
                name: "Major Technical University",
              },
              knowsAbout: [
                "Cybersecurity",
                "Cyberwarfare",
                "Penetration Testing",
                "Threat Modeling",
                "Incident Response",
                "Security Architecture",
                "Vulnerability Assessment",
                "DevSecOps"
              ],
              hasCredential: [
                "CISSP", "CISM", "CISA", "CEH Master", "GIAC GSEC", "GIAC GPEN", "GIAC GCIH"
              ]
            }),
          }}
        />
      </body>
    </html>
  )
}
