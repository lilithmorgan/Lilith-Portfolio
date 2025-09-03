"use client"

import { useState, useEffect } from "react"
import { Terminal, Shield, Cpu, Code, Network, Github, Twitter, Search, FileCode, Computer, Globe } from "lucide-react"
import Image from "next/image"
import Link from "next/link"
import GlitchText from "@/components/GlitchText"

// Extracted Component: TypewriterText - Enhanced for accessibility
const TypewriterText = ({ text }: { text: string }) => {
  const [displayText, setDisplayText] = useState("")
  const [currentIndex, setCurrentIndex] = useState(0)

  useEffect(() => {
    if (currentIndex < text.length) {
      const timeout = setTimeout(() => {
        setDisplayText((prev) => prev + text[currentIndex])
        setCurrentIndex((prev) => prev + 1)
      }, 100)
      return () => clearTimeout(timeout)
    }
  }, [currentIndex, text])

  return (
    <span aria-live="polite" aria-label={text}>
      {displayText}
      <span className="animate-pulse" aria-hidden={true}>_</span>
    </span>
  )
}

// Extracted Component: StatCard
const StatCard = ({ icon: Icon, label, value }: { 
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>, 
  label: string, 
  value: string 
}) => (
  <div className="glass-card p-4 hover:border-pink-500 transition-colors duration-300">
    <Icon className="w-6 h-6 text-pink-500 mb-2" aria-hidden={true} />
    <div className="text-2xl font-bold text-pink-500">{value}</div>
    <div className="text-xs text-gray-400">{label}</div>
  </div>
)

// Extracted Component: ElegantButton - Enhanced for accessibility and UX
const ElegantButton = ({ 
  href, 
  children, 
  className = "",
  ariaLabel
}: { 
  href: string, 
  children: React.ReactNode,
  className?: string,
  ariaLabel?: string
}) => (
  <Link
    href={href}
    className={`group relative px-6 py-3 text-pink-500 hover:text-black transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-pink-500 focus:ring-offset-2 focus:ring-offset-black rounded-sm min-h-[44px] min-w-[44px] inline-flex items-center justify-center ${className}`}
    aria-label={ariaLabel}
    tabIndex={0}
  >
    <span className="absolute inset-0 border border-pink-500 bg-transparent group-hover:bg-pink-500 group-focus:bg-pink-500/20 transition-colors duration-300" aria-hidden={true}></span>
    <span className="absolute inset-0 border border-pink-500 bg-transparent group-hover:bg-pink-500 group-focus:bg-pink-500/20 transition-colors duration-300 animation-delay-100" aria-hidden={true}></span>
    <span className="relative font-mono text-center">{children}</span>
  </Link>
)

// Extracted Component: SocialIcon - Enhanced for accessibility
const SocialIcon = ({ 
  icon: Icon, 
  href, 
  label 
}: { 
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>, 
  href: string, 
  label: string 
}) => (
  <Link
    href={href}
    className="group relative p-2 inline-block min-h-[44px] min-w-[44px] flex items-center justify-center focus:outline-none focus:ring-2 focus:ring-pink-500 focus:ring-offset-2 focus:ring-offset-black rounded-sm transition-all duration-300"
    aria-label={`Visit ${label} profile`}
    tabIndex={0}
  >
    <span className="absolute inset-0 border border-pink-500/80 bg-transparent group-hover:bg-pink-500/5 group-focus:bg-pink-500/10 transition-colors duration-300" aria-hidden={true}></span>
    <span className="relative z-10 block">
      <Icon
        className="w-6 h-6 text-pink-500 group-hover:text-pink-500/80 group-focus:text-pink-400 transition-colors duration-300"
        aria-hidden={true}
      />
    </span>
  </Link>
)

// Extracted Component: ServiceCard
const ServiceCard = ({
  icon: Icon,
  title,
  description
}: {
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>,
  title: string,
  description: string
}) => (
  <div className="group relative overflow-hidden glass-card p-6 hover:border-pink-500 transition-all duration-300">
    <div className="absolute inset-0 bg-pink-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
    <div className="relative z-10">
      <Icon
        className="w-12 h-12 text-pink-500 mb-4 group-hover:animate-pulse"
        aria-hidden={true}
      />
      <h3 className="text-xl font-bold text-pink-500 mb-2">{title}</h3>
      <p className="text-sm text-gray-400 leading-relaxed">{description}</p>
    </div>
    <div className="absolute inset-0 border border-pink-500 opacity-0 scale-90 group-hover:opacity-100 group-hover:scale-100 transition-all duration-300" />
  </div>
)

// ProjectCard removed (unused)


export default function HomePage() {




  // Stats Data
  const stats = [
    { icon: Shield, label: "Years Experience", value: "15+" },
    { icon: Terminal, label: "Major Companies", value: "50+" },
    { icon: Cpu, label: "Critical Systems", value: "500+" },
    { icon: Network, label: "Success Rate", value: "99.9%" },
  ]

  // Services Data
  const services = [
    {
      icon: Search,
      title: "Threat Modeling",
      description:
        "Advanced threat modeling and risk assessment for critical infrastructure. Expert in OWASP methodologies and nation-state attack vectors.",
    },
    {
      icon: FileCode,
      title: "Penetration Testing",
      description: "Comprehensive pentesting across networks, applications, and infrastructure. Specialized in bypassing advanced security controls.",
    },
    {
      icon: Shield,
      title: "DevSecOps",
      description:
        "Security integration throughout SDLC. Expert in secure CI/CD pipelines, infrastructure as code, and automated security testing.",
    },
    {
      icon: Computer,
      title: "Incident Response",
      description:
        "Rapid response to cyber incidents and advanced threat campaigns. Specialized in forensics, threat hunting, and system remediation.",
    },
    {
      icon: Code,
      title: "Secure Architecture",
      description:
        "Design and implementation of secure systems for enterprise environments. Expert in zero-trust architectures and defense-in-depth strategies.",
    },
  ]

  // Social Links (only GitHub and Twitter as requested)
  const socialLinks = [
    { icon: Github, href: "https://github.com/lilithmorgan", label: "GitHub" },
    { icon: Twitter, href: "https://x.com/Li_Lilith_Li", label: "Twitter" },
  ]

  return (
    <>
      <div className="min-h-screen bg-black text-pink-50 font-mono relative p-8 overflow-hidden">
        {/* Skip Link for Accessibility */}
        <a href="#main-content" className="skip-link">Skip to main content</a>
        
        {/* Elegant Floating Particles Background */}
        <div className="fixed inset-0 bg-black opacity-50 pointer-events-none floating-particles" aria-hidden={true} />

        {/* Subtle Scanline Effect */}
        <div className="fixed inset-0 pointer-events-none scanline opacity-30" aria-hidden={true} />

        {/* Navigation - Enhanced for accessibility */}
        <nav className="flex justify-between items-center mb-20 text-sm relative z-10" role="navigation" aria-label="Main navigation">
          <div className="flex gap-8" role="menubar">
            {[
              { label: "Home", path: "/", active: true },
            ].map((item) => (
              <Link
                key={item.label}
                href={item.path}
                className={`group relative overflow-hidden focus:outline-none focus:ring-2 focus:ring-pink-500 focus:ring-offset-2 focus:ring-offset-black rounded-sm px-2 py-1 transition-all duration-300 ${item.active ? "text-pink-500" : "text-gray-500 hover:text-pink-500"}`}
                aria-current={item.active ? "page" : undefined}
                role="menuitem"
                tabIndex={0}
              >
                <span className="inline-block transform group-hover:-translate-y-full transition-transform duration-300">
                  &#47;&#47;0{item.active ? "1" : "2"}. &lt;{item.label}/&gt;
                </span>
                <span className="absolute inset-0 transform translate-y-full group-hover:translate-y-0 transition-transform duration-300">
                  [ACCESS_GRANTED]
                </span>
              </Link>
            ))}
          </div>
          <div className="gradient-text text-2xl animate-pulse font-bold" role="banner">\Lilith</div>
          <div className="flex gap-8">{/* Empty div to maintain layout */}</div>
        </nav>

        <main id="main-content" role="main">
          {/* Hero Section */}
          <section className="mb-32 relative z-10" aria-labelledby="hero-heading">
            <div className="relative max-w-4xl mx-auto">
              <div className="glitch-container mb-4">
                <p className="text-pink-500 mb-2 opacity-80" aria-label="System initialization code">
                  &lt;init&gt;system.out.print(&quot;identity&quot;);&lt;/init&gt;
                </p>
                <h1 id="hero-heading" className="text-6xl mb-4 font-bold">
                  <TypewriterText text="Mikaela Lilith Morgan" />
                </h1>
                <p className="gradient-text mb-8 text-lg font-semibold" role="doc-subtitle">
                  <TypewriterText text="[CYBERSECURITY_SPECIALIST] :: {CYBERWARFARE_EXPERT}" />
                </p>
              </div>

              {/* Stats Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8" role="region" aria-label="Professional statistics">
                {stats.map((stat, index) => (
                  <StatCard
                    key={index}
                    icon={stat.icon}
                    label={stat.label}
                    value={stat.value}
                  />
                ))}
              </div>

              {/* Contact Buttons */}
              <div className="flex flex-wrap justify-center gap-4 mb-4" role="region" aria-label="Contact links">
                <ElegantButton 
                  href="mailto:mikaela.r.morgan@proton.me"
                  ariaLabel="Enviar email para mikaela.r.morgan@proton.me"
                >
                  mikaela.r.morgan@proton.me
                </ElegantButton>
              </div>
              <p className="text-center text-sm text-gray-400 mb-12">For special projects and services, please contact me by email.</p>

              {/* Social Icons */}
              <div className="flex justify-center gap-6">
                {socialLinks.map((social) => (
                  <SocialIcon
                    key={social.label}
                    icon={social.icon}
                    href={social.href}
                    label={social.label}
                  />
                ))}
              </div>
            </div>
          </section>


          {/* Services Section */}
          <section className="mb-32 relative z-10" aria-labelledby="services-heading">
            <h2 id="services-heading" className="text-2xl sm:text-3xl md:text-4xl mb-16 text-center break-words">
              <GlitchText>[WHY_CHOOSE_ME]</GlitchText>
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-8 max-w-7xl mx-auto">
              {services.map((service, index) => (
                <ServiceCard
                  key={index}
                  icon={service.icon}
                  title={service.title}
                  description={service.description}
                />
              ))}
            </div>
          </section>

          {/* Core Capabilities Section (swapped) */}
          <section className="mb-32 relative z-10 max-w-7xl mx-auto">
            <h2 className="text-2xl sm:text-3xl md:text-4xl mb-12 text-center break-words">
              <GlitchText>[CORE_CAPABILITIES]</GlitchText>
            </h2>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-start">
              {/* Left Column - Content */}
              <div className="space-y-6 max-w-lg">
                <div className="group relative overflow-hidden glass-card p-6">
                  <div className="space-y-4">
                    <p className="text-pink-500 mb-3 flex items-center gap-2">
                      <span className="w-5 h-5 rounded-full border border-pink-500 inline-flex items-center justify-center text-sm">
                        1
                      </span>
                      WHY CHOOSE LILITH
                    </p>
                    <h3 className="text-3xl font-bold leading-tight">
                      <span className="gradient-text">15 YEARS SECURING</span>{" "}
                      <span className="glitch-container">CRITICAL SYSTEMS</span>
                      <br />
                      <span className="gradient-text">WITH ABSOLUTE DISCRETION</span>
                    </h3>
                    <div className="space-y-4 text-gray-400 mt-6">
                      <p className="leading-relaxed text-sm">
                      With 15+ years of elite cybersecurity experience across major companies in technology, finance, and critical infrastructure, I provide unparalleled security expertise with complete confidentiality.
                      </p>
                      <p className="leading-relaxed text-sm">
                      My proven track record includes advanced threat detection, sophisticated attack mitigation, and comprehensive security architecture for Fortune 500 companies - all with absolute discretion guaranteed.
                      </p>
                    </div>
                  </div>
                </div>

                {[
                  {
                    icon: Shield,
                    title: "Elite Expertise",
                    description:
                      "15+ years mastering both offensive and defensive cybersecurity across critical industries with absolute discretion.",
                  },
                  {
                    icon: Globe,
                    title: "Fortune 500 Experience",
                    description:
                      "Proven success protecting major companies in technology, finance, and critical infrastructure sectors.",
                  },
                  {
                    icon: Network,
                    title: "Complete Confidentiality",
                    description:
                      "Absolute discretion guaranteed - client names and sensitive project details never disclosed.",
                  },
                ].map((feature, index) => (
                  <div
                    key={index}
                    className="group relative overflow-hidden glass-card hover:border-pink-500 transition-all duration-300 p-4"
                  >
                    <div className="absolute inset-0 bg-pink-500/10 transform -skew-x-12 translate-x-full group-hover:translate-x-0 transition-transform duration-500" />
                    <div className="relative flex gap-4">
                      <div className="flex-shrink-0">
                        <div className="w-10 h-10 rounded-lg border border-pink-500 flex items-center justify-center group-hover:bg-pink-500 group-hover:text-black transition-all duration-300">
                          <feature.icon className="w-5 h-5" aria-hidden={true} />
                        </div>
                      </div>
                      <div className="space-y-1">
                        <h3 className="text-lg font-bold text-pink-500">{feature.title}</h3>
                        <p className="text-sm text-gray-400 leading-relaxed">{feature.description}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Right Column - Cyberpunk Specialist Image */}
              <div className="relative w-full max-w-md mx-auto h-[500px] hidden lg:block lg:self-center">
                <Image
                  src="/Cyberpunk.png"
                  alt="Mikaela Lilith Morgan - Elite Cybersecurity Specialist"
                  fill
                  className="object-cover rounded-lg shadow-lg"
                  priority
                  sizes="(max-width: 768px) 100vw, (max-width: 1200px) 50vw, 400px"
                />
              </div>
            </div>
          </section>

          {/* Media Coverage section removed as requested */}

          {/* About Me Section */}
          <section id="about" className="mb-32 relative z-10 max-w-4xl mx-auto">
            <h2 className="text-4xl mb-12 text-center">
              <GlitchText>[ABOUT_ME]</GlitchText>
            </h2>

            {/* Skills */}
            <div className="mb-16">
              <h3 className="text-2xl text-pink-500 mb-6 font-bold">Skills</h3>
              <div className="space-y-6">
                <div className="glass-card p-6 hover:border-pink-500 transition-all duration-300">
                  <h4 className="text-pink-500 mb-3">Core Expertise</h4>
                  <p className="text-gray-400">
                    Advanced Penetration Testing, Vulnerability Assessment, DevSecOps Integration, Threat Modeling, Secure Code Review, Incident Response, Cyber Investigations, Secure Architecture Design.
                  </p>
                </div>
                <div className="glass-card p-6 hover:border-pink-500 transition-all duration-300">
                  <h4 className="text-pink-500 mb-3">Technical Proficiency</h4>
                  <p className="text-gray-400">
                    Enterprise Security Frameworks, OWASP Top 10, NIST Cybersecurity Framework, ISO 27001, SOC 2, Advanced Persistent Threat (APT) Analysis, Zero-Day Research, Cryptographic Implementations.
                  </p>
                </div>
                <div className="glass-card p-6 hover:border-pink-500 transition-all duration-300">
                  <h4 className="text-pink-500 mb-3">Industry Sectors</h4>
                  <p className="text-gray-400">Financial Services, Technology, Healthcare, Critical Infrastructure, Government Contractors, Fortune 500 Enterprises, Startup Security Architecture.</p>
                </div>
              </div>
            </div>

            {/* Experience */}
            <div className="mb-16">
              <h3 className="text-2xl text-pink-500 mb-6 font-bold">Experience</h3>
              <div className="space-y-6">
                {[
                  {
                    role: "Principal Cybersecurity Consultant",
                    company: "[Fortune 500 Technology Company]",
                    period: "2020 - Present",
                    location: "Global [Remote/Confidential]",
                  },
                  {
                    role: "Lead Cybersecurity Team",
                    company: "[Europe's largest cybersecurity company]",
                    period: "2016 - 2020",
                    location: "Europe [Remote/Confidential]",
                  },
                  {
                    role: "Security Architect",
                    company: "[Large technology and services company]",
                    period: "2010 - 2015",
                    location: "Brazil [Confidential]",
                  },
                ].map((job, index) => (
                  <div
                    key={index}
                    className="group relative overflow-hidden glass-card p-6 hover:border-pink-500 transition-all duration-300"
                  >
                    <div className="absolute inset-0 bg-pink-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
                    <div className="relative z-10">
                      <h4 className="text-pink-500 font-bold mb-2">{job.role}</h4>
                      <p className="text-gray-400 mb-1">at {job.company}</p>
                      <p className="text-sm text-gray-500">{job.period}</p>
                      {job.location && <p className="text-sm text-gray-500">{job.location}</p>}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Education & Certifications */}
            <div className="mb-16">
              <h3 className="text-2xl text-pink-500 mb-6 font-bold">Education & Certifications</h3>
              <div className="grid grid-cols-1 gap-6">
                {/* Education */}
                <div className="glass-card p-6 hover:border-pink-500 transition-all duration-300">
                  <h4 className="text-pink-500 mb-4 text-xl">Education</h4>
                  <div className="space-y-4">
                    <div className="group">
                      <p className="text-white mb-2 text-lg">Bachelor of Science in Computer Science. Brazil, 2011-2015</p>
                    </div>
                    <div className="group">
                      <p className="text-white mb-2 text-lg">Master of Science in Cybersecurity. Ireland, 2017-2021</p>
                    </div>
                  </div>
                </div>

                {/* Certifications */}
                <div className="glass-card p-6 hover:border-pink-500 transition-all duration-300">
                  <h4 className="text-pink-500 mb-4 text-xl">Certifications</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {[
                      {
                        name: "Certified Information Systems Security Professional (CISSP)",
                        issuer: "(ISC)²",
                        date: "2012",
                      },
                      {
                        name: "Certified Ethical Hacker (CEH) Master",
                        issuer: "EC-Council",
                        date: "2013",
                      },
                      {
                        name: "GIAC Security Essentials (GSEC)",
                        issuer: "SANS Institute",
                        date: "2014",
                      },
                      {
                        name: "Certified Information Security Manager (CISM)",
                        issuer: "ISACA",
                        date: "2016",
                      },
                      {
                        name: "GIAC Penetration Tester (GPEN)",
                        issuer: "SANS Institute",
                        date: "2017",
                      },
                      {
                        name: "Certified Information Systems Auditor (CISA)",
                        issuer: "ISACA",
                        date: "2018",
                      },
                      {
                        name: "AWS Certified Security - Specialty",
                        issuer: "Amazon Web Services",
                        date: "2019",
                      },
                      {
                        name: "GIAC Incident Handler (GCIH)",
                        issuer: "SANS Institute",
                        date: "2020",
                      },
                      
                      
                      // Professional certifications for elite security expert
                    ].map((cert, index) => (
                      <div
                        key={index}
                        className="group relative overflow-hidden glass-card p-4 hover:border-pink-500 transition-all duration-300"
                      >
                        <div className="absolute inset-0 bg-pink-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
                        <div className="relative z-10">
                          <h5 className="text-pink-500 font-bold mb-2 text-sm">{cert.name}</h5>
                          <div className="flex justify-between items-center">
                            <p className="text-gray-400 text-sm">{cert.issuer}</p>
                            <p className="text-gray-500 text-xs">{cert.date}</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* Projects section removed as requested */}

            {/* Additional Experiences */}
            <div>
              <h3 className="text-2xl text-pink-500 mb-6 font-bold">Additional Experiences</h3>
              <div className="space-y-4">
                {[
                  {
                    role: "Independent Security Consultant",
                    company: "Lilith Security Solutions",
                    period: "2010 - Present",
                    details: "Providing elite cybersecurity services to Fortune 500 companies across multiple industries. All client engagements maintained under strict confidentiality agreements.",
                  },
                  {
                    role: "Advanced Threat Research",
                    company: "[Classified Government Initiative]",
                    period: "2018 - 2022",
                    details: "Led research team investigating nation-state cyber capabilities and developing advanced defensive countermeasures. Cleared for sensitive security information.",
                  },
                  {
                    role: "Security Architecture Advisory Board",
                    company: "[Major Technology Consortium]",
                    period: "2015 - Present",
                    details: "Strategic advisor for enterprise security architecture standards and emerging threat landscape analysis. Contributing to industry-wide security best practices.",
                  },
                ].map((exp, index) => (
                  <div
                    key={index}
                    className="group relative overflow-hidden glass-card p-4 hover:border-pink-500 transition-all duration-300"
                  >
                    <div className="absolute inset-0 bg-pink-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
                    <div className="relative z-10">
                      <div className="flex justify-between items-start mb-1">
                        <h4 className="text-pink-500 font-bold">{exp.role}</h4>
                        <span className="text-sm text-gray-500">{exp.period}</span>
                      </div>
                      <p className="text-gray-400">{exp.company}</p>
                      {exp.details && <p className="text-sm text-gray-500 mt-1">{exp.details}</p>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </section>

          {/* Secure Channels section removed as requested */}

          {/* Copyright Section */}
          <footer className="text-center pb-8 text-pink-400/60 font-mono text-sm relative z-10">
            <div className="flex items-center justify-center gap-2">
              <Terminal className="w-4 h-4" />
              <span>&copy; {new Date().getFullYear()} Mikaela Lilith Morgan. All rights reserved.</span>
            </div>
          </footer>
        </main>
      </div>
    </>
  )
}
