"use client"

import { MDXRemote } from 'next-mdx-remote/rsc'
import rehypeHighlight from 'rehype-highlight'
import remarkGfm from 'remark-gfm'
import remarkMath from 'remark-math'
import rehypeKatex from 'rehype-katex'
import rehypeSanitize from 'rehype-sanitize'
import Image from 'next/image'
import { useEffect } from 'react'
import mermaid from 'mermaid'

// Initialize mermaid
if (typeof window !== 'undefined') {
  mermaid.initialize({
    startOnLoad: true,
    theme: 'dark',
    themeVariables: {
      primaryColor: '#ef4444',
      primaryTextColor: '#fff',
      primaryBorderColor: '#ef4444',
      lineColor: '#ef4444',
      secondaryColor: '#fb7185',
      tertiaryColor: '#fecdd3',
    }
  })
}

// Custom components for MDX
const components = {
  pre: ({ children }: { children?: React.ReactNode }) => {
    // Get the child code element
    const codeElement = children as React.ReactElement
    
    // Extract language and filename from className
    const match = codeElement?.props?.className?.match(/language-(\w+)(?::|$)(.*)/)
    const language = match?.[1] || ''
    const filename = match?.[2]?.trim() || language
    
    // Handle Mermaid diagrams
    if (language === 'mermaid') {
      return (
        <div className="mermaid my-6">
          {codeElement.props.children}
        </div>
      )
    }

    return (
      <pre data-filename={filename || undefined} className={codeElement?.props?.className}>
        {codeElement}
      </pre>
    )
  },
  
  code: ({ children, className, ...rest }: React.HTMLAttributes<HTMLElement>) => {
    return (
      <code {...rest} className={className}>
        {children}
      </code>
    )
  },
  
  img: ({ src, alt }: React.ImgHTMLAttributes<HTMLImageElement>) => {
    // If no image source is provided, return null
    if (!src) return null;

    // Check if the image is an external URL
    const isExternal = typeof src === 'string' && (src.startsWith('http') || src.startsWith('https'));
    
    // For external images, use them directly
    if (isExternal) {
      return (
        <figure className="my-6">
          <div className="relative w-full max-w-2xl">
            <Image
              src={src}
              alt={alt || "Blog post image"}
              width={700}
              height={475}
              className="object-contain w-full h-auto"
              unoptimized={true}
            />
          </div>
          {alt && (
            <figcaption className="text-red-400/70 text-sm mt-2 font-mono">
              {alt}
            </figcaption>
          )}
        </figure>
      );
    }

    // For local images, handle the path correctly
    // Remove any leading slash and 'images/' prefix if present
    const imagePath = src.replace(/^\/?(images\/)?/, '')
    const fullImagePath = `/images/${imagePath}`

    return (
      <figure className="my-6">
        <div className="relative w-full max-w-2xl">
          <Image
            src={fullImagePath}
            alt={alt || "Blog post image"}
            width={700}
            height={475}
            className="object-contain w-full h-auto"
            onError={(e) => {
              // If image fails to load, replace with a placeholder or hide
              e.currentTarget.style.display = 'none'
            }}
          />
        </div>
        {alt && (
          <figcaption className="text-red-400/70 text-sm mt-2 font-mono">
            {alt}
          </figcaption>
        )}
      </figure>
    );
  },

  table: (props: React.TableHTMLAttributes<HTMLTableElement>) => (
    <div className="overflow-x-auto my-6">
      <table className="min-w-full divide-y divide-red-500/20" {...props} />
    </div>
  ),
}

export default function MDXContent({ content }: { content: string }) {
  useEffect(() => {
    if (typeof window !== 'undefined') {
      mermaid.contentLoaded()
    }
  }, [content])

  return (
    <div className="mdx-wrapper">
      <MDXRemote 
        source={content}
        components={components}
        options={{
          mdxOptions: {
            remarkPlugins: [
              remarkGfm,
              remarkMath
            ],
            rehypePlugins: [
              [rehypeHighlight, { ignoreMissing: true }],
              rehypeKatex,
              rehypeSanitize
            ],
          },
        }}
      />
    </div>
  )
} 
