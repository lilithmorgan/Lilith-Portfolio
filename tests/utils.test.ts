import { describe, it, expect } from 'vitest'
import { cn } from '../lib/utils'

describe('cn utility', () => {
  it('combines multiple class names', () => {
    expect(cn('a', 'b', 'c')).toBe('a b c')
  })

  it('handles falsy values gracefully', () => {
    expect(cn('a', null as unknown as string, undefined as unknown as string, false as unknown as string, 'b')).toBe('a b')
  })

  it('merges tailwind classes with last-wins behavior', () => {
    // tailwind-merge collapses conflicting classes (e.g., p-2 vs p-4)
    expect(cn('p-2', 'p-4')).toBe('p-4')
  })
})

