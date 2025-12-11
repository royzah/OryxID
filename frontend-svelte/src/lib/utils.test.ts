import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import { cn, formatDate, truncate } from './utils';

describe('cn utility function', () => {
	describe('basic functionality', () => {
		it('should merge class names', () => {
			const result = cn('foo', 'bar');
			expect(result).toBe('foo bar');
		});

		it('should handle single class', () => {
			const result = cn('foo');
			expect(result).toBe('foo');
		});

		it('should handle empty input', () => {
			const result = cn();
			expect(result).toBe('');
		});
	});

	describe('conditional classes', () => {
		it('should handle conditional classes', () => {
			const result = cn('foo', true && 'bar');
			expect(result).toBe('foo bar');
		});

		it('should filter out falsy values', () => {
			const result = cn('foo', false && 'bar', null, undefined, 'baz');
			expect(result).toBe('foo baz');
		});

		it('should handle object syntax', () => {
			const result = cn({ foo: true, bar: false, baz: true });
			expect(result).toBe('foo baz');
		});
	});

	describe('tailwind merge functionality', () => {
		it('should merge conflicting tailwind classes', () => {
			// tailwind-merge should prefer the last class when there are conflicts
			const result = cn('px-2 py-1', 'px-4');
			expect(result).toBe('py-1 px-4');
		});

		it('should merge bg color classes', () => {
			const result = cn('bg-red-500', 'bg-blue-500');
			expect(result).toBe('bg-blue-500');
		});

		it('should merge text size classes', () => {
			const result = cn('text-sm', 'text-lg');
			expect(result).toBe('text-lg');
		});

		it('should keep non-conflicting classes', () => {
			const result = cn('bg-red-500 text-white', 'p-4');
			expect(result).toBe('bg-red-500 text-white p-4');
		});

		it('should handle responsive prefixes', () => {
			const result = cn('sm:text-sm', 'md:text-lg');
			expect(result).toBe('sm:text-sm md:text-lg');
		});

		it('should merge width classes', () => {
			const result = cn('w-4', 'w-8');
			expect(result).toBe('w-8');
		});

		it('should merge height classes', () => {
			const result = cn('h-4', 'h-8');
			expect(result).toBe('h-8');
		});

		it('should merge margin classes', () => {
			const result = cn('m-2', 'm-4');
			expect(result).toBe('m-4');
		});

		it('should handle complex merging', () => {
			const result = cn(
				'inline-flex items-center justify-center rounded-md text-sm font-medium',
				'bg-primary text-primary-foreground hover:bg-primary/90',
				'h-10 px-4 py-2',
				'custom-class'
			);
			expect(result).toContain('inline-flex');
			expect(result).toContain('custom-class');
		});
	});

	describe('array inputs', () => {
		it('should handle array of classes', () => {
			const result = cn(['foo', 'bar']);
			expect(result).toBe('foo bar');
		});

		it('should handle nested arrays', () => {
			const result = cn(['foo', ['bar', 'baz']]);
			expect(result).toBe('foo bar baz');
		});
	});

	describe('real world examples', () => {
		it('should work with button variant classes', () => {
			const baseClasses =
				'inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium';
			const variantClasses = 'bg-primary text-primary-foreground hover:bg-primary/90';
			const sizeClasses = 'h-10 px-4 py-2';

			const result = cn(baseClasses, variantClasses, sizeClasses);

			expect(result).toContain('inline-flex');
			expect(result).toContain('bg-primary');
			expect(result).toContain('h-10');
		});

		it('should allow overriding default classes', () => {
			const defaultClasses = 'bg-primary text-white p-4';
			const overrideClasses = 'bg-secondary p-2';

			const result = cn(defaultClasses, overrideClasses);

			expect(result).toContain('bg-secondary');
			expect(result).toContain('p-2');
			expect(result).toContain('text-white');
			expect(result).not.toContain('bg-primary');
		});

		it('should work with input classes', () => {
			const baseClasses =
				'flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm';
			const customClass = 'custom-input';

			const result = cn(baseClasses, customClass);

			expect(result).toContain('flex');
			expect(result).toContain('h-10');
			expect(result).toContain('custom-input');
		});
	});
});

describe('formatDate utility function', () => {
	describe('basic functionality', () => {
		it('should format a date string', () => {
			const result = formatDate('2024-01-15T10:30:00Z');
			expect(result).toMatch(/Jan/);
			expect(result).toMatch(/15/);
			expect(result).toMatch(/2024/);
		});

		it('should format a Date object', () => {
			const date = new Date('2024-06-20T14:45:00Z');
			const result = formatDate(date);
			expect(result).toMatch(/Jun/);
			expect(result).toMatch(/20/);
			expect(result).toMatch(/2024/);
		});

		it('should include time component', () => {
			const result = formatDate('2024-03-10T09:15:00Z');
			// Should contain hour and minute
			expect(result).toMatch(/\d{1,2}:\d{2}/);
		});
	});

	describe('edge cases', () => {
		it('should handle ISO date strings', () => {
			const result = formatDate('2024-12-31');
			expect(result).toMatch(/Dec/);
			expect(result).toMatch(/31/);
		});

		it('should handle dates at midnight', () => {
			const result = formatDate('2024-01-01T00:00:00Z');
			expect(result).toMatch(/Jan/);
			expect(result).toMatch(/1/);
		});

		it('should handle dates at end of day', () => {
			const result = formatDate('2024-01-01T23:59:59Z');
			expect(result).toMatch(/Jan/);
		});
	});
});

describe('truncate utility function', () => {
	describe('basic functionality', () => {
		it('should truncate strings longer than length', () => {
			const result = truncate('Hello, World!', 5);
			expect(result).toBe('Hello...');
		});

		it('should not truncate strings equal to length', () => {
			const result = truncate('Hello', 5);
			expect(result).toBe('Hello');
		});

		it('should not truncate strings shorter than length', () => {
			const result = truncate('Hi', 5);
			expect(result).toBe('Hi');
		});

		it('should handle empty strings', () => {
			const result = truncate('', 5);
			expect(result).toBe('');
		});
	});

	describe('edge cases', () => {
		it('should handle length of 0', () => {
			const result = truncate('Hello', 0);
			expect(result).toBe('...');
		});

		it('should handle length of 1', () => {
			const result = truncate('Hello', 1);
			expect(result).toBe('H...');
		});

		it('should handle very long strings', () => {
			const longString = 'a'.repeat(1000);
			const result = truncate(longString, 10);
			expect(result.length).toBe(13); // 10 chars + 3 for '...'
			expect(result.endsWith('...')).toBe(true);
		});

		it('should handle unicode characters', () => {
			const result = truncate('Hello World', 7);
			expect(result).toBe('Hello W...');
		});
	});

	describe('real world examples', () => {
		it('should truncate long descriptions', () => {
			const description = 'This is a very long description that should be truncated for display purposes';
			const result = truncate(description, 30);
			expect(result).toBe('This is a very long descriptio...');
		});

		it('should work with client IDs', () => {
			const clientId = 'abc123def456ghi789jkl012mno345';
			const result = truncate(clientId, 12);
			expect(result).toBe('abc123def456...');
		});
	});
});
