import '@testing-library/jest-dom';
import { vi, beforeEach } from 'vitest';
import { readable } from 'svelte/store';

// Mock SvelteKit modules
vi.mock('$app/navigation', () => ({
	goto: vi.fn(),
	invalidate: vi.fn(),
	invalidateAll: vi.fn(),
	beforeNavigate: vi.fn(),
	afterNavigate: vi.fn()
}));

vi.mock('$app/environment', () => ({
	browser: true,
	dev: true,
	building: false,
	version: 'test'
}));

vi.mock('$app/stores', () => {
	return {
		page: readable({
			url: new URL('http://localhost'),
			params: {},
			route: { id: '/' },
			status: 200,
			error: null,
			data: {},
			form: null
		}),
		navigating: readable(null),
		updated: {
			subscribe: readable(false).subscribe,
			check: vi.fn()
		}
	};
});

// Mock localStorage
const store: Record<string, string> = {};
const localStorageMock: Storage = {
	getItem: vi.fn((key: string): string | null => store[key] || null),
	setItem: vi.fn((key: string, value: string): void => {
		store[key] = value;
	}),
	removeItem: vi.fn((key: string): void => {
		delete store[key];
	}),
	clear: vi.fn((): void => {
		Object.keys(store).forEach((key) => delete store[key]);
	}),
	get length(): number {
		return Object.keys(store).length;
	},
	key: vi.fn((index: number): string | null => Object.keys(store)[index] || null)
};

Object.defineProperty(globalThis, 'localStorage', {
	value: localStorageMock
});

// Mock fetch
globalThis.fetch = vi.fn();

// Reset mocks before each test
beforeEach(() => {
	vi.clearAllMocks();
	localStorageMock.clear();
});
