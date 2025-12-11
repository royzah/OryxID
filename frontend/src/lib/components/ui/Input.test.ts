import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import Input from './Input.svelte';

describe('Input Component', () => {
	describe('rendering', () => {
		it('should render an input element', () => {
			render(Input);
			const input = screen.getByRole('textbox');
			expect(input).toBeInTheDocument();
		});

		it('should render with correct base classes', () => {
			render(Input);
			const input = screen.getByRole('textbox');
			expect(input).toHaveClass('flex', 'h-10', 'w-full', 'rounded-md');
		});
	});

	describe('value binding', () => {
		it('should bind value prop', () => {
			render(Input, { props: { value: 'initial' } });
			const input = screen.getByRole('textbox') as HTMLInputElement;
			expect(input.value).toBe('initial');
		});

		it('should update value on input', async () => {
			const { component } = render(Input, { props: { value: '' } });
			const input = screen.getByRole('textbox');

			await fireEvent.input(input, { target: { value: 'new value' } });

			expect((input as HTMLInputElement).value).toBe('new value');
		});
	});

	describe('input types', () => {
		it('should accept type="text"', () => {
			render(Input, { props: { type: 'text' } });
			const input = screen.getByRole('textbox');
			expect(input).toHaveAttribute('type', 'text');
		});

		it('should accept type="password"', () => {
			render(Input, { props: { type: 'password' } });
			// Password inputs don't have the textbox role
			const input = document.querySelector('input[type="password"]');
			expect(input).toBeInTheDocument();
		});

		it('should accept type="email"', () => {
			render(Input, { props: { type: 'email' } });
			const input = screen.getByRole('textbox');
			expect(input).toHaveAttribute('type', 'email');
		});

		it('should accept type="number"', () => {
			render(Input, { props: { type: 'number' } });
			const input = screen.getByRole('spinbutton');
			expect(input).toHaveAttribute('type', 'number');
		});

		it('should accept type="search"', () => {
			render(Input, { props: { type: 'search' } });
			const input = screen.getByRole('searchbox');
			expect(input).toHaveAttribute('type', 'search');
		});
	});

	describe('placeholder', () => {
		it('should render placeholder text', () => {
			render(Input, { props: { placeholder: 'Enter text...' } });
			const input = screen.getByPlaceholderText('Enter text...');
			expect(input).toBeInTheDocument();
		});

		it('should have placeholder styling', () => {
			render(Input, { props: { placeholder: 'Test' } });
			const input = screen.getByRole('textbox');
			expect(input).toHaveClass('placeholder:text-muted-foreground');
		});
	});

	describe('disabled state', () => {
		it('should be disabled when disabled prop is true', () => {
			render(Input, { props: { disabled: true } });
			const input = screen.getByRole('textbox');
			expect(input).toBeDisabled();
		});

		it('should have disabled styling classes', () => {
			render(Input, { props: { disabled: true } });
			const input = screen.getByRole('textbox');
			expect(input).toHaveClass('disabled:cursor-not-allowed', 'disabled:opacity-50');
		});
	});

	describe('required state', () => {
		it('should be required when required prop is true', () => {
			render(Input, { props: { required: true } });
			const input = screen.getByRole('textbox');
			expect(input).toBeRequired();
		});
	});

	describe('custom classes', () => {
		it('should apply custom class', () => {
			render(Input, { props: { class: 'custom-input' } });
			const input = screen.getByRole('textbox');
			expect(input).toHaveClass('custom-input');
		});

		it('should merge custom classes with default classes', () => {
			render(Input, { props: { class: 'my-custom-class' } });
			const input = screen.getByRole('textbox');
			expect(input).toHaveClass('my-custom-class');
			expect(input).toHaveClass('w-full');
		});
	});

	describe('events', () => {
		it('should emit input event', async () => {
			let eventFired = false;
			const { component } = render(Input);
			component.$on('input', () => {
				eventFired = true;
			});

			const input = screen.getByRole('textbox');
			await fireEvent.input(input, { target: { value: 'test' } });

			expect(eventFired).toBe(true);
		});

		it('should emit change event', async () => {
			let eventFired = false;
			const { component } = render(Input);
			component.$on('change', () => {
				eventFired = true;
			});

			const input = screen.getByRole('textbox');
			await fireEvent.change(input, { target: { value: 'test' } });

			expect(eventFired).toBe(true);
		});

		it('should emit blur event', async () => {
			let eventFired = false;
			const { component } = render(Input);
			component.$on('blur', () => {
				eventFired = true;
			});

			const input = screen.getByRole('textbox');
			await fireEvent.blur(input);

			expect(eventFired).toBe(true);
		});

		it('should emit focus event', async () => {
			let eventFired = false;
			const { component } = render(Input);
			component.$on('focus', () => {
				eventFired = true;
			});

			const input = screen.getByRole('textbox');
			await fireEvent.focus(input);

			expect(eventFired).toBe(true);
		});
	});

	describe('accessibility', () => {
		it('should be focusable', () => {
			render(Input);
			const input = screen.getByRole('textbox');
			input.focus();
			expect(document.activeElement).toBe(input);
		});

		it('should have focus ring styles', () => {
			render(Input);
			const input = screen.getByRole('textbox');
			expect(input).toHaveClass('focus-visible:ring-2');
		});

		it('should support id attribute for labels', () => {
			render(Input, { props: { id: 'my-input' } });
			const input = screen.getByRole('textbox');
			expect(input).toHaveAttribute('id', 'my-input');
		});

		it('should support aria-label', () => {
			render(Input, { props: { 'aria-label': 'Enter your name' } });
			const input = screen.getByLabelText('Enter your name');
			expect(input).toBeInTheDocument();
		});
	});

	describe('attributes', () => {
		it('should support autocomplete attribute', () => {
			render(Input, { props: { autocomplete: 'email' } });
			const input = screen.getByRole('textbox');
			expect(input).toHaveAttribute('autocomplete', 'email');
		});

		it('should support maxlength attribute', () => {
			render(Input, { props: { maxlength: 100 } });
			const input = screen.getByRole('textbox');
			expect(input).toHaveAttribute('maxlength', '100');
		});

		it('should support min and max for number inputs', () => {
			render(Input, { props: { type: 'number', min: 0, max: 100 } });
			const input = screen.getByRole('spinbutton');
			expect(input).toHaveAttribute('min', '0');
			expect(input).toHaveAttribute('max', '100');
		});

		it('should support pattern attribute', () => {
			render(Input, { props: { pattern: '[a-z]+' } });
			const input = screen.getByRole('textbox');
			expect(input).toHaveAttribute('pattern', '[a-z]+');
		});
	});
});
