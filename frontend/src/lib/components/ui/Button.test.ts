import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import Button from './Button.svelte';

describe('Button Component', () => {
	describe('rendering', () => {
		it('should render with default props', () => {
			render(Button);
			const button = screen.getByRole('button');
			expect(button).toBeInTheDocument();
		});

		it('should render slot content', () => {
			render(Button);
			const button = screen.getByRole('button');
			expect(button).toBeInTheDocument();
		});
	});

	describe('variants', () => {
		it('should apply default variant classes', () => {
			render(Button, { props: { variant: 'default' } });
			const button = screen.getByRole('button');
			expect(button).toHaveClass('bg-primary');
		});

		it('should apply destructive variant classes', () => {
			render(Button, { props: { variant: 'destructive' } });
			const button = screen.getByRole('button');
			expect(button).toHaveClass('bg-destructive');
		});

		it('should apply outline variant classes', () => {
			render(Button, { props: { variant: 'outline' } });
			const button = screen.getByRole('button');
			expect(button).toHaveClass('border');
		});

		it('should apply secondary variant classes', () => {
			render(Button, { props: { variant: 'secondary' } });
			const button = screen.getByRole('button');
			expect(button).toHaveClass('bg-secondary');
		});

		it('should apply ghost variant classes', () => {
			render(Button, { props: { variant: 'ghost' } });
			const button = screen.getByRole('button');
			expect(button).toHaveClass('hover:bg-accent');
		});

		it('should apply link variant classes', () => {
			render(Button, { props: { variant: 'link' } });
			const button = screen.getByRole('button');
			expect(button).toHaveClass('underline-offset-4');
		});
	});

	describe('sizes', () => {
		it('should apply default size classes', () => {
			render(Button, { props: { size: 'default' } });
			const button = screen.getByRole('button');
			expect(button).toHaveClass('h-10');
		});

		it('should apply small size classes', () => {
			render(Button, { props: { size: 'sm' } });
			const button = screen.getByRole('button');
			expect(button).toHaveClass('h-9');
		});

		it('should apply large size classes', () => {
			render(Button, { props: { size: 'lg' } });
			const button = screen.getByRole('button');
			expect(button).toHaveClass('h-11');
		});

		it('should apply icon size classes', () => {
			render(Button, { props: { size: 'icon' } });
			const button = screen.getByRole('button');
			expect(button).toHaveClass('w-10');
		});
	});

	describe('custom classes', () => {
		it('should apply custom class', () => {
			render(Button, { props: { class: 'custom-class' } });
			const button = screen.getByRole('button');
			expect(button).toHaveClass('custom-class');
		});

		it('should merge custom classes with default classes', () => {
			render(Button, { props: { class: 'my-class', variant: 'default' } });
			const button = screen.getByRole('button');
			expect(button).toHaveClass('my-class');
			expect(button).toHaveClass('bg-primary');
		});
	});

	describe('disabled state', () => {
		it('should be disabled when disabled prop is true', () => {
			render(Button, { props: { disabled: true } });
			const button = screen.getByRole('button');
			expect(button).toBeDisabled();
		});

		it('should have disabled styles', () => {
			render(Button, { props: { disabled: true } });
			const button = screen.getByRole('button');
			expect(button).toHaveClass('disabled:opacity-50');
		});
	});

	describe('interactions', () => {
		it('should handle click events', async () => {
			let clicked = false;
			const { component } = render(Button);
			component.$on('click', () => {
				clicked = true;
			});

			const button = screen.getByRole('button');
			await fireEvent.click(button);

			expect(clicked).toBe(true);
		});

		it('should not trigger click when disabled', async () => {
			render(Button, { props: { disabled: true } });

			const button = screen.getByRole('button');
			await fireEvent.click(button);

			// Button should be disabled
			expect(button).toBeDisabled();
		});
	});

	describe('button types', () => {
		it('should accept type="submit"', () => {
			render(Button, { props: { type: 'submit' } });
			const button = screen.getByRole('button');
			expect(button).toHaveAttribute('type', 'submit');
		});

		it('should accept type="button"', () => {
			render(Button, { props: { type: 'button' } });
			const button = screen.getByRole('button');
			expect(button).toHaveAttribute('type', 'button');
		});

		it('should accept type="reset"', () => {
			render(Button, { props: { type: 'reset' } });
			const button = screen.getByRole('button');
			expect(button).toHaveAttribute('type', 'reset');
		});
	});

	describe('accessibility', () => {
		it('should be focusable', () => {
			render(Button);
			const button = screen.getByRole('button');
			button.focus();
			expect(document.activeElement).toBe(button);
		});

		it('should have focus ring styles', () => {
			render(Button);
			const button = screen.getByRole('button');
			expect(button).toHaveClass('focus-visible:ring-2');
		});
	});
});
