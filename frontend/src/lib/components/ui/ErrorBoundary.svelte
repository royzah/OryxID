<script lang="ts">
	import { onMount } from 'svelte';

	export let fallback: string = 'Something went wrong. Please try again.';

	let hasError = false;
	let errorMessage = '';

	onMount(() => {
		// Catch unhandled errors in this component's subtree
		const handleError = (event: ErrorEvent) => {
			hasError = true;
			errorMessage = event.message || fallback;
			event.preventDefault();
		};

		window.addEventListener('error', handleError);

		return () => {
			window.removeEventListener('error', handleError);
		};
	});

	function reset() {
		hasError = false;
		errorMessage = '';
	}
</script>

{#if hasError}
	<div class="bg-red-50 border border-red-200 rounded-lg p-6 text-center">
		<div class="mx-auto w-12 h-12 bg-red-100 rounded-full flex items-center justify-center mb-4">
			<svg class="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
			</svg>
		</div>
		<h3 class="text-lg font-semibold text-red-800 mb-2">Error</h3>
		<p class="text-red-600 mb-4">{errorMessage || fallback}</p>
		<button
			on:click={reset}
			class="inline-flex items-center px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors text-sm font-medium"
		>
			<svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
			</svg>
			Try Again
		</button>
	</div>
{:else}
	<slot />
{/if}
