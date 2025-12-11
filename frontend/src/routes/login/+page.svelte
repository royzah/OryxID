<script lang="ts">
	import { goto } from '$app/navigation';
	import { Button, Input, Label, Card } from '$lib/components/ui';
	import { auth, isAuthenticated } from '$lib/stores';
	import { onMount } from 'svelte';

	let username = '';
	let password = '';
	let error = '';
	let loading = false;

	onMount(() => {
		// Redirect if already authenticated
		if ($isAuthenticated) {
			goto('/');
		}
	});

	async function handleSubmit(e: Event) {
		e.preventDefault();
		error = '';
		loading = true;

		try {
			await auth.login({ username, password });
			goto('/');
		} catch (e) {
			error = e instanceof Error ? e.message : 'Login failed';
		} finally {
			loading = false;
		}
	}
</script>

<svelte:head>
	<title>Login - OryxID</title>
</svelte:head>

<div class="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
	<Card class="w-full max-w-md p-8">
		<div class="text-center mb-8">
			<div
				class="mx-auto w-16 h-16 bg-purple-600 rounded-xl flex items-center justify-center mb-4"
			>
				<span class="text-white text-2xl font-bold">O</span>
			</div>
			<h1 class="text-2xl font-bold text-gray-900">OryxID</h1>
			<p class="text-gray-600 mt-2">Sign in to the admin panel</p>
		</div>

		{#if error}
			<div class="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
				{error}
			</div>
		{/if}

		<form on:submit={handleSubmit} class="space-y-6">
			<div class="space-y-2">
				<Label for="username">Username or Email</Label>
				<Input
					id="username"
					type="text"
					placeholder="Enter your username or email"
					bind:value={username}
					required
					autocomplete="username"
				/>
			</div>

			<div class="space-y-2">
				<Label for="password">Password</Label>
				<Input
					id="password"
					type="password"
					placeholder="Enter your password"
					bind:value={password}
					required
					autocomplete="current-password"
				/>
			</div>

			<Button type="submit" class="w-full" disabled={loading}>
				{#if loading}
					<svg class="animate-spin -ml-1 mr-3 h-5 w-5 text-white" fill="none" viewBox="0 0 24 24">
						<circle
							class="opacity-25"
							cx="12"
							cy="12"
							r="10"
							stroke="currentColor"
							stroke-width="4"
						></circle>
						<path
							class="opacity-75"
							fill="currentColor"
							d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
						></path>
					</svg>
					Signing in...
				{:else}
					Sign in
				{/if}
			</Button>
		</form>

		<p class="mt-8 text-center text-sm text-gray-500">
			OAuth2/OIDC Server Administration
		</p>
	</Card>
</div>
