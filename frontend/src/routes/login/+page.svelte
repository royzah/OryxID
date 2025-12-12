<script lang="ts">
	import { goto } from '$app/navigation';
	import { Button, Input, Label, Card } from '$lib/components/ui';
	import { auth, isAuthenticated } from '$lib/stores';
	import { isMFARequired } from '$lib/api';
	import { onMount } from 'svelte';

	let username = '';
	let password = '';
	let mfaCode = '';
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
			const response = await auth.login({ username, password });
			// If MFA is required, the form will switch to MFA view via $auth.mfaRequired
			if (!isMFARequired(response)) {
				goto('/');
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Login failed';
		} finally {
			loading = false;
		}
	}

	async function handleMFASubmit(e: Event) {
		e.preventDefault();
		error = '';
		loading = true;

		try {
			await auth.verifyMFA(mfaCode);
			goto('/');
		} catch (e) {
			error = e instanceof Error ? e.message : 'Invalid verification code';
		} finally {
			loading = false;
		}
	}

	function cancelMFA() {
		auth.cancelMFA();
		mfaCode = '';
		error = '';
	}
</script>

<svelte:head>
	<title>Login - OryxID</title>
</svelte:head>

<div class="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-50 to-gray-100 py-12 px-4 sm:px-6 lg:px-8">
	<Card class="w-full max-w-md p-10 shadow-xl border-0">
		<div class="text-center mb-10">
			<img src="/favicon-96x96.png" alt="OryxID" class="mx-auto w-16 h-16 rounded-2xl shadow-lg mb-6" />
			{#if $auth.mfaRequired}
				<h1 class="text-2xl font-semibold text-gray-900">Two-Factor Authentication</h1>
				<p class="text-gray-500 mt-2">Enter the code from your authenticator app</p>
			{:else}
				<h1 class="text-2xl font-semibold text-gray-900">Welcome back</h1>
				<p class="text-gray-500 mt-2">Sign in to OryxID Admin</p>
			{/if}
		</div>

		{#if error}
			<div class="mb-6 p-4 bg-red-50 border border-red-100 rounded-xl text-red-600 text-sm">
				{error}
			</div>
		{/if}

		{#if $auth.mfaRequired}
			<form on:submit={handleMFASubmit} class="space-y-5">
				<div class="space-y-2">
					<Label for="mfaCode">Verification Code</Label>
					<Input
						id="mfaCode"
						type="text"
						placeholder="000000"
						bind:value={mfaCode}
						required
						maxlength={8}
						class="text-center text-2xl tracking-widest font-mono"
						autocomplete="one-time-code"
					/>
					<p class="text-xs text-gray-500 text-center">
						Enter the 6-digit code from your authenticator app or a backup code
					</p>
				</div>

				<Button type="submit" class="w-full h-11" disabled={loading}>
					{#if loading}
						<svg class="animate-spin -ml-1 mr-3 h-5 w-5" fill="none" viewBox="0 0 24 24">
							<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
							<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
						</svg>
						Verifying...
					{:else}
						Verify
					{/if}
				</Button>

				<Button type="button" variant="outline" class="w-full" on:click={cancelMFA}>
					Back to login
				</Button>
			</form>
		{:else}
			<form on:submit={handleSubmit} class="space-y-5">
				<div class="space-y-2">
					<Label for="username">Username</Label>
					<Input
						id="username"
						type="text"
						placeholder="Enter your username"
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

				<Button type="submit" class="w-full h-11" disabled={loading}>
					{#if loading}
						<svg class="animate-spin -ml-1 mr-3 h-5 w-5" fill="none" viewBox="0 0 24 24">
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
		{/if}

		<p class="mt-10 text-center text-sm text-gray-400">
			OAuth2/OIDC Server Administration
		</p>
	</Card>
</div>
