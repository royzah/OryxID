<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, Button, Input, Label } from '$lib/components/ui';

	let userCode = '';
	let loading = false;
	let error: string | null = null;
	let success = false;
	let deviceInfo: {
		client_name: string;
		scope: string;
		expires_in: number;
	} | null = null;

	// Extract user_code from URL if provided
	onMount(() => {
		const params = new URLSearchParams(window.location.search);
		const code = params.get('user_code');
		if (code) {
			userCode = code.replace(/-/g, '').toUpperCase();
			verifyCode();
		}
	});

	async function verifyCode() {
		if (!userCode.trim()) {
			error = 'Please enter a device code';
			return;
		}

		loading = true;
		error = null;

		try {
			const response = await fetch('/oauth/device/verify', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ user_code: formatUserCode(userCode) }),
				credentials: 'include'
			});

			if (!response.ok) {
				const data = await response.json();
				throw new Error(data.error_description || data.error || 'Invalid device code');
			}

			deviceInfo = await response.json();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to verify code';
			deviceInfo = null;
		} finally {
			loading = false;
		}
	}

	async function authorizeDevice() {
		loading = true;
		error = null;

		try {
			const response = await fetch('/oauth/device/authorize', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ user_code: formatUserCode(userCode), action: 'approve' }),
				credentials: 'include'
			});

			if (!response.ok) {
				const data = await response.json();
				throw new Error(data.error_description || data.error || 'Authorization failed');
			}

			success = true;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Authorization failed';
		} finally {
			loading = false;
		}
	}

	async function denyDevice() {
		loading = true;
		error = null;

		try {
			const response = await fetch('/oauth/device/authorize', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ user_code: formatUserCode(userCode), action: 'deny' }),
				credentials: 'include'
			});

			if (!response.ok) {
				const data = await response.json();
				throw new Error(data.error_description || data.error || 'Failed to deny');
			}

			success = true;
			deviceInfo = null;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to deny device';
		} finally {
			loading = false;
		}
	}

	function formatUserCode(code: string): string {
		const clean = code.replace(/[^A-Z0-9]/gi, '').toUpperCase();
		if (clean.length >= 8) {
			return clean.slice(0, 4) + '-' + clean.slice(4, 8);
		}
		return clean;
	}

	function handleInput(e: Event) {
		const target = e.target as HTMLInputElement;
		userCode = target.value.toUpperCase().replace(/[^A-Z0-9-]/g, '');
	}
</script>

<svelte:head>
	<title>Device Authorization - OryxID</title>
</svelte:head>

<div class="min-h-screen bg-gradient-to-br from-purple-50 to-indigo-100 flex items-center justify-center p-4">
	<Card class="w-full max-w-md">
		<div class="p-8">
			<div class="text-center mb-8">
				<div class="w-16 h-16 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-4">
					<svg class="w-8 h-8 text-purple-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
					</svg>
				</div>
				<h1 class="text-2xl font-bold text-gray-900">Device Authorization</h1>
				<p class="text-gray-500 mt-2">Enter the code shown on your device</p>
			</div>

			{#if error}
				<div class="mb-6 p-4 bg-red-50 border border-red-200 rounded-xl text-red-700 text-sm">
					{error}
				</div>
			{/if}

			{#if success}
				<div class="text-center py-8">
					<div class="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
						<svg class="w-8 h-8 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
						</svg>
					</div>
					<h2 class="text-xl font-semibold text-gray-900 mb-2">
						{deviceInfo ? 'Device Authorized' : 'Access Denied'}
					</h2>
					<p class="text-gray-500">
						{deviceInfo ? 'You can close this window and return to your device.' : 'The device was not authorized.'}
					</p>
				</div>
			{:else if deviceInfo}
				<div class="space-y-6">
					<div class="p-4 bg-purple-50 border border-purple-200 rounded-xl">
						<p class="text-sm text-purple-700 font-medium mb-2">Application requesting access:</p>
						<p class="text-lg font-semibold text-purple-900">{deviceInfo.client_name}</p>
					</div>

					{#if deviceInfo.scope}
						<div>
							<Label>Requested permissions:</Label>
							<div class="mt-2 flex flex-wrap gap-2">
								{#each deviceInfo.scope.split(' ') as scope}
									<span class="px-3 py-1 bg-gray-100 text-gray-700 rounded-full text-sm">
										{scope}
									</span>
								{/each}
							</div>
						</div>
					{/if}

					<div class="text-sm text-gray-500">
						This code expires in {Math.floor(deviceInfo.expires_in / 60)} minutes.
					</div>

					<div class="flex gap-3">
						<Button class="flex-1" variant="outline" on:click={denyDevice} disabled={loading}>
							Deny
						</Button>
						<Button class="flex-1" on:click={authorizeDevice} disabled={loading}>
							{#if loading}
								<svg class="animate-spin -ml-1 mr-2 h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
									<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
									<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
								</svg>
							{/if}
							Authorize
						</Button>
					</div>
				</div>
			{:else}
				<form on:submit|preventDefault={verifyCode} class="space-y-6">
					<div>
						<Label for="user_code">Device Code</Label>
						<Input
							id="user_code"
							type="text"
							placeholder="XXXX-XXXX"
							value={userCode}
							on:input={handleInput}
							class="mt-2 text-center text-2xl tracking-widest font-mono"
							maxlength={9}
							autocomplete="off"
						/>
						<p class="text-xs text-gray-500 mt-2 text-center">
							Enter the 8-character code displayed on your device
						</p>
					</div>

					<Button type="submit" class="w-full" disabled={loading || userCode.length < 8}>
						{#if loading}
							<svg class="animate-spin -ml-1 mr-2 h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
								<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
								<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
							</svg>
						{/if}
						Continue
					</Button>
				</form>
			{/if}

			<div class="mt-8 pt-6 border-t border-gray-100 text-center">
				<p class="text-xs text-gray-400">
					OryxID - OAuth 2.0 / OpenID Connect Server
				</p>
			</div>
		</div>
	</Card>
</div>

<style>
	:global(body) {
		background: linear-gradient(135deg, #f5f3ff 0%, #e0e7ff 100%);
	}
</style>
