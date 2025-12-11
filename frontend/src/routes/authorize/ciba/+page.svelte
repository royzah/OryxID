<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, Button, Label } from '$lib/components/ui';

	let authReqId = '';
	let loading = true;
	let error: string | null = null;
	let success = false;
	let denied = false;
	let requestInfo: {
		client_name: string;
		scope: string;
		binding_message?: string;
		expires_in: number;
	} | null = null;

	onMount(async () => {
		const params = new URLSearchParams(window.location.search);
		authReqId = params.get('auth_req_id') || '';

		if (!authReqId) {
			error = 'Missing authentication request ID';
			loading = false;
			return;
		}

		await loadRequest();
	});

	async function loadRequest() {
		try {
			const response = await fetch(`/oauth/bc-authorize/info?auth_req_id=${authReqId}`, {
				credentials: 'include'
			});

			if (!response.ok) {
				const data = await response.json();
				throw new Error(data.error_description || data.error || 'Request not found');
			}

			requestInfo = await response.json();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load request';
		} finally {
			loading = false;
		}
	}

	async function authorize() {
		loading = true;
		error = null;

		try {
			const response = await fetch('/oauth/bc-authorize/complete', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ auth_req_id: authReqId, action: 'approve' }),
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

	async function deny() {
		loading = true;
		error = null;

		try {
			const response = await fetch('/oauth/bc-authorize/complete', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ auth_req_id: authReqId, action: 'deny' }),
				credentials: 'include'
			});

			if (!response.ok) {
				const data = await response.json();
				throw new Error(data.error_description || data.error || 'Failed to deny');
			}

			denied = true;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to deny request';
		} finally {
			loading = false;
		}
	}
</script>

<svelte:head>
	<title>Authorize Sign-in - OryxID</title>
</svelte:head>

<div class="min-h-screen bg-gradient-to-br from-purple-50 to-indigo-100 flex items-center justify-center p-4">
	<Card class="w-full max-w-md">
		<div class="p-8">
			<div class="text-center mb-8">
				<div class="w-16 h-16 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-4">
					<svg class="w-8 h-8 text-purple-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" />
					</svg>
				</div>
				<h1 class="text-2xl font-bold text-gray-900">Sign-in Request</h1>
				<p class="text-gray-500 mt-2">An application is requesting to sign you in</p>
			</div>

			{#if error}
				<div class="mb-6 p-4 bg-red-50 border border-red-200 rounded-xl text-red-700 text-sm">
					{error}
				</div>
			{/if}

			{#if loading && !requestInfo}
				<div class="flex items-center justify-center py-12">
					<svg class="animate-spin h-8 w-8 text-purple-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
						<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
						<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
					</svg>
				</div>
			{:else if success}
				<div class="text-center py-8">
					<div class="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
						<svg class="w-8 h-8 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
						</svg>
					</div>
					<h2 class="text-xl font-semibold text-gray-900 mb-2">Sign-in Approved</h2>
					<p class="text-gray-500">You have been signed in. You can close this window.</p>
				</div>
			{:else if denied}
				<div class="text-center py-8">
					<div class="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
						<svg class="w-8 h-8 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
						</svg>
					</div>
					<h2 class="text-xl font-semibold text-gray-900 mb-2">Sign-in Denied</h2>
					<p class="text-gray-500">The sign-in request was denied. You can close this window.</p>
				</div>
			{:else if requestInfo}
				<div class="space-y-6">
					<div class="p-4 bg-purple-50 border border-purple-200 rounded-xl">
						<p class="text-sm text-purple-700 font-medium mb-2">Application:</p>
						<p class="text-lg font-semibold text-purple-900">{requestInfo.client_name}</p>
					</div>

					{#if requestInfo.binding_message}
						<div class="p-4 bg-blue-50 border border-blue-200 rounded-xl">
							<p class="text-sm text-blue-700 font-medium mb-2">Message from application:</p>
							<p class="text-blue-900">{requestInfo.binding_message}</p>
						</div>
					{/if}

					{#if requestInfo.scope}
						<div>
							<Label>Requested permissions:</Label>
							<div class="mt-2 flex flex-wrap gap-2">
								{#each requestInfo.scope.split(' ') as scope}
									<span class="px-3 py-1 bg-gray-100 text-gray-700 rounded-full text-sm">
										{scope}
									</span>
								{/each}
							</div>
						</div>
					{/if}

					<div class="text-sm text-gray-500">
						This request expires in {Math.floor(requestInfo.expires_in / 60)} minutes.
					</div>

					<div class="p-4 bg-amber-50 border border-amber-200 rounded-xl">
						<div class="flex items-start gap-3">
							<svg class="w-5 h-5 text-amber-600 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
							</svg>
							<div>
								<p class="text-sm text-amber-800">
									Only approve if you initiated this sign-in request.
								</p>
							</div>
						</div>
					</div>

					<div class="flex gap-3">
						<Button class="flex-1" variant="outline" on:click={deny} disabled={loading}>
							Deny
						</Button>
						<Button class="flex-1" on:click={authorize} disabled={loading}>
							{#if loading}
								<svg class="animate-spin -ml-1 mr-2 h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
									<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
									<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
								</svg>
							{/if}
							Approve Sign-in
						</Button>
					</div>
				</div>
			{:else if !error}
				<div class="text-center py-8 text-gray-500">
					No pending sign-in request found.
				</div>
			{/if}

			<div class="mt-8 pt-6 border-t border-gray-100 text-center">
				<p class="text-xs text-gray-400">
					OryxID - OpenID Connect CIBA
				</p>
			</div>
		</div>
	</Card>
</div>
