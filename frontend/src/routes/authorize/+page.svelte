<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, Button, Label } from '$lib/components/ui';

	let loading = true;
	let error: string | null = null;
	let authInfo: {
		client_name: string;
		client_id: string;
		scope: string;
		redirect_uri: string;
		state?: string;
		response_type: string;
		authorization_details?: Array<{
			type: string;
			[key: string]: unknown;
		}>;
	} | null = null;

	// Store original query params for form submission
	let originalParams = '';

	onMount(async () => {
		originalParams = window.location.search;
		await loadAuthInfo();
	});

	async function loadAuthInfo() {
		try {
			const response = await fetch(`/oauth/authorize/info${originalParams}`, {
				credentials: 'include'
			});

			if (!response.ok) {
				const data = await response.json();
				// If redirect error, let the backend handle it
				if (data.redirect_uri) {
					window.location.href = data.redirect_uri;
					return;
				}
				throw new Error(data.error_description || data.error || 'Invalid authorization request');
			}

			authInfo = await response.json();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load authorization request';
		} finally {
			loading = false;
		}
	}

	async function authorize() {
		loading = true;
		error = null;

		try {
			const response = await fetch('/oauth/authorize/consent', {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({
					...Object.fromEntries(new URLSearchParams(originalParams)),
					consent: 'approve'
				}),
				credentials: 'include',
				redirect: 'manual'
			});

			// Handle redirect response
			if (response.type === 'opaqueredirect' || response.status === 302) {
				const redirectUrl = response.headers.get('Location');
				if (redirectUrl) {
					window.location.href = redirectUrl;
					return;
				}
			}

			const data = await response.json();
			if (data.redirect_uri) {
				window.location.href = data.redirect_uri;
			} else {
				throw new Error('Authorization failed');
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Authorization failed';
			loading = false;
		}
	}

	async function deny() {
		loading = true;

		try {
			const response = await fetch('/oauth/authorize/consent', {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({
					...Object.fromEntries(new URLSearchParams(originalParams)),
					consent: 'deny'
				}),
				credentials: 'include'
			});

			const data = await response.json();
			if (data.redirect_uri) {
				window.location.href = data.redirect_uri;
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to deny authorization';
			loading = false;
		}
	}

	// Scope descriptions
	const scopeDescriptions: Record<string, string> = {
		openid: 'Verify your identity',
		profile: 'View your basic profile information',
		email: 'View your email address',
		offline_access: 'Access your data when you are not using the application',
		address: 'View your address',
		phone: 'View your phone number'
	};

	function getScopeDescription(scope: string): string {
		return scopeDescriptions[scope] || scope;
	}

	function formatAuthorizationDetail(detail: Record<string, unknown>): string {
		const type = detail.type as string;
		const parts = [type];

		if (detail.instructedAmount) {
			const amount = detail.instructedAmount as { currency: string; amount: string };
			parts.push(`${amount.currency} ${amount.amount}`);
		}

		return parts.join(': ');
	}
</script>

<svelte:head>
	<title>Authorize Application - OryxID</title>
</svelte:head>

<div class="min-h-screen bg-gradient-to-br from-purple-50 to-indigo-100 flex items-center justify-center p-4">
	<Card class="w-full max-w-md">
		<div class="p-8">
			{#if loading && !authInfo}
				<div class="flex items-center justify-center py-12">
					<svg class="animate-spin h-8 w-8 text-purple-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
						<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
						<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
					</svg>
				</div>
			{:else if error}
				<div class="text-center">
					<div class="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
						<svg class="w-8 h-8 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
						</svg>
					</div>
					<h2 class="text-xl font-semibold text-gray-900 mb-2">Authorization Error</h2>
					<p class="text-gray-500">{error}</p>
				</div>
			{:else if authInfo}
				<div class="text-center mb-8">
					<div class="w-16 h-16 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-4">
						<svg class="w-8 h-8 text-purple-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
						</svg>
					</div>
					<h1 class="text-2xl font-bold text-gray-900">Authorize Application</h1>
				</div>

				<div class="space-y-6">
					<div class="p-4 bg-purple-50 border border-purple-200 rounded-xl text-center">
						<p class="text-sm text-purple-700 font-medium mb-1">Application</p>
						<p class="text-xl font-semibold text-purple-900">{authInfo.client_name}</p>
						<p class="text-xs text-purple-600 mt-1 font-mono">{authInfo.client_id}</p>
					</div>

					{#if authInfo.scope}
						<div>
							<Label>This application would like to:</Label>
							<ul class="mt-3 space-y-2">
								{#each authInfo.scope.split(' ').filter(s => s) as scope}
									<li class="flex items-center gap-3 p-3 bg-gray-50 rounded-lg">
										<svg class="w-5 h-5 text-green-600 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
											<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
										</svg>
										<span class="text-gray-700">{getScopeDescription(scope)}</span>
									</li>
								{/each}
							</ul>
						</div>
					{/if}

					{#if authInfo.authorization_details && authInfo.authorization_details.length > 0}
						<div>
							<Label>Rich Authorization Requests:</Label>
							<ul class="mt-3 space-y-2">
								{#each authInfo.authorization_details as detail}
									<li class="p-3 bg-blue-50 border border-blue-200 rounded-lg">
										<p class="font-medium text-blue-900">{detail.type}</p>
										{#if detail.instructedAmount}
											<p class="text-sm text-blue-700 mt-1">
												Amount: {(detail.instructedAmount as {currency: string, amount: string}).currency} {(detail.instructedAmount as {currency: string, amount: string}).amount}
											</p>
										{/if}
									</li>
								{/each}
							</ul>
						</div>
					{/if}

					<div class="p-4 bg-gray-50 rounded-xl">
						<p class="text-xs text-gray-500">
							By clicking "Allow", you authorize <span class="font-medium">{authInfo.client_name}</span> to access the above information.
						</p>
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
							Allow
						</Button>
					</div>
				</div>
			{/if}

			<div class="mt-8 pt-6 border-t border-gray-100 text-center">
				<p class="text-xs text-gray-400">
					OryxID - OAuth 2.0 / OpenID Connect Server
				</p>
			</div>
		</div>
	</Card>
</div>
