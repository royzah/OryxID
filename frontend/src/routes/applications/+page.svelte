<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, Button, Input, Label, Badge } from '$lib/components/ui';
	import { applicationsApi, scopesApi } from '$lib/api';
	import type { Application, Scope, CreateApplicationRequest } from '$lib/types';

	let applications: Application[] = [];
	let scopes: Scope[] = [];
	let loading = true;
	let error: string | null = null;
	let searchQuery = '';

	// Modal state
	let showModal = false;
	let modalMode: 'create' | 'edit' | 'view' | 'secret' = 'create';
	let selectedApp: Application | null = null;
	let newlyCreatedApp: Application | null = null;
	let saving = false;
	let secretCopied = false;

	// Form state
	let formData: CreateApplicationRequest = {
		name: '',
		description: '',
		client_type: 'confidential',
		grant_types: ['authorization_code'],
		response_types: ['code'],
		redirect_uris: [''],
		post_logout_uris: [],
		scope_ids: [],
		skip_authorization: false
	};

	onMount(async () => {
		await loadData();
	});

	async function loadData() {
		try {
			loading = true;
			[applications, scopes] = await Promise.all([
				applicationsApi.list(searchQuery || undefined),
				scopesApi.list()
			]);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load data';
		} finally {
			loading = false;
		}
	}

	function openCreateModal() {
		modalMode = 'create';
		selectedApp = null;
		newlyCreatedApp = null;
		formData = {
			name: '',
			description: '',
			client_type: 'confidential',
			grant_types: ['authorization_code'],
			response_types: ['code'],
			redirect_uris: [''],
			post_logout_uris: [],
			scope_ids: [],
			skip_authorization: false
		};
		showModal = true;
	}

	function openViewModal(app: Application) {
		modalMode = 'view';
		selectedApp = app;
		showModal = true;
	}

	function openEditModal(app: Application) {
		modalMode = 'edit';
		selectedApp = app;
		formData = {
			name: app.name,
			description: app.description || '',
			client_type: app.client_type,
			grant_types: [...app.grant_types],
			response_types: [...app.response_types],
			redirect_uris: app.redirect_uris.length > 0 ? [...app.redirect_uris] : [''],
			post_logout_uris: [...app.post_logout_uris],
			scope_ids: app.scopes?.map((s) => s.id) || [],
			skip_authorization: app.skip_authorization
		};
		showModal = true;
	}

	async function handleSubmit() {
		if (!formData.name.trim()) {
			error = 'Name is required';
			return;
		}

		saving = true;
		error = null;

		try {
			const cleanData = {
				...formData,
				redirect_uris: formData.redirect_uris.filter((uri) => uri.trim())
			};

			if (modalMode === 'create') {
				const created = await applicationsApi.create(cleanData);
				newlyCreatedApp = created;
				modalMode = 'secret';
				secretCopied = false;
				await loadData();
			} else if (modalMode === 'edit' && selectedApp) {
				await applicationsApi.update(selectedApp.id, cleanData);
				showModal = false;
				await loadData();
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to save application';
		} finally {
			saving = false;
		}
	}

	async function handleDelete(app: Application) {
		if (!confirm(`Are you sure you want to delete "${app.name}"?`)) {
			return;
		}

		try {
			await applicationsApi.delete(app.id);
			await loadData();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to delete application';
		}
	}

	function addRedirectUri() {
		formData.redirect_uris = [...formData.redirect_uris, ''];
	}

	function removeRedirectUri(index: number) {
		formData.redirect_uris = formData.redirect_uris.filter((_, i) => i !== index);
	}

	function toggleGrantType(type: string) {
		if (formData.grant_types.includes(type)) {
			formData.grant_types = formData.grant_types.filter((t) => t !== type);
		} else {
			formData.grant_types = [...formData.grant_types, type];
		}
	}

	function toggleScope(scopeId: string) {
		if (formData.scope_ids?.includes(scopeId)) {
			formData.scope_ids = formData.scope_ids.filter((id) => id !== scopeId);
		} else {
			formData.scope_ids = [...(formData.scope_ids || []), scopeId];
		}
	}

	async function copyToClipboard(text: string, type: 'id' | 'secret') {
		await navigator.clipboard.writeText(text);
		if (type === 'secret') {
			secretCopied = true;
		}
	}

	function closeSecretModal() {
		showModal = false;
		newlyCreatedApp = null;
	}

	const grantTypes = [
		{ value: 'authorization_code', label: 'Authorization Code' },
		{ value: 'client_credentials', label: 'Client Credentials' },
		{ value: 'refresh_token', label: 'Refresh Token' },
		{ value: 'urn:ietf:params:oauth:grant-type:device_code', label: 'Device Authorization (RFC 8628)' },
		{ value: 'urn:ietf:params:oauth:grant-type:token-exchange', label: 'Token Exchange (RFC 8693)' },
		{ value: 'urn:openid:params:grant-type:ciba', label: 'CIBA (OpenID Connect)' },
		{ value: 'implicit', label: 'Implicit (deprecated)' }
	];
</script>

<div class="space-y-6">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-semibold text-gray-900">Applications</h1>
			<p class="text-gray-500 mt-1">Manage OAuth2/OIDC client applications</p>
		</div>
		<Button on:click={openCreateModal}>
			<svg class="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
			</svg>
			New Application
		</Button>
	</div>

	{#if error}
		<div class="p-4 bg-red-50 border border-red-200 rounded-xl text-red-700">{error}</div>
	{/if}

	<div class="flex gap-4">
		<div class="flex-1">
			<Input
				type="search"
				placeholder="Search applications..."
				bind:value={searchQuery}
				on:input={() => loadData()}
			/>
		</div>
	</div>

	{#if loading}
		<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
			{#each [1, 2, 3] as _}
				<Card class="p-6">
					<div class="animate-pulse space-y-4">
						<div class="h-4 bg-gray-200 rounded w-3/4"></div>
						<div class="h-3 bg-gray-200 rounded w-1/2"></div>
						<div class="h-8 bg-gray-200 rounded w-full"></div>
					</div>
				</Card>
			{/each}
		</div>
	{:else if applications.length === 0}
		<Card class="p-12 text-center">
			<div class="w-16 h-16 mx-auto bg-gray-100 rounded-full flex items-center justify-center mb-4">
				<svg class="w-8 h-8 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
					<path
						stroke-linecap="round"
						stroke-linejoin="round"
						stroke-width="2"
						d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"
					/>
				</svg>
			</div>
			<h3 class="text-lg font-medium text-gray-900 mb-2">No applications yet</h3>
			<p class="text-gray-500 mb-6">Create your first OAuth2 client application to get started.</p>
			<Button on:click={openCreateModal}>Create Application</Button>
		</Card>
	{:else}
		<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
			{#each applications as app}
				<Card class="p-6 hover:shadow-md transition-shadow">
					<div class="flex items-start justify-between mb-4">
						<div>
							<h3 class="font-semibold text-gray-900">{app.name}</h3>
							<p class="text-sm text-gray-500 mt-1 line-clamp-2">
								{app.description || 'No description'}
							</p>
						</div>
						<Badge variant={app.client_type === 'confidential' ? 'default' : 'secondary'}>
							{app.client_type}
						</Badge>
					</div>

					<div class="space-y-2 text-sm text-gray-600 mb-4">
						<div class="flex items-center gap-2">
							<span class="font-medium">Client ID:</span>
							<code class="bg-gray-100 px-2 py-0.5 rounded text-xs truncate flex-1">
								{app.client_id}
							</code>
						</div>
						<div class="flex items-center gap-2 flex-wrap">
							<span class="font-medium">Grants:</span>
							{#each app.grant_types.slice(0, 2) as grant}
								<Badge variant="outline" class="text-xs">{grant}</Badge>
							{/each}
							{#if app.grant_types.length > 2}
								<Badge variant="outline" class="text-xs">+{app.grant_types.length - 2}</Badge>
							{/if}
						</div>
					</div>

					<div class="flex gap-2">
						<Button variant="outline" class="flex-1" on:click={() => openViewModal(app)}>
							View
						</Button>
						<Button variant="outline" class="flex-1" on:click={() => openEditModal(app)}>
							Edit
						</Button>
						<Button variant="destructive" on:click={() => handleDelete(app)}>
							<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
								<path
									stroke-linecap="round"
									stroke-linejoin="round"
									stroke-width="2"
									d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
								/>
							</svg>
						</Button>
					</div>
				</Card>
			{/each}
		</div>
	{/if}
</div>

<!-- Modal -->
{#if showModal}
	<div class="fixed inset-0 z-50 overflow-y-auto">
		<div class="flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:p-0">
			<div
				class="fixed inset-0 transition-opacity bg-gray-900/50 backdrop-blur-sm"
				on:click={() => modalMode !== 'secret' && (showModal = false)}
				on:keydown={(e) => e.key === 'Escape' && modalMode !== 'secret' && (showModal = false)}
				role="button"
				tabindex="0"
			></div>

			<div
				class="inline-block w-full max-w-2xl overflow-hidden text-left align-middle transition-all transform bg-white rounded-2xl shadow-xl"
			>
				<div class="px-6 py-4 border-b border-gray-100">
					<h3 class="text-lg font-semibold text-gray-900">
						{#if modalMode === 'secret'}
							Application Created
						{:else if modalMode === 'create'}
							Create Application
						{:else if modalMode === 'edit'}
							Edit Application
						{:else}
							Application Details
						{/if}
					</h3>
				</div>

				<div class="px-6 py-4 max-h-[70vh] overflow-y-auto">
					{#if modalMode === 'secret' && newlyCreatedApp}
						<!-- Secret display after creation -->
						<div class="space-y-6">
							<div class="p-4 bg-amber-50 border border-amber-200 rounded-xl">
								<div class="flex items-start gap-3">
									<svg class="w-5 h-5 text-amber-600 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
										<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
									</svg>
									<div>
										<p class="font-medium text-amber-800">Save your client secret</p>
										<p class="text-sm text-amber-700 mt-1">This is the only time you'll see this secret. Store it securely.</p>
									</div>
								</div>
							</div>

							<div>
								<Label>Application Name</Label>
								<p class="mt-1 text-gray-900 font-medium">{newlyCreatedApp.name}</p>
							</div>

							<div>
								<Label>Client ID</Label>
								<div class="mt-1 flex items-center gap-2">
									<code class="flex-1 p-3 bg-gray-50 border border-gray-200 rounded-lg text-sm font-mono break-all">
										{newlyCreatedApp.client_id}
									</code>
									<Button variant="outline" on:click={() => copyToClipboard(newlyCreatedApp?.client_id || '', 'id')}>
										<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
											<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
										</svg>
									</Button>
								</div>
							</div>

							{#if newlyCreatedApp.client_secret}
								<div>
									<Label>Client Secret</Label>
									<div class="mt-1 flex items-center gap-2">
										<code class="flex-1 p-3 bg-gray-900 text-green-400 rounded-lg text-sm font-mono break-all">
											{newlyCreatedApp.client_secret}
										</code>
										<Button variant="outline" on:click={() => copyToClipboard(newlyCreatedApp?.client_secret || '', 'secret')}>
											{#if secretCopied}
												<svg class="w-4 h-4 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
													<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
												</svg>
											{:else}
												<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
													<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
												</svg>
											{/if}
										</Button>
									</div>
								</div>
							{/if}
						</div>
					{:else if modalMode === 'view' && selectedApp}
						<div class="space-y-4">
							<div>
								<Label>Name</Label>
								<p class="mt-1 text-gray-900">{selectedApp.name}</p>
							</div>
							<div>
								<Label>Description</Label>
								<p class="mt-1 text-gray-900">{selectedApp.description || 'N/A'}</p>
							</div>
							<div>
								<Label>Client ID</Label>
								<code class="block mt-1 p-2 bg-gray-100 rounded text-sm break-all">
									{selectedApp.client_id}
								</code>
							</div>
							<div>
								<Label>Client Type</Label>
								<p class="mt-1">
									<Badge>{selectedApp.client_type}</Badge>
								</p>
							</div>
							<div>
								<Label>Grant Types</Label>
								<div class="mt-1 flex flex-wrap gap-2">
									{#each selectedApp.grant_types as grant}
										<Badge variant="outline">{grant}</Badge>
									{/each}
								</div>
							</div>
							<div>
								<Label>Redirect URIs</Label>
								<ul class="mt-1 space-y-1">
									{#each selectedApp.redirect_uris as uri}
										<li class="text-sm text-gray-600 font-mono">{uri}</li>
									{/each}
								</ul>
							</div>
							{#if selectedApp.scopes && selectedApp.scopes.length > 0}
								<div>
									<Label>Scopes</Label>
									<div class="mt-1 flex flex-wrap gap-2">
										{#each selectedApp.scopes as scope}
											<Badge variant="secondary">{scope.name}</Badge>
										{/each}
									</div>
								</div>
							{/if}
						</div>
					{:else}
						<form on:submit|preventDefault={handleSubmit} class="space-y-4">
							<div>
								<Label for="name">Name *</Label>
								<Input
									id="name"
									bind:value={formData.name}
									placeholder="My Application"
									required
								/>
							</div>

							<div>
								<Label for="description">Description</Label>
								<Input
									id="description"
									bind:value={formData.description}
									placeholder="Application description"
								/>
							</div>

							<div>
								<Label>Client Type</Label>
								<div class="mt-2 flex gap-4">
									<label class="flex items-center gap-2">
										<input
											type="radio"
											bind:group={formData.client_type}
											value="confidential"
											class="text-primary"
										/>
										<span class="text-sm">Confidential</span>
									</label>
									<label class="flex items-center gap-2">
										<input
											type="radio"
											bind:group={formData.client_type}
											value="public"
											class="text-primary"
										/>
										<span class="text-sm">Public</span>
									</label>
								</div>
							</div>

							<div>
								<Label>Grant Types</Label>
								<div class="mt-2 space-y-2">
									{#each grantTypes as grant}
										<label class="flex items-center gap-2">
											<input
												type="checkbox"
												checked={formData.grant_types.includes(grant.value)}
												on:change={() => toggleGrantType(grant.value)}
												class="rounded text-primary"
											/>
											<span class="text-sm">{grant.label}</span>
										</label>
									{/each}
								</div>
							</div>

							<div>
								<Label>Redirect URIs</Label>
								<div class="mt-2 space-y-2">
									{#each formData.redirect_uris as _uri, i}
										<div class="flex gap-2">
											<Input
												bind:value={formData.redirect_uris[i]}
												placeholder="https://example.com/callback"
												class="flex-1"
											/>
											{#if formData.redirect_uris.length > 1}
												<Button
													type="button"
													variant="outline"
													on:click={() => removeRedirectUri(i)}
												>
													<svg
														class="w-4 h-4"
														fill="none"
														viewBox="0 0 24 24"
														stroke="currentColor"
													>
														<path
															stroke-linecap="round"
															stroke-linejoin="round"
															stroke-width="2"
															d="M6 18L18 6M6 6l12 12"
														/>
													</svg>
												</Button>
											{/if}
										</div>
									{/each}
									<Button type="button" variant="outline" on:click={addRedirectUri}>
										Add URI
									</Button>
								</div>
							</div>

							{#if scopes.length > 0}
								<div>
									<Label>Scopes</Label>
									<div class="mt-2 space-y-2">
										{#each scopes as scope}
											<label class="flex items-center gap-2">
												<input
													type="checkbox"
													checked={formData.scope_ids?.includes(scope.id)}
													on:change={() => toggleScope(scope.id)}
													class="rounded text-primary"
												/>
												<span class="text-sm">{scope.name}</span>
												{#if scope.description}
													<span class="text-xs text-gray-500">- {scope.description}</span>
												{/if}
											</label>
										{/each}
									</div>
								</div>
							{/if}

							<div>
								<label class="flex items-center gap-2">
									<input
										type="checkbox"
										bind:checked={formData.skip_authorization}
										class="rounded text-primary"
									/>
									<span class="text-sm">Skip authorization prompt (first-party apps only)</span>
								</label>
							</div>
						</form>
					{/if}
				</div>

				<div class="px-6 py-4 border-t border-gray-100 flex justify-end gap-3">
					{#if modalMode === 'secret'}
						<Button on:click={closeSecretModal}>
							Done
						</Button>
					{:else}
						<Button variant="outline" on:click={() => (showModal = false)}>
							{modalMode === 'view' ? 'Close' : 'Cancel'}
						</Button>
						{#if modalMode !== 'view'}
							<Button on:click={handleSubmit} disabled={saving}>
								{#if saving}
									<svg class="animate-spin -ml-1 mr-2 h-4 w-4" fill="none" viewBox="0 0 24 24">
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
									Saving...
								{:else}
									{modalMode === 'create' ? 'Create' : 'Save Changes'}
								{/if}
							</Button>
						{/if}
					{/if}
				</div>
			</div>
		</div>
	</div>
{/if}
