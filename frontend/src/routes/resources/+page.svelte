<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, Button, Input, Label, Badge } from '$lib/components/ui';
	import { audiencesApi, scopesApi } from '$lib/api';
	import type { Audience, Scope, CreateAudienceRequest } from '$lib/types';

	let audiences: Audience[] = [];
	let scopes: Scope[] = [];
	let loading = true;
	let error: string | null = null;

	// Modal state
	let showModal = false;
	let modalMode: 'create' | 'edit' = 'create';
	let selectedAudience: Audience | null = null;
	let saving = false;

	// Form state
	let formData: CreateAudienceRequest = {
		identifier: '',
		name: '',
		description: '',
		scope_ids: []
	};

	onMount(async () => {
		await loadData();
	});

	async function loadData() {
		try {
			loading = true;
			[audiences, scopes] = await Promise.all([
				audiencesApi.list(),
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
		selectedAudience = null;
		formData = {
			identifier: '',
			name: '',
			description: '',
			scope_ids: []
		};
		showModal = true;
	}

	function openEditModal(audience: Audience) {
		modalMode = 'edit';
		selectedAudience = audience;
		formData = {
			identifier: audience.identifier,
			name: audience.name,
			description: audience.description || '',
			scope_ids: audience.scopes?.map(s => s.id) || []
		};
		showModal = true;
	}

	async function handleSubmit() {
		if (!formData.identifier.trim() || !formData.name.trim()) {
			error = 'Identifier and name are required';
			return;
		}

		saving = true;
		error = null;

		try {
			if (modalMode === 'create') {
				await audiencesApi.create(formData);
			} else if (modalMode === 'edit' && selectedAudience) {
				await audiencesApi.update(selectedAudience.id, formData);
			}

			showModal = false;
			await loadData();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to save API resource';
		} finally {
			saving = false;
		}
	}

	async function handleDelete(audience: Audience) {
		if (!confirm(`Are you sure you want to delete "${audience.name}"?`)) {
			return;
		}

		try {
			await audiencesApi.delete(audience.id);
			await loadData();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to delete API resource';
		}
	}

	function toggleScope(scopeId: string) {
		if (formData.scope_ids?.includes(scopeId)) {
			formData.scope_ids = formData.scope_ids.filter(id => id !== scopeId);
		} else {
			formData.scope_ids = [...(formData.scope_ids || []), scopeId];
		}
	}
</script>

<div class="space-y-6">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-bold text-gray-900">API Resources</h1>
			<p class="text-gray-600 mt-1">Register your APIs and define which scopes they accept</p>
		</div>
		<Button on:click={openCreateModal}>
			<svg class="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
			</svg>
			New API
		</Button>
	</div>

	{#if error}
		<div class="p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">{error}</div>
	{/if}

	{#if loading}
		<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
			{#each [1, 2] as _}
				<Card class="p-6">
					<div class="animate-pulse space-y-4">
						<div class="h-4 bg-gray-200 rounded w-1/2"></div>
						<div class="h-3 bg-gray-200 rounded w-3/4"></div>
					</div>
				</Card>
			{/each}
		</div>
	{:else if audiences.length === 0}
		<Card class="p-12 text-center">
			<div class="w-16 h-16 mx-auto bg-gray-100 rounded-full flex items-center justify-center mb-4">
				<svg class="w-8 h-8 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
					<path
						stroke-linecap="round"
						stroke-linejoin="round"
						stroke-width="2"
						d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"
					/>
				</svg>
			</div>
			<h3 class="text-lg font-medium text-gray-900 mb-2">No API resources registered</h3>
			<p class="text-gray-500 mb-6">Register your APIs to define which scopes they accept for token validation.</p>
			<Button on:click={openCreateModal}>Register API</Button>
		</Card>
	{:else}
		<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
			{#each audiences as audience}
				<Card class="p-6 hover:shadow-md transition-shadow">
					<div class="flex items-start justify-between mb-3">
						<div>
							<h3 class="text-lg font-semibold text-gray-900">{audience.name}</h3>
							<code class="text-sm text-gray-500 bg-gray-100 px-2 py-0.5 rounded">{audience.identifier}</code>
						</div>
					</div>

					<p class="text-sm text-gray-600 mb-4">
						{audience.description || 'No description'}
					</p>

					{#if audience.scopes && audience.scopes.length > 0}
						<div class="mb-4">
							<p class="text-xs text-gray-500 mb-2">Accepted scopes:</p>
							<div class="flex flex-wrap gap-1">
								{#each audience.scopes as scope}
									<Badge variant="secondary">{scope.name}</Badge>
								{/each}
							</div>
						</div>
					{:else}
						<p class="text-xs text-gray-400 mb-4">No scopes assigned</p>
					{/if}

					<div class="flex gap-2">
						<Button variant="outline" class="flex-1" on:click={() => openEditModal(audience)}>
							Edit
						</Button>
						<Button variant="destructive" on:click={() => handleDelete(audience)}>
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
				class="fixed inset-0 transition-opacity bg-gray-500 bg-opacity-75"
				on:click={() => (showModal = false)}
				on:keydown={(e) => e.key === 'Escape' && (showModal = false)}
				role="button"
				tabindex="0"
			></div>

			<div
				class="inline-block w-full max-w-lg overflow-hidden text-left align-middle transition-all transform bg-white rounded-lg shadow-xl"
			>
				<div class="px-6 py-4 border-b border-gray-200">
					<h3 class="text-lg font-semibold text-gray-900">
						{modalMode === 'create' ? 'Register API' : 'Edit API'}
					</h3>
				</div>

				<div class="px-6 py-4 max-h-[60vh] overflow-y-auto">
					<form on:submit|preventDefault={handleSubmit} class="space-y-4">
						<div>
							<Label for="identifier">API Identifier *</Label>
							<Input
								id="identifier"
								bind:value={formData.identifier}
								placeholder="https://api.example.com"
								required
							/>
							<p class="mt-1 text-xs text-gray-500">
								The unique identifier for this API (typically the base URL)
							</p>
						</div>

						<div>
							<Label for="name">Name *</Label>
							<Input
								id="name"
								bind:value={formData.name}
								placeholder="Billing API"
								required
							/>
						</div>

						<div>
							<Label for="description">Description</Label>
							<Input
								id="description"
								bind:value={formData.description}
								placeholder="Internal billing service API"
							/>
						</div>

						<div>
							<Label>Accepted Scopes</Label>
							<p class="text-xs text-gray-500 mb-2">
								Select which scopes are valid for this API
							</p>
							<div class="border rounded-lg p-3 max-h-48 overflow-y-auto space-y-2">
								{#if scopes.length === 0}
									<p class="text-sm text-gray-400">No scopes available. Create scopes first.</p>
								{:else}
									{#each scopes as scope}
										<label class="flex items-center gap-2 cursor-pointer hover:bg-gray-50 p-1 rounded">
											<input
												type="checkbox"
												checked={formData.scope_ids?.includes(scope.id)}
												on:change={() => toggleScope(scope.id)}
												class="rounded text-purple-600"
											/>
											<span class="text-sm font-medium">{scope.name}</span>
											{#if scope.description}
												<span class="text-xs text-gray-400">- {scope.description}</span>
											{/if}
										</label>
									{/each}
								{/if}
							</div>
						</div>
					</form>
				</div>

				<div class="px-6 py-4 border-t border-gray-200 flex justify-end gap-3">
					<Button variant="outline" on:click={() => (showModal = false)}>Cancel</Button>
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
							{modalMode === 'create' ? 'Register' : 'Save Changes'}
						{/if}
					</Button>
				</div>
			</div>
		</div>
	</div>
{/if}
