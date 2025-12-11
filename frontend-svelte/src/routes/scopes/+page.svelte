<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, Button, Input, Label, Badge } from '$lib/components/ui';
	import { scopesApi } from '$lib/api';
	import type { Scope, CreateScopeRequest } from '$lib/types';

	let scopes: Scope[] = [];
	let loading = true;
	let error: string | null = null;

	// Modal state
	let showModal = false;
	let modalMode: 'create' | 'edit' = 'create';
	let selectedScope: Scope | null = null;
	let saving = false;

	// Form state
	let formData: CreateScopeRequest = {
		name: '',
		description: '',
		is_default: false
	};

	onMount(async () => {
		await loadData();
	});

	async function loadData() {
		try {
			loading = true;
			scopes = await scopesApi.list();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load scopes';
		} finally {
			loading = false;
		}
	}

	function openCreateModal() {
		modalMode = 'create';
		selectedScope = null;
		formData = {
			name: '',
			description: '',
			is_default: false
		};
		showModal = true;
	}

	function openEditModal(scope: Scope) {
		modalMode = 'edit';
		selectedScope = scope;
		formData = {
			name: scope.name,
			description: scope.description || '',
			is_default: scope.is_default
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
			if (modalMode === 'create') {
				await scopesApi.create(formData);
			} else if (modalMode === 'edit' && selectedScope) {
				await scopesApi.update(selectedScope.id, formData);
			}

			showModal = false;
			await loadData();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to save scope';
		} finally {
			saving = false;
		}
	}

	async function handleDelete(scope: Scope) {
		if (!confirm(`Are you sure you want to delete "${scope.name}"?`)) {
			return;
		}

		try {
			await scopesApi.delete(scope.id);
			await loadData();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to delete scope';
		}
	}

	// Common OAuth2 scopes for quick creation
	const commonScopes = [
		{ name: 'openid', description: 'OpenID Connect scope' },
		{ name: 'profile', description: 'Access to user profile information' },
		{ name: 'email', description: 'Access to user email' },
		{ name: 'offline_access', description: 'Request refresh tokens' },
		{ name: 'read', description: 'Read access to resources' },
		{ name: 'write', description: 'Write access to resources' }
	];

	function addCommonScope(scope: { name: string; description: string }) {
		formData.name = scope.name;
		formData.description = scope.description;
	}
</script>

<div class="space-y-6">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-bold text-gray-900">Scopes</h1>
			<p class="text-gray-600 mt-1">Define OAuth2 access scopes for your applications</p>
		</div>
		<Button on:click={openCreateModal}>
			<svg class="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
			</svg>
			New Scope
		</Button>
	</div>

	{#if error}
		<div class="p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">{error}</div>
	{/if}

	{#if loading}
		<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
			{#each [1, 2, 3] as _}
				<Card class="p-6">
					<div class="animate-pulse space-y-4">
						<div class="h-4 bg-gray-200 rounded w-1/2"></div>
						<div class="h-3 bg-gray-200 rounded w-3/4"></div>
					</div>
				</Card>
			{/each}
		</div>
	{:else if scopes.length === 0}
		<Card class="p-12 text-center">
			<div class="w-16 h-16 mx-auto bg-gray-100 rounded-full flex items-center justify-center mb-4">
				<svg class="w-8 h-8 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
					<path
						stroke-linecap="round"
						stroke-linejoin="round"
						stroke-width="2"
						d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
					/>
				</svg>
			</div>
			<h3 class="text-lg font-medium text-gray-900 mb-2">No scopes defined</h3>
			<p class="text-gray-500 mb-6">Create OAuth2 scopes to control access permissions.</p>
			<Button on:click={openCreateModal}>Create Scope</Button>
		</Card>
	{:else}
		<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
			{#each scopes as scope}
				<Card class="p-6 hover:shadow-md transition-shadow">
					<div class="flex items-start justify-between mb-3">
						<div class="flex items-center gap-2">
							<code class="text-lg font-semibold text-gray-900">{scope.name}</code>
							{#if scope.is_default}
								<Badge variant="secondary">Default</Badge>
							{/if}
						</div>
					</div>

					<p class="text-sm text-gray-600 mb-4 line-clamp-2">
						{scope.description || 'No description'}
					</p>

					<div class="flex gap-2">
						<Button variant="outline" class="flex-1" on:click={() => openEditModal(scope)}>
							Edit
						</Button>
						<Button variant="destructive" on:click={() => handleDelete(scope)}>
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
				class="inline-block w-full max-w-md overflow-hidden text-left align-middle transition-all transform bg-white rounded-lg shadow-xl"
			>
				<div class="px-6 py-4 border-b border-gray-200">
					<h3 class="text-lg font-semibold text-gray-900">
						{modalMode === 'create' ? 'Create Scope' : 'Edit Scope'}
					</h3>
				</div>

				<div class="px-6 py-4">
					<form on:submit|preventDefault={handleSubmit} class="space-y-4">
						{#if modalMode === 'create'}
							<div>
								<Label>Quick Add Common Scopes</Label>
								<div class="mt-2 flex flex-wrap gap-2">
									{#each commonScopes as scope}
										<button
											type="button"
											class="px-2 py-1 text-xs bg-gray-100 hover:bg-gray-200 rounded transition-colors"
											on:click={() => addCommonScope(scope)}
										>
											{scope.name}
										</button>
									{/each}
								</div>
							</div>
						{/if}

						<div>
							<Label for="name">Name *</Label>
							<Input
								id="name"
								bind:value={formData.name}
								placeholder="read:users"
								required
								pattern="[a-z0-9:_-]+"
							/>
							<p class="mt-1 text-xs text-gray-500">
								Lowercase letters, numbers, colons, underscores, and hyphens only
							</p>
						</div>

						<div>
							<Label for="description">Description</Label>
							<Input
								id="description"
								bind:value={formData.description}
								placeholder="Read access to user data"
							/>
						</div>

						<div>
							<label class="flex items-center gap-2">
								<input
									type="checkbox"
									bind:checked={formData.is_default}
									class="rounded text-purple-600"
								/>
								<span class="text-sm">Include by default in all applications</span>
							</label>
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
							{modalMode === 'create' ? 'Create' : 'Save Changes'}
						{/if}
					</Button>
				</div>
			</div>
		</div>
	</div>
{/if}
