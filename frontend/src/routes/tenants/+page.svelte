<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, Button, Input, Label, Badge } from '$lib/components/ui';
	import { tenantsApi } from '$lib/api';
	import type { Tenant, CreateTenantRequest } from '$lib/types';

	let tenants: Tenant[] = [];
	let loading = true;
	let error: string | null = null;
	let searchQuery = '';

	// Modal state
	let showModal = false;
	let modalMode: 'create' | 'edit' | 'view' = 'create';
	let selectedTenant: Tenant | null = null;
	let saving = false;

	// Form state
	let formData: CreateTenantRequest = {
		name: '',
		type: 'operator',
		email: '',
		certificate_subject: '',
		description: ''
	};

	const tenantTypes = [
		{ value: 'operator', label: 'Operator' },
		{ value: 'authority', label: 'Authority' },
		{ value: 'emergency_service', label: 'Emergency Service' }
	];

	onMount(async () => {
		await loadData();
	});

	async function loadData() {
		try {
			loading = true;
			tenants = await tenantsApi.list(searchQuery || undefined);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load tenants';
		} finally {
			loading = false;
		}
	}

	function openCreateModal() {
		modalMode = 'create';
		selectedTenant = null;
		formData = {
			name: '',
			type: 'operator',
			email: '',
			certificate_subject: '',
			description: ''
		};
		showModal = true;
	}

	function openViewModal(tenant: Tenant) {
		modalMode = 'view';
		selectedTenant = tenant;
		showModal = true;
	}

	function openEditModal(tenant: Tenant) {
		modalMode = 'edit';
		selectedTenant = tenant;
		formData = {
			name: tenant.name,
			type: tenant.type,
			email: tenant.email,
			certificate_subject: tenant.certificate_subject || '',
			description: tenant.description || ''
		};
		showModal = true;
	}

	async function handleSubmit() {
		if (!formData.name.trim() || !formData.email.trim()) {
			error = 'Name and email are required';
			return;
		}

		saving = true;
		error = null;

		try {
			if (modalMode === 'create') {
				await tenantsApi.create(formData);
			} else if (modalMode === 'edit' && selectedTenant) {
				await tenantsApi.update(selectedTenant.id, formData);
			}
			showModal = false;
			await loadData();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to save tenant';
		} finally {
			saving = false;
		}
	}

	async function handleDelete(tenant: Tenant) {
		if (!confirm(`Are you sure you want to delete "${tenant.name}"?`)) {
			return;
		}

		try {
			await tenantsApi.delete(tenant.id);
			await loadData();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to delete tenant';
		}
	}

	async function handleSuspend(tenant: Tenant) {
		if (!confirm(`Are you sure you want to suspend "${tenant.name}"?`)) {
			return;
		}

		try {
			await tenantsApi.suspend(tenant.id);
			await loadData();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to suspend tenant';
		}
	}

	async function handleActivate(tenant: Tenant) {
		try {
			await tenantsApi.activate(tenant.id);
			await loadData();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to activate tenant';
		}
	}

	function getStatusColor(status: string) {
		switch (status) {
			case 'active':
				return 'default';
			case 'suspended':
				return 'secondary';
			case 'revoked':
				return 'destructive';
			default:
				return 'outline';
		}
	}

	function getTypeLabel(type: string) {
		return tenantTypes.find((t) => t.value === type)?.label || type;
	}
</script>

<div class="space-y-6">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-semibold text-gray-900">Tenants</h1>
			<p class="text-gray-500 mt-1">Manage multi-tenant organizations (TrustSky USSP)</p>
		</div>
		<Button on:click={openCreateModal}>
			<svg class="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
			</svg>
			New Tenant
		</Button>
	</div>

	{#if error}
		<div class="p-4 bg-red-50 border border-red-200 rounded-xl text-red-700">{error}</div>
	{/if}

	<div class="flex gap-4">
		<div class="flex-1">
			<Input
				type="search"
				placeholder="Search tenants..."
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
	{:else if tenants.length === 0}
		<Card class="p-12 text-center">
			<div class="w-16 h-16 mx-auto bg-gray-100 rounded-full flex items-center justify-center mb-4">
				<svg class="w-8 h-8 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
					<path
						stroke-linecap="round"
						stroke-linejoin="round"
						stroke-width="2"
						d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"
					/>
				</svg>
			</div>
			<h3 class="text-lg font-medium text-gray-900 mb-2">No tenants yet</h3>
			<p class="text-gray-500 mb-6">Create your first tenant to enable multi-tenancy.</p>
			<Button on:click={openCreateModal}>Create Tenant</Button>
		</Card>
	{:else}
		<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
			{#each tenants as tenant}
				<Card class="p-6 hover:shadow-md transition-shadow">
					<div class="flex items-start justify-between mb-4">
						<div>
							<h3 class="font-semibold text-gray-900">{tenant.name}</h3>
							<p class="text-sm text-gray-500 mt-1">{tenant.email}</p>
						</div>
						<div class="flex gap-2">
							<Badge variant={getStatusColor(tenant.status)}>{tenant.status}</Badge>
						</div>
					</div>

					<div class="space-y-2 text-sm text-gray-600 mb-4">
						<div class="flex items-center gap-2">
							<span class="font-medium">Type:</span>
							<Badge variant="outline">{getTypeLabel(tenant.type)}</Badge>
						</div>
						{#if tenant.description}
							<p class="text-gray-500 line-clamp-2">{tenant.description}</p>
						{/if}
					</div>

					<div class="flex gap-2">
						<Button variant="outline" class="flex-1" on:click={() => openViewModal(tenant)}>
							View
						</Button>
						<Button variant="outline" class="flex-1" on:click={() => openEditModal(tenant)}>
							Edit
						</Button>
						{#if tenant.status === 'active'}
							<Button variant="secondary" on:click={() => handleSuspend(tenant)}>
								<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
									<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z" />
								</svg>
							</Button>
						{:else if tenant.status === 'suspended'}
							<Button variant="default" on:click={() => handleActivate(tenant)}>
								<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
									<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
									<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
								</svg>
							</Button>
						{/if}
						<Button variant="destructive" on:click={() => handleDelete(tenant)}>
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
				on:click={() => (showModal = false)}
				on:keydown={(e) => e.key === 'Escape' && (showModal = false)}
				role="button"
				tabindex="0"
			></div>

			<div class="inline-block w-full max-w-lg overflow-hidden text-left align-middle transition-all transform bg-white rounded-2xl shadow-xl">
				<div class="px-6 py-4 border-b border-gray-100">
					<h3 class="text-lg font-semibold text-gray-900">
						{#if modalMode === 'create'}
							Create Tenant
						{:else if modalMode === 'edit'}
							Edit Tenant
						{:else}
							Tenant Details
						{/if}
					</h3>
				</div>

				<div class="px-6 py-4 max-h-[70vh] overflow-y-auto">
					{#if modalMode === 'view' && selectedTenant}
						<div class="space-y-4">
							<div>
								<Label>Name</Label>
								<p class="mt-1 text-gray-900">{selectedTenant.name}</p>
							</div>
							<div>
								<Label>Email</Label>
								<p class="mt-1 text-gray-900">{selectedTenant.email}</p>
							</div>
							<div>
								<Label>Type</Label>
								<p class="mt-1"><Badge variant="outline">{getTypeLabel(selectedTenant.type)}</Badge></p>
							</div>
							<div>
								<Label>Status</Label>
								<p class="mt-1"><Badge variant={getStatusColor(selectedTenant.status)}>{selectedTenant.status}</Badge></p>
							</div>
							{#if selectedTenant.certificate_subject}
								<div>
									<Label>Certificate Subject</Label>
									<code class="block mt-1 p-2 bg-gray-100 rounded text-sm break-all">{selectedTenant.certificate_subject}</code>
								</div>
							{/if}
							{#if selectedTenant.description}
								<div>
									<Label>Description</Label>
									<p class="mt-1 text-gray-600">{selectedTenant.description}</p>
								</div>
							{/if}
							<div>
								<Label>Tenant ID</Label>
								<code class="block mt-1 p-2 bg-gray-100 rounded text-sm break-all">{selectedTenant.id}</code>
								<p class="text-xs text-gray-500 mt-1">Use this ID in JWT tokens as tenant_id claim</p>
							</div>
						</div>
					{:else}
						<form on:submit|preventDefault={handleSubmit} class="space-y-4">
							<div>
								<Label for="name">Name *</Label>
								<Input id="name" bind:value={formData.name} placeholder="Acme Drone Operations" required />
							</div>

							<div>
								<Label for="email">Email *</Label>
								<Input id="email" type="email" bind:value={formData.email} placeholder="admin@acme.com" required />
							</div>

							<div>
								<Label>Type</Label>
								<div class="mt-2 flex gap-4 flex-wrap">
									{#each tenantTypes as type}
										<label class="flex items-center gap-2">
											<input type="radio" bind:group={formData.type} value={type.value} class="text-primary" />
											<span class="text-sm">{type.label}</span>
										</label>
									{/each}
								</div>
							</div>

							<div>
								<Label for="certificate_subject">Certificate Subject (Optional)</Label>
								<Input id="certificate_subject" bind:value={formData.certificate_subject} placeholder="CN=acme.com,O=Acme Inc" />
								<p class="text-xs text-gray-500 mt-1">For mTLS client certificate authentication</p>
							</div>

							<div>
								<Label for="description">Description</Label>
								<Input id="description" bind:value={formData.description} placeholder="Commercial drone operator" />
							</div>
						</form>
					{/if}
				</div>

				<div class="px-6 py-4 border-t border-gray-100 flex justify-end gap-3">
					<Button variant="outline" on:click={() => (showModal = false)}>
						{modalMode === 'view' ? 'Close' : 'Cancel'}
					</Button>
					{#if modalMode !== 'view'}
						<Button on:click={handleSubmit} disabled={saving}>
							{#if saving}
								<svg class="animate-spin -ml-1 mr-2 h-4 w-4" fill="none" viewBox="0 0 24 24">
									<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
									<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
								</svg>
								Saving...
							{:else}
								{modalMode === 'create' ? 'Create' : 'Save Changes'}
							{/if}
						</Button>
					{/if}
				</div>
			</div>
		</div>
	</div>
{/if}
