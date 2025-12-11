<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, Button, Input, Label, Badge } from '$lib/components/ui';
	import { usersApi } from '$lib/api';
	import type { User, CreateUserRequest } from '$lib/types';

	let users: User[] = [];
	let loading = true;
	let error: string | null = null;
	let searchQuery = '';

	// Modal state
	let showModal = false;
	let modalMode: 'create' | 'edit' | 'view' = 'create';
	let selectedUser: User | null = null;
	let saving = false;

	// Form state
	let formData: CreateUserRequest = {
		username: '',
		email: '',
		password: '',
		is_active: true,
		is_admin: false
	};

	onMount(async () => {
		await loadData();
	});

	async function loadData() {
		try {
			loading = true;
			users = await usersApi.list(searchQuery || undefined);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load users';
		} finally {
			loading = false;
		}
	}

	function openCreateModal() {
		modalMode = 'create';
		selectedUser = null;
		formData = {
			username: '',
			email: '',
			password: '',
			is_active: true,
			is_admin: false
		};
		showModal = true;
	}

	function openViewModal(user: User) {
		modalMode = 'view';
		selectedUser = user;
		showModal = true;
	}

	function openEditModal(user: User) {
		modalMode = 'edit';
		selectedUser = user;
		formData = {
			username: user.username,
			email: user.email,
			password: '',
			is_active: user.is_active,
			is_admin: user.is_admin
		};
		showModal = true;
	}

	async function handleSubmit() {
		if (!formData.username.trim() || !formData.email.trim()) {
			error = 'Username and email are required';
			return;
		}

		if (modalMode === 'create' && !formData.password) {
			error = 'Password is required for new users';
			return;
		}

		saving = true;
		error = null;

		try {
			if (modalMode === 'create') {
				await usersApi.create(formData);
			} else if (modalMode === 'edit' && selectedUser) {
				// For updates, omit password if empty
				const { password, ...rest } = formData;
				const updateData = password ? formData : rest;
				await usersApi.update(selectedUser.id, updateData);
			}

			showModal = false;
			await loadData();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to save user';
		} finally {
			saving = false;
		}
	}

	async function handleDelete(user: User) {
		if (!confirm(`Are you sure you want to delete "${user.username}"?`)) {
			return;
		}

		try {
			await usersApi.delete(user.id);
			await loadData();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to delete user';
		}
	}

	function formatDate(dateStr: string): string {
		return new Date(dateStr).toLocaleDateString('en-US', {
			year: 'numeric',
			month: 'short',
			day: 'numeric'
		});
	}
</script>

<div class="space-y-6">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-bold text-gray-900">Users</h1>
			<p class="text-gray-600 mt-1">Manage user accounts and permissions</p>
		</div>
		<Button on:click={openCreateModal}>
			<svg class="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
			</svg>
			New User
		</Button>
	</div>

	{#if error}
		<div class="p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">{error}</div>
	{/if}

	<div class="flex gap-4">
		<div class="flex-1">
			<Input
				type="search"
				placeholder="Search users..."
				bind:value={searchQuery}
				on:input={() => loadData()}
			/>
		</div>
	</div>

	{#if loading}
		<Card class="overflow-hidden">
			<div class="animate-pulse">
				<div class="h-12 bg-gray-100"></div>
				{#each [1, 2, 3] as _}
					<div class="h-16 border-t border-gray-100 px-6 py-4">
						<div class="h-4 bg-gray-200 rounded w-1/4 mb-2"></div>
						<div class="h-3 bg-gray-200 rounded w-1/3"></div>
					</div>
				{/each}
			</div>
		</Card>
	{:else if users.length === 0}
		<Card class="p-12 text-center">
			<div class="w-16 h-16 mx-auto bg-gray-100 rounded-full flex items-center justify-center mb-4">
				<svg class="w-8 h-8 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
					<path
						stroke-linecap="round"
						stroke-linejoin="round"
						stroke-width="2"
						d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z"
					/>
				</svg>
			</div>
			<h3 class="text-lg font-medium text-gray-900 mb-2">No users found</h3>
			<p class="text-gray-500 mb-6">Create user accounts to allow access to your system.</p>
			<Button on:click={openCreateModal}>Create User</Button>
		</Card>
	{:else}
		<Card class="overflow-hidden">
			<table class="min-w-full divide-y divide-gray-200">
				<thead class="bg-gray-50">
					<tr>
						<th
							scope="col"
							class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
						>
							User
						</th>
						<th
							scope="col"
							class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
						>
							Status
						</th>
						<th
							scope="col"
							class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
						>
							Role
						</th>
						<th
							scope="col"
							class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
						>
							Created
						</th>
						<th scope="col" class="relative px-6 py-3">
							<span class="sr-only">Actions</span>
						</th>
					</tr>
				</thead>
				<tbody class="bg-white divide-y divide-gray-200">
					{#each users as user}
						<tr class="hover:bg-gray-50">
							<td class="px-6 py-4 whitespace-nowrap">
								<div class="flex items-center">
									<div
										class="w-10 h-10 flex-shrink-0 bg-purple-100 rounded-full flex items-center justify-center"
									>
										<span class="text-purple-600 font-medium">
											{user.username.charAt(0).toUpperCase()}
										</span>
									</div>
									<div class="ml-4">
										<div class="text-sm font-medium text-gray-900">{user.username}</div>
										<div class="text-sm text-gray-500">{user.email}</div>
									</div>
								</div>
							</td>
							<td class="px-6 py-4 whitespace-nowrap">
								<Badge variant={user.is_active ? 'default' : 'secondary'}>
									{user.is_active ? 'Active' : 'Inactive'}
								</Badge>
								{#if user.email_verified}
									<Badge variant="outline" class="ml-1">Verified</Badge>
								{/if}
							</td>
							<td class="px-6 py-4 whitespace-nowrap">
								{#if user.is_admin}
									<Badge variant="destructive">Admin</Badge>
								{:else}
									<Badge variant="outline">User</Badge>
								{/if}
							</td>
							<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
								{formatDate(user.created_at)}
							</td>
							<td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
								<div class="flex justify-end gap-2">
									<Button variant="ghost" on:click={() => openViewModal(user)}>View</Button>
									<Button variant="ghost" on:click={() => openEditModal(user)}>Edit</Button>
									<Button variant="ghost" class="text-red-600" on:click={() => handleDelete(user)}>
										Delete
									</Button>
								</div>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</Card>
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
						{modalMode === 'create'
							? 'Create User'
							: modalMode === 'edit'
								? 'Edit User'
								: 'User Details'}
					</h3>
				</div>

				<div class="px-6 py-4">
					{#if modalMode === 'view' && selectedUser}
						<div class="space-y-4">
							<div class="flex items-center gap-4">
								<div
									class="w-16 h-16 bg-purple-100 rounded-full flex items-center justify-center"
								>
									<span class="text-purple-600 text-2xl font-medium">
										{selectedUser.username.charAt(0).toUpperCase()}
									</span>
								</div>
								<div>
									<h4 class="text-lg font-semibold">{selectedUser.username}</h4>
									<p class="text-gray-500">{selectedUser.email}</p>
								</div>
							</div>

							<div class="grid grid-cols-2 gap-4">
								<div>
									<Label>Status</Label>
									<p class="mt-1">
										<Badge variant={selectedUser.is_active ? 'default' : 'secondary'}>
											{selectedUser.is_active ? 'Active' : 'Inactive'}
										</Badge>
									</p>
								</div>
								<div>
									<Label>Role</Label>
									<p class="mt-1">
										<Badge variant={selectedUser.is_admin ? 'destructive' : 'outline'}>
											{selectedUser.is_admin ? 'Admin' : 'User'}
										</Badge>
									</p>
								</div>
								<div>
									<Label>Email Verified</Label>
									<p class="mt-1">
										<Badge variant={selectedUser.email_verified ? 'default' : 'secondary'}>
											{selectedUser.email_verified ? 'Yes' : 'No'}
										</Badge>
									</p>
								</div>
								<div>
									<Label>Created</Label>
									<p class="mt-1 text-sm text-gray-600">
										{formatDate(selectedUser.created_at)}
									</p>
								</div>
							</div>

							{#if selectedUser.roles && selectedUser.roles.length > 0}
								<div>
									<Label>Roles</Label>
									<div class="mt-1 flex flex-wrap gap-2">
										{#each selectedUser.roles as role}
											<Badge variant="secondary">{role.name}</Badge>
										{/each}
									</div>
								</div>
							{/if}
						</div>
					{:else}
						<form on:submit|preventDefault={handleSubmit} class="space-y-4">
							<div>
								<Label for="username">Username *</Label>
								<Input
									id="username"
									bind:value={formData.username}
									placeholder="johndoe"
									required
								/>
							</div>

							<div>
								<Label for="email">Email *</Label>
								<Input
									id="email"
									type="email"
									bind:value={formData.email}
									placeholder="john@example.com"
									required
								/>
							</div>

							<div>
								<Label for="password">
									Password {modalMode === 'create' ? '*' : '(leave blank to keep current)'}
								</Label>
								<Input
									id="password"
									type="password"
									bind:value={formData.password}
									placeholder={modalMode === 'create' ? 'Enter password' : 'Enter new password'}
									required={modalMode === 'create'}
								/>
							</div>

							<div class="flex gap-4">
								<label class="flex items-center gap-2">
									<input
										type="checkbox"
										bind:checked={formData.is_active}
										class="rounded text-purple-600"
									/>
									<span class="text-sm">Active</span>
								</label>
								<label class="flex items-center gap-2">
									<input
										type="checkbox"
										bind:checked={formData.is_admin}
										class="rounded text-purple-600"
									/>
									<span class="text-sm">Admin</span>
								</label>
							</div>
						</form>
					{/if}
				</div>

				<div class="px-6 py-4 border-t border-gray-200 flex justify-end gap-3">
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
				</div>
			</div>
		</div>
	</div>
{/if}
