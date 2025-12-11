<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, Button, Input, Label, Badge } from '$lib/components/ui';
	import { auditApi } from '$lib/api';
	import type { AuditLog, AuditLogsResponse } from '$lib/types';

	let logs: AuditLog[] = [];
	let total = 0;
	let page = 1;
	let limit = 20;
	let loading = true;
	let error: string | null = null;

	// Filters
	let filterAction = '';
	let filterUserId = '';

	// Detail modal
	let showModal = false;
	let selectedLog: AuditLog | null = null;

	onMount(async () => {
		await loadData();
	});

	async function loadData() {
		try {
			loading = true;
			const response: AuditLogsResponse = await auditApi.list({
				page,
				limit,
				action: filterAction || undefined,
				user_id: filterUserId || undefined
			});
			logs = response.logs || [];
			total = response.total;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load audit logs';
		} finally {
			loading = false;
		}
	}

	function applyFilters() {
		page = 1;
		loadData();
	}

	function clearFilters() {
		filterAction = '';
		filterUserId = '';
		page = 1;
		loadData();
	}

	function nextPage() {
		if (page * limit < total) {
			page++;
			loadData();
		}
	}

	function prevPage() {
		if (page > 1) {
			page--;
			loadData();
		}
	}

	function viewDetails(log: AuditLog) {
		selectedLog = log;
		showModal = true;
	}

	function formatDate(dateStr: string): string {
		return new Date(dateStr).toLocaleString('en-US', {
			year: 'numeric',
			month: 'short',
			day: 'numeric',
			hour: '2-digit',
			minute: '2-digit',
			second: '2-digit'
		});
	}

	function getActionBadgeVariant(
		action: string
	): 'default' | 'secondary' | 'destructive' | 'outline' {
		if (action.includes('delete') || action.includes('revoke')) return 'destructive';
		if (action.includes('create') || action.includes('register')) return 'default';
		if (action.includes('update') || action.includes('modify')) return 'secondary';
		return 'outline';
	}

	function getStatusBadgeVariant(
		statusCode: number
	): 'default' | 'secondary' | 'destructive' | 'outline' {
		if (statusCode >= 200 && statusCode < 300) return 'default';
		if (statusCode >= 400 && statusCode < 500) return 'secondary';
		if (statusCode >= 500) return 'destructive';
		return 'outline';
	}

	const actionTypes = [
		'login',
		'logout',
		'token_issued',
		'token_revoked',
		'user_created',
		'user_updated',
		'user_deleted',
		'application_created',
		'application_updated',
		'application_deleted',
		'scope_created',
		'scope_updated',
		'scope_deleted'
	];
</script>

<div class="space-y-6">
	<div>
		<h1 class="text-2xl font-bold text-gray-900">Audit Logs</h1>
		<p class="text-gray-600 mt-1">Track system activity and security events</p>
	</div>

	{#if error}
		<div class="p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">{error}</div>
	{/if}

	<!-- Filters -->
	<Card class="p-4">
		<div class="flex flex-wrap gap-4 items-end">
			<div class="flex-1 min-w-[200px]">
				<Label for="action-filter">Action</Label>
				<select
					id="action-filter"
					bind:value={filterAction}
					class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-purple-500"
				>
					<option value="">All Actions</option>
					{#each actionTypes as action}
						<option value={action}>{action.replace(/_/g, ' ')}</option>
					{/each}
				</select>
			</div>
			<div class="flex-1 min-w-[200px]">
				<Label for="user-filter">User ID</Label>
				<Input
					id="user-filter"
					bind:value={filterUserId}
					placeholder="Filter by user ID"
					class="mt-1"
				/>
			</div>
			<div class="flex gap-2">
				<Button on:click={applyFilters}>Apply Filters</Button>
				<Button variant="outline" on:click={clearFilters}>Clear</Button>
			</div>
		</div>
	</Card>

	{#if loading}
		<Card class="overflow-hidden">
			<div class="animate-pulse">
				<div class="h-12 bg-gray-100"></div>
				{#each [1, 2, 3, 4, 5] as _}
					<div class="h-16 border-t border-gray-100 px-6 py-4">
						<div class="h-4 bg-gray-200 rounded w-1/4 mb-2"></div>
						<div class="h-3 bg-gray-200 rounded w-1/2"></div>
					</div>
				{/each}
			</div>
		</Card>
	{:else if logs.length === 0}
		<Card class="p-12 text-center">
			<div class="w-16 h-16 mx-auto bg-gray-100 rounded-full flex items-center justify-center mb-4">
				<svg class="w-8 h-8 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
					<path
						stroke-linecap="round"
						stroke-linejoin="round"
						stroke-width="2"
						d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
					/>
				</svg>
			</div>
			<h3 class="text-lg font-medium text-gray-900 mb-2">No audit logs found</h3>
			<p class="text-gray-500">
				{filterAction || filterUserId
					? 'Try adjusting your filters'
					: 'Audit logs will appear here as activity occurs'}
			</p>
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
							Timestamp
						</th>
						<th
							scope="col"
							class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
						>
							Action
						</th>
						<th
							scope="col"
							class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
						>
							Resource
						</th>
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
							IP Address
						</th>
						<th scope="col" class="relative px-6 py-3">
							<span class="sr-only">Details</span>
						</th>
					</tr>
				</thead>
				<tbody class="bg-white divide-y divide-gray-200">
					{#each logs as log}
						<tr class="hover:bg-gray-50">
							<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
								{formatDate(log.created_at)}
							</td>
							<td class="px-6 py-4 whitespace-nowrap">
								<Badge variant={getActionBadgeVariant(log.action)}>
									{log.action.replace(/_/g, ' ')}
								</Badge>
							</td>
							<td class="px-6 py-4 whitespace-nowrap">
								<div class="text-sm text-gray-900">{log.resource}</div>
								<div class="text-xs text-gray-500 font-mono truncate max-w-[150px]">
									{log.resource_id}
								</div>
							</td>
							<td class="px-6 py-4 whitespace-nowrap">
								{#if log.user}
									<div class="text-sm text-gray-900">{log.user.username}</div>
								{:else if log.user_id}
									<div class="text-xs text-gray-500 font-mono">{log.user_id}</div>
								{:else}
									<span class="text-gray-400">System</span>
								{/if}
							</td>
							<td class="px-6 py-4 whitespace-nowrap">
								<Badge variant={getStatusBadgeVariant(log.status_code)}>
									{log.status_code}
								</Badge>
							</td>
							<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-mono">
								{log.ip_address}
							</td>
							<td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
								<Button variant="ghost" on:click={() => viewDetails(log)}>Details</Button>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</Card>

		<!-- Pagination -->
		<div class="flex items-center justify-between">
			<p class="text-sm text-gray-600">
				Showing {(page - 1) * limit + 1} to {Math.min(page * limit, total)} of {total} entries
			</p>
			<div class="flex gap-2">
				<Button variant="outline" on:click={prevPage} disabled={page === 1}>Previous</Button>
				<Button variant="outline" on:click={nextPage} disabled={page * limit >= total}>Next</Button>
			</div>
		</div>
	{/if}
</div>

<!-- Detail Modal -->
{#if showModal && selectedLog}
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
					<h3 class="text-lg font-semibold text-gray-900">Audit Log Details</h3>
				</div>

				<div class="px-6 py-4 space-y-4 max-h-[70vh] overflow-y-auto">
					<div class="grid grid-cols-2 gap-4">
						<div>
							<Label>Timestamp</Label>
							<p class="mt-1 text-sm">{formatDate(selectedLog.created_at)}</p>
						</div>
						<div>
							<Label>Status Code</Label>
							<p class="mt-1">
								<Badge variant={getStatusBadgeVariant(selectedLog.status_code)}>
									{selectedLog.status_code}
								</Badge>
							</p>
						</div>
					</div>

					<div>
						<Label>Action</Label>
						<p class="mt-1">
							<Badge variant={getActionBadgeVariant(selectedLog.action)}>
								{selectedLog.action.replace(/_/g, ' ')}
							</Badge>
						</p>
					</div>

					<div>
						<Label>Resource</Label>
						<p class="mt-1 text-sm">{selectedLog.resource}</p>
						<code class="block mt-1 text-xs bg-gray-100 p-2 rounded break-all">
							{selectedLog.resource_id}
						</code>
					</div>

					{#if selectedLog.user}
						<div>
							<Label>User</Label>
							<p class="mt-1 text-sm">
								{selectedLog.user.username} ({selectedLog.user.email})
							</p>
						</div>
					{:else if selectedLog.user_id}
						<div>
							<Label>User ID</Label>
							<code class="block mt-1 text-xs bg-gray-100 p-2 rounded">
								{selectedLog.user_id}
							</code>
						</div>
					{/if}

					{#if selectedLog.application}
						<div>
							<Label>Application</Label>
							<p class="mt-1 text-sm">{selectedLog.application.name}</p>
						</div>
					{:else if selectedLog.application_id}
						<div>
							<Label>Application ID</Label>
							<code class="block mt-1 text-xs bg-gray-100 p-2 rounded">
								{selectedLog.application_id}
							</code>
						</div>
					{/if}

					<div>
						<Label>IP Address</Label>
						<code class="block mt-1 text-xs bg-gray-100 p-2 rounded">
							{selectedLog.ip_address}
						</code>
					</div>

					<div>
						<Label>User Agent</Label>
						<code class="block mt-1 text-xs bg-gray-100 p-2 rounded break-all">
							{selectedLog.user_agent}
						</code>
					</div>

					{#if selectedLog.metadata && Object.keys(selectedLog.metadata).length > 0}
						<div>
							<Label>Metadata</Label>
							<pre class="mt-1 text-xs bg-gray-100 p-2 rounded overflow-x-auto">
								{JSON.stringify(selectedLog.metadata, null, 2)}
							</pre>
						</div>
					{/if}
				</div>

				<div class="px-6 py-4 border-t border-gray-200 flex justify-end">
					<Button variant="outline" on:click={() => (showModal = false)}>Close</Button>
				</div>
			</div>
		</div>
	</div>
{/if}
