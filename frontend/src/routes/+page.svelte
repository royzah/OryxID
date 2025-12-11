<script lang="ts">
	import { onMount } from 'svelte';
	import { Card } from '$lib/components/ui';
	import { statsApi } from '$lib/api';
	import type { Statistics } from '$lib/types';

	let stats: Statistics | null = null;
	let loading = true;
	let error: string | null = null;

	onMount(async () => {
		try {
			stats = await statsApi.get();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load statistics';
		} finally {
			loading = false;
		}
	});

	interface StatCard {
		key: keyof Statistics;
		label: string;
		icon: string;
		color: string;
		href: string | null;
	}

	const statCards: StatCard[] = [
		{
			key: 'applications',
			label: 'Applications',
			icon: 'apps',
			color: 'purple',
			href: '/applications'
		},
		{ key: 'users', label: 'Users', icon: 'users', color: 'blue', href: '/users' },
		{ key: 'scopes', label: 'Scopes', icon: 'shield', color: 'green', href: '/scopes' },
		{
			key: 'active_tokens',
			label: 'Active Tokens',
			icon: 'key',
			color: 'orange',
			href: null
		}
	];

	function getStatValue(key: keyof Statistics): number {
		return stats ? stats[key] : 0;
	}
</script>

<div class="space-y-8">
	<div>
		<h1 class="text-2xl font-bold text-gray-900">Dashboard</h1>
		<p class="text-gray-600 mt-1">Overview of your OAuth2/OIDC server</p>
	</div>

	{#if loading}
		<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
			{#each [1, 2, 3, 4] as _}
				<Card class="p-6">
					<div class="animate-pulse">
						<div class="h-4 bg-gray-200 rounded w-24 mb-4"></div>
						<div class="h-8 bg-gray-200 rounded w-16"></div>
					</div>
				</Card>
			{/each}
		</div>
	{:else if error}
		<div class="bg-red-50 border border-red-200 rounded-lg p-4 text-red-700">
			{error}
		</div>
	{:else if stats}
		<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
			{#each statCards as card}
				<Card class="p-6 hover:shadow-md transition-shadow">
					{#if card.href}
						<a href={card.href} class="block">
							<div class="flex items-center justify-between">
								<div>
									<p class="text-sm font-medium text-gray-600">{card.label}</p>
									<p class="text-3xl font-bold text-gray-900 mt-1">
										{getStatValue(card.key)}
									</p>
								</div>
								<div
									class="w-12 h-12 bg-{card.color}-100 rounded-lg flex items-center justify-center"
								>
									{#if card.icon === 'apps'}
										<svg
											class="w-6 h-6 text-{card.color}-600"
											fill="none"
											viewBox="0 0 24 24"
											stroke="currentColor"
										>
											<path
												stroke-linecap="round"
												stroke-linejoin="round"
												stroke-width="2"
												d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"
											/>
										</svg>
									{:else if card.icon === 'users'}
										<svg
											class="w-6 h-6 text-{card.color}-600"
											fill="none"
											viewBox="0 0 24 24"
											stroke="currentColor"
										>
											<path
												stroke-linecap="round"
												stroke-linejoin="round"
												stroke-width="2"
												d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z"
											/>
										</svg>
									{:else if card.icon === 'shield'}
										<svg
											class="w-6 h-6 text-{card.color}-600"
											fill="none"
											viewBox="0 0 24 24"
											stroke="currentColor"
										>
											<path
												stroke-linecap="round"
												stroke-linejoin="round"
												stroke-width="2"
												d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
											/>
										</svg>
									{:else if card.icon === 'key'}
										<svg
											class="w-6 h-6 text-{card.color}-600"
											fill="none"
											viewBox="0 0 24 24"
											stroke="currentColor"
										>
											<path
												stroke-linecap="round"
												stroke-linejoin="round"
												stroke-width="2"
												d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"
											/>
										</svg>
									{/if}
								</div>
							</div>
						</a>
					{:else}
						<div class="flex items-center justify-between">
							<div>
								<p class="text-sm font-medium text-gray-600">{card.label}</p>
								<p class="text-3xl font-bold text-gray-900 mt-1">
									{getStatValue(card.key)}
								</p>
							</div>
							<div class="w-12 h-12 bg-orange-100 rounded-lg flex items-center justify-center">
								<svg
									class="w-6 h-6 text-orange-600"
									fill="none"
									viewBox="0 0 24 24"
									stroke="currentColor"
								>
									<path
										stroke-linecap="round"
										stroke-linejoin="round"
										stroke-width="2"
										d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"
									/>
								</svg>
							</div>
						</div>
					{/if}
				</Card>
			{/each}
		</div>
	{/if}

	<!-- Quick Actions -->
	<div>
		<h2 class="text-lg font-semibold text-gray-900 mb-4">Quick Actions</h2>
		<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
			<a
				href="/applications"
				class="flex items-center gap-4 p-4 bg-white rounded-lg border border-gray-200 hover:border-purple-300 hover:shadow-sm transition-all"
			>
				<div class="w-10 h-10 bg-purple-100 rounded-lg flex items-center justify-center">
					<svg class="w-5 h-5 text-purple-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
						<path
							stroke-linecap="round"
							stroke-linejoin="round"
							stroke-width="2"
							d="M12 4v16m8-8H4"
						/>
					</svg>
				</div>
				<div>
					<p class="font-medium text-gray-900">Create Application</p>
					<p class="text-sm text-gray-500">Register a new OAuth2 client</p>
				</div>
			</a>

			<a
				href="/scopes"
				class="flex items-center gap-4 p-4 bg-white rounded-lg border border-gray-200 hover:border-purple-300 hover:shadow-sm transition-all"
			>
				<div class="w-10 h-10 bg-green-100 rounded-lg flex items-center justify-center">
					<svg class="w-5 h-5 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
						<path
							stroke-linecap="round"
							stroke-linejoin="round"
							stroke-width="2"
							d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
						/>
					</svg>
				</div>
				<div>
					<p class="font-medium text-gray-900">Manage Scopes</p>
					<p class="text-sm text-gray-500">Define access permissions</p>
				</div>
			</a>

			<a
				href="/audit"
				class="flex items-center gap-4 p-4 bg-white rounded-lg border border-gray-200 hover:border-purple-300 hover:shadow-sm transition-all"
			>
				<div class="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
					<svg class="w-5 h-5 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
						<path
							stroke-linecap="round"
							stroke-linejoin="round"
							stroke-width="2"
							d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
						/>
					</svg>
				</div>
				<div>
					<p class="font-medium text-gray-900">View Audit Logs</p>
					<p class="text-sm text-gray-500">Track system activity</p>
				</div>
			</a>
		</div>
	</div>
</div>
