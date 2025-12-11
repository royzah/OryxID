<script lang="ts">
	import '../app.css';
	import { auth, isAuthenticated } from '$lib/stores';
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';

	// Navigation items
	const navItems = [
		{ href: '/', label: 'Dashboard', icon: 'home' },
		{ href: '/applications', label: 'Applications', icon: 'apps' },
		{ href: '/scopes', label: 'Scopes', icon: 'shield' },
		{ href: '/users', label: 'Users', icon: 'users' },
		{ href: '/audit', label: 'Audit Logs', icon: 'history' },
		{ href: '/settings', label: 'Settings', icon: 'settings' }
	];

	$: isLoginPage = $page.url.pathname === '/login';

	onMount(() => {
		// Redirect to login if not authenticated (except on login page)
		const unsubscribe = auth.subscribe((state) => {
			if (state.isInitialized && !state.token && !isLoginPage) {
				goto('/login');
			}
		});

		return unsubscribe;
	});

	async function handleLogout() {
		await auth.logout();
	}
</script>

<svelte:head>
	<title>OryxID Admin</title>
</svelte:head>

{#if isLoginPage}
	<slot />
{:else if $isAuthenticated}
	<div class="min-h-screen bg-gray-50">
		<!-- Sidebar -->
		<aside class="fixed inset-y-0 left-0 z-50 w-64 bg-white border-r border-gray-200">
			<!-- Logo -->
			<div class="flex items-center h-16 px-6 border-b border-gray-200">
				<div class="flex items-center gap-2">
					<div class="w-8 h-8 bg-purple-600 rounded-lg flex items-center justify-center">
						<span class="text-white font-bold text-sm">O</span>
					</div>
					<span class="text-lg font-semibold text-gray-900">OryxID</span>
				</div>
			</div>

			<!-- Navigation -->
			<nav class="p-4 space-y-1">
				{#each navItems as item}
					<a
						href={item.href}
						class="flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-lg transition-colors
							{$page.url.pathname === item.href
							? 'bg-purple-50 text-purple-700'
							: 'text-gray-600 hover:bg-gray-100 hover:text-gray-900'}"
					>
						{#if item.icon === 'home'}
							<svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
								<path
									stroke-linecap="round"
									stroke-linejoin="round"
									stroke-width="2"
									d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"
								/>
							</svg>
						{:else if item.icon === 'apps'}
							<svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
								<path
									stroke-linecap="round"
									stroke-linejoin="round"
									stroke-width="2"
									d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"
								/>
							</svg>
						{:else if item.icon === 'shield'}
							<svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
								<path
									stroke-linecap="round"
									stroke-linejoin="round"
									stroke-width="2"
									d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
								/>
							</svg>
						{:else if item.icon === 'users'}
							<svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
								<path
									stroke-linecap="round"
									stroke-linejoin="round"
									stroke-width="2"
									d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z"
								/>
							</svg>
						{:else if item.icon === 'history'}
							<svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
								<path
									stroke-linecap="round"
									stroke-linejoin="round"
									stroke-width="2"
									d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
								/>
							</svg>
						{:else if item.icon === 'settings'}
							<svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
								<path
									stroke-linecap="round"
									stroke-linejoin="round"
									stroke-width="2"
									d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
								/>
								<path
									stroke-linecap="round"
									stroke-linejoin="round"
									stroke-width="2"
									d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
								/>
							</svg>
						{/if}
						{item.label}
					</a>
				{/each}
			</nav>

			<!-- User section -->
			<div class="absolute bottom-0 left-0 right-0 p-4 border-t border-gray-200">
				<div class="flex items-center gap-3 mb-3">
					<div
						class="w-8 h-8 bg-purple-100 rounded-full flex items-center justify-center text-purple-600 font-medium"
					>
						{$auth.user?.username?.charAt(0).toUpperCase() || 'U'}
					</div>
					<div class="flex-1 min-w-0">
						<p class="text-sm font-medium text-gray-900 truncate">{$auth.user?.username}</p>
						<p class="text-xs text-gray-500 truncate">{$auth.user?.email}</p>
					</div>
				</div>
				<button
					on:click={handleLogout}
					class="w-full flex items-center justify-center gap-2 px-3 py-2 text-sm font-medium text-gray-600 bg-gray-100 rounded-lg hover:bg-gray-200 transition-colors"
				>
					<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
						<path
							stroke-linecap="round"
							stroke-linejoin="round"
							stroke-width="2"
							d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"
						/>
					</svg>
					Sign out
				</button>
			</div>
		</aside>

		<!-- Main content -->
		<main class="ml-64 p-8">
			<slot />
		</main>
	</div>
{:else}
	<div class="min-h-screen flex items-center justify-center bg-gray-50">
		<div class="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-600"></div>
	</div>
{/if}
