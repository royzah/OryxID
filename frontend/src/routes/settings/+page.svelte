<script lang="ts">
	import { Card, Button, Input, Label, Badge } from '$lib/components/ui';
	import { auth } from '$lib/stores';

	let saving = false;
	let message: { type: 'success' | 'error'; text: string } | null = null;

	// Server settings (would be loaded from API in real implementation)
	let settings = {
		issuer: 'https://auth.example.com',
		accessTokenLifespan: 3600,
		refreshTokenLifespan: 86400,
		idTokenLifespan: 3600,
		authCodeLifespan: 600,
		requirePKCE: true,
		allowImplicit: false,
		rotateRefreshTokens: true,
		revokeOldRefreshTokens: true
	};

	// Password change form
	let passwordForm = {
		currentPassword: '',
		newPassword: '',
		confirmPassword: ''
	};

	async function saveSettings() {
		saving = true;
		message = null;

		try {
			// TODO: Implement API call to save settings
			await new Promise((resolve) => setTimeout(resolve, 1000));
			message = { type: 'success', text: 'Settings saved successfully' };
		} catch (e) {
			message = { type: 'error', text: e instanceof Error ? e.message : 'Failed to save settings' };
		} finally {
			saving = false;
		}
	}

	async function changePassword() {
		if (passwordForm.newPassword !== passwordForm.confirmPassword) {
			message = { type: 'error', text: 'Passwords do not match' };
			return;
		}

		if (passwordForm.newPassword.length < 8) {
			message = { type: 'error', text: 'Password must be at least 8 characters' };
			return;
		}

		saving = true;
		message = null;

		try {
			// TODO: Implement API call to change password
			await new Promise((resolve) => setTimeout(resolve, 1000));
			message = { type: 'success', text: 'Password changed successfully' };
			passwordForm = { currentPassword: '', newPassword: '', confirmPassword: '' };
		} catch (e) {
			message = {
				type: 'error',
				text: e instanceof Error ? e.message : 'Failed to change password'
			};
		} finally {
			saving = false;
		}
	}

	function formatDuration(seconds: number): string {
		if (seconds < 60) return `${seconds} seconds`;
		if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes`;
		if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours`;
		return `${Math.floor(seconds / 86400)} days`;
	}
</script>

<div class="space-y-6 max-w-4xl">
	<div>
		<h1 class="text-2xl font-bold text-gray-900">Settings</h1>
		<p class="text-gray-600 mt-1">Configure your OAuth2/OIDC server settings</p>
	</div>

	{#if message}
		<div
			class="p-4 rounded-lg {message.type === 'success'
				? 'bg-green-50 border border-green-200 text-green-700'
				: 'bg-red-50 border border-red-200 text-red-700'}"
		>
			{message.text}
		</div>
	{/if}

	<!-- Profile Section -->
	<Card class="p-6">
		<h2 class="text-lg font-semibold text-gray-900 mb-4">Profile</h2>
		<div class="flex items-center gap-4 mb-6">
			<div class="w-16 h-16 bg-purple-100 rounded-full flex items-center justify-center">
				<span class="text-purple-600 text-2xl font-medium">
					{$auth.user?.username?.charAt(0).toUpperCase() || 'U'}
				</span>
			</div>
			<div>
				<h3 class="text-lg font-medium text-gray-900">{$auth.user?.username}</h3>
				<p class="text-gray-500">{$auth.user?.email}</p>
				<div class="flex gap-2 mt-1">
					{#if $auth.user?.is_admin}
						<Badge variant="destructive">Admin</Badge>
					{:else}
						<Badge variant="outline">User</Badge>
					{/if}
					{#if $auth.user?.email_verified}
						<Badge variant="default">Verified</Badge>
					{/if}
				</div>
			</div>
		</div>
	</Card>

	<!-- Change Password -->
	<Card class="p-6">
		<h2 class="text-lg font-semibold text-gray-900 mb-4">Change Password</h2>
		<form on:submit|preventDefault={changePassword} class="space-y-4 max-w-md">
			<div>
				<Label for="current-password">Current Password</Label>
				<Input
					id="current-password"
					type="password"
					bind:value={passwordForm.currentPassword}
					required
				/>
			</div>
			<div>
				<Label for="new-password">New Password</Label>
				<Input id="new-password" type="password" bind:value={passwordForm.newPassword} required />
				<p class="mt-1 text-xs text-gray-500">Must be at least 8 characters</p>
			</div>
			<div>
				<Label for="confirm-password">Confirm New Password</Label>
				<Input
					id="confirm-password"
					type="password"
					bind:value={passwordForm.confirmPassword}
					required
				/>
			</div>
			<Button type="submit" disabled={saving}>
				{saving ? 'Changing...' : 'Change Password'}
			</Button>
		</form>
	</Card>

	<!-- Server Configuration (Admin only) -->
	{#if $auth.user?.is_admin}
		<Card class="p-6">
			<h2 class="text-lg font-semibold text-gray-900 mb-4">Server Configuration</h2>
			<form on:submit|preventDefault={saveSettings} class="space-y-6">
				<div>
					<Label for="issuer">Issuer URL</Label>
					<Input id="issuer" bind:value={settings.issuer} placeholder="https://auth.example.com" />
					<p class="mt-1 text-xs text-gray-500">
						The issuer identifier for your OAuth2/OIDC server
					</p>
				</div>

				<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
					<div>
						<Label for="access-token-lifespan">Access Token Lifespan (seconds)</Label>
						<Input
							id="access-token-lifespan"
							type="number"
							bind:value={settings.accessTokenLifespan}
							min="60"
						/>
						<p class="mt-1 text-xs text-gray-500">
							{formatDuration(settings.accessTokenLifespan)}
						</p>
					</div>
					<div>
						<Label for="refresh-token-lifespan">Refresh Token Lifespan (seconds)</Label>
						<Input
							id="refresh-token-lifespan"
							type="number"
							bind:value={settings.refreshTokenLifespan}
							min="3600"
						/>
						<p class="mt-1 text-xs text-gray-500">
							{formatDuration(settings.refreshTokenLifespan)}
						</p>
					</div>
					<div>
						<Label for="id-token-lifespan">ID Token Lifespan (seconds)</Label>
						<Input
							id="id-token-lifespan"
							type="number"
							bind:value={settings.idTokenLifespan}
							min="60"
						/>
						<p class="mt-1 text-xs text-gray-500">
							{formatDuration(settings.idTokenLifespan)}
						</p>
					</div>
					<div>
						<Label for="auth-code-lifespan">Authorization Code Lifespan (seconds)</Label>
						<Input
							id="auth-code-lifespan"
							type="number"
							bind:value={settings.authCodeLifespan}
							min="60"
							max="600"
						/>
						<p class="mt-1 text-xs text-gray-500">
							{formatDuration(settings.authCodeLifespan)}
						</p>
					</div>
				</div>

				<div class="space-y-3">
					<h3 class="font-medium text-gray-700">Security Options</h3>

					<label class="flex items-center gap-3">
						<input
							type="checkbox"
							bind:checked={settings.requirePKCE}
							class="rounded text-purple-600"
						/>
						<div>
							<span class="text-sm font-medium">Require PKCE</span>
							<p class="text-xs text-gray-500">
								Require Proof Key for Code Exchange for all authorization code flows
							</p>
						</div>
					</label>

					<label class="flex items-center gap-3">
						<input
							type="checkbox"
							bind:checked={settings.allowImplicit}
							class="rounded text-purple-600"
						/>
						<div>
							<span class="text-sm font-medium">Allow Implicit Flow</span>
							<p class="text-xs text-gray-500">
								Enable the legacy implicit grant type (not recommended)
							</p>
						</div>
					</label>

					<label class="flex items-center gap-3">
						<input
							type="checkbox"
							bind:checked={settings.rotateRefreshTokens}
							class="rounded text-purple-600"
						/>
						<div>
							<span class="text-sm font-medium">Rotate Refresh Tokens</span>
							<p class="text-xs text-gray-500">Issue a new refresh token with each token refresh</p>
						</div>
					</label>

					<label class="flex items-center gap-3">
						<input
							type="checkbox"
							bind:checked={settings.revokeOldRefreshTokens}
							class="rounded text-purple-600"
						/>
						<div>
							<span class="text-sm font-medium">Revoke Old Refresh Tokens</span>
							<p class="text-xs text-gray-500">
								Automatically revoke old refresh tokens when rotating
							</p>
						</div>
					</label>
				</div>

				<div class="flex gap-3">
					<Button type="submit" disabled={saving}>
						{saving ? 'Saving...' : 'Save Settings'}
					</Button>
				</div>
			</form>
		</Card>

		<!-- Danger Zone -->
		<Card class="p-6 border-red-200">
			<h2 class="text-lg font-semibold text-red-600 mb-4">Danger Zone</h2>
			<div class="space-y-4">
				<div class="flex items-center justify-between p-4 bg-red-50 rounded-lg">
					<div>
						<h3 class="font-medium text-gray-900">Rotate Signing Keys</h3>
						<p class="text-sm text-gray-500">Generate new signing keys. Old tokens will be invalidated.</p>
					</div>
					<Button variant="destructive">Rotate Keys</Button>
				</div>

				<div class="flex items-center justify-between p-4 bg-red-50 rounded-lg">
					<div>
						<h3 class="font-medium text-gray-900">Revoke All Tokens</h3>
						<p class="text-sm text-gray-500">Invalidate all active access and refresh tokens.</p>
					</div>
					<Button variant="destructive">Revoke All</Button>
				</div>

				<div class="flex items-center justify-between p-4 bg-red-50 rounded-lg">
					<div>
						<h3 class="font-medium text-gray-900">Clear All Sessions</h3>
						<p class="text-sm text-gray-500">Log out all users and clear all sessions.</p>
					</div>
					<Button variant="destructive">Clear Sessions</Button>
				</div>
			</div>
		</Card>
	{/if}
</div>
