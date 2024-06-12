<script>
	import { browser } from '$app/environment';
	import {
		OidcContext,
		LoginButton,
		LogoutButton,
		RefreshTokenButton,
		authError,
		accessToken,
		idToken,
		isAuthenticated,
		isLoading,
		login,
		logout,
		userInfo
	} from '@dopry/svelte-oidc';

	const metadata = {};
</script>

{#if browser}
	<OidcContext
		issuer="http://localhost:8000/o"
		client_id="2EIxgjlyy5VgCp2fjhEpKLyRtSMMPK0hZ0gBpNdm"
		redirect_uri="http://localhost:5173"
		post_logout_redirect_uri="http://localhost:5173"
		{metadata}
		scope="openid"
		extraOptions={{
			mergeClaims: true
		}}
	>
		<LoginButton>Login</LoginButton>
		<LogoutButton>Logout</LogoutButton>
		<RefreshTokenButton>RefreshToken</RefreshTokenButton><br />
		<pre>isLoading: {$isLoading}</pre>
		<pre>isAuthenticated: {$isAuthenticated}</pre>
		<pre>authToken: {$accessToken}</pre>
		<pre>idToken: {$idToken}</pre>
		<pre>userInfo: {JSON.stringify($userInfo, null, 2)}</pre>
		<pre>authError: {$authError}</pre>
	</OidcContext>
{/if}
