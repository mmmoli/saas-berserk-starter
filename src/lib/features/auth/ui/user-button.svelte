<script lang="ts">
	import { Button } from '~ui/button';
	import { page } from '$app/stores';
	import { signOut } from '@auth/sveltekit/client';
	import SignoutButton from './signout-button.svelte';
	const session = $page.data.session;
</script>

{#if session}
	<div class="flex items-center space-x-2">
		<pre>{session.user?.name}</pre>
		<Button on:click={() => signOut()}>Sign Out</Button>
	</div>
{:else}
	<SignoutButton />
{/if}
