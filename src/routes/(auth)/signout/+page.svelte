<script lang="ts">
	import { signOut } from '@auth/sveltekit/client';
	import { Button } from '~ui/button';
</script>

<h1>Sign Out</h1>

<Button on:click={() => signOut()}>Sign Out</Button>
