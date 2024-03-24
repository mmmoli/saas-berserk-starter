<script lang="ts">
	import { signIn } from '@auth/sveltekit/client';
	import { Button } from '~ui/button';
</script>

<h1>Sign In</h1>

<Button on:click={() => signIn('github')}>Sign in</Button>
