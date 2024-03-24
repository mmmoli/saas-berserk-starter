<script lang="ts">
	import { page } from '$app/stores';
</script>

<h1>App</h1>

{#if $page.data.session}
	<pre>{JSON.stringify($page.data.session, null, 2)}</pre>
{/if}
