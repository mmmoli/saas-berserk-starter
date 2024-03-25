<script>
	import { Button } from '~ui/button';
	import { UserButton } from '~features/auth';
	import { route } from '~shared/routes';
</script>

<div class="flex items-center justify-between">
	<Button variant="link" href={route('/app')}>App</Button>
	<UserButton />
</div>
