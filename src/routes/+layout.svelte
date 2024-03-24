<script>
	import { Button } from '~ui/button';
	import '../app.pcss';
	import { route } from '~shared/routes';
</script>

<Button variant="link" href={route('/app')}>App</Button>
<slot />
