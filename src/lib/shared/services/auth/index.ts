import { SvelteKitAuth } from '@auth/sveltekit';
import GitHub from '@auth/sveltekit/providers/github';
import { AUTH_GITHUB_ID, AUTH_GITHUB_SECRET, AUTH_SECRET } from '$env/static/private';
import { DrizzleAdapter } from '@auth/drizzle-adapter';
import { db } from '~shared/services/db';
import { route } from '~shared/routes';

export const { handle, signIn, signOut } = SvelteKitAuth({
	adapter: DrizzleAdapter(db),
	providers: [GitHub({ clientId: AUTH_GITHUB_ID, clientSecret: AUTH_GITHUB_SECRET })],
	secret: AUTH_SECRET,
	pages: {
		newUser: route('/app'),
		signIn: route('/signin'),
		signOut: route('/signout')
	}
});
