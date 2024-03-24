import { SvelteKitAuth } from '@auth/sveltekit';
import { AUTH_SECRET } from '$env/static/private';
import { DrizzleAdapter } from '@auth/drizzle-adapter';
import { db } from '~shared/services/db';
import { route } from '~shared/routes';
import { providers } from './providers';

export const { handle, signIn, signOut } = SvelteKitAuth({
	adapter: DrizzleAdapter(db),
	providers,
	secret: AUTH_SECRET,
	pages: {
		newUser: route('/app'),
		signIn: route('/signin'),
		signOut: route('/signout')
	}
});
