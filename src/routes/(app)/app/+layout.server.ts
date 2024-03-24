import { redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { route } from '~shared/routes';

export const load: PageServerLoad = async (event) => {
	const session = await event.locals.auth();
	if (!session?.user) throw redirect(307, route('/signin'));
	return {};
};
