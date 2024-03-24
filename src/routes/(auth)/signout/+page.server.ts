import { signOut } from '~shared/services/auth';
import type { Actions } from './$types';
export const actions: Actions = { default: signOut };
