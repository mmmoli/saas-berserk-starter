import { type Handle } from '@sveltejs/kit';
import { handle as authenticationHandle } from '~shared/services/auth';
import { sequence } from '@sveltejs/kit/hooks';

export const handle: Handle = sequence(authenticationHandle);
