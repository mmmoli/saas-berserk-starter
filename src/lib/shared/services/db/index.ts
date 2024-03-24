import { drizzle } from 'drizzle-orm/libsql';
import { createClient } from '@libsql/client';
import { DB_TURSO_CONNECTION_URL, DB_TURSO_AUTH_TOKEN } from '$env/static/private';
import * as schema from './schemas';

const client = createClient({
	url: DB_TURSO_CONNECTION_URL,
	authToken: DB_TURSO_AUTH_TOKEN
});

export const db = drizzle(client, { schema });
