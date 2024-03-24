import type { Config } from 'drizzle-kit';

export default {
	schema: './src/lib/shared/services/db/schemas',
	out: './drizzle',
	driver: 'turso',
	dbCredentials: {
		url: process.env.DB_TURSO_CONNECTION_URL!,
		authToken: process.env.DB_TURSO_AUTH_TOKEN!
	}
} satisfies Config;
