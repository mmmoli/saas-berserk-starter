import * as server from '../entries/pages/_layout.server.ts.js';

export const index = 0;
let component_cache;
export const component = async () => component_cache ??= (await import('../entries/pages/_layout.svelte.js')).default;
export { server };
export const server_id = "src/routes/+layout.server.ts";
export const imports = ["_app/immutable/nodes/0.DCsCsQR-.js","_app/immutable/chunks/scheduler.DV-TwITQ.js","_app/immutable/chunks/index.BKwc0d0r.js","_app/immutable/chunks/index.TEHHQehO.js","_app/immutable/chunks/index.GOXzoJKF.js","_app/immutable/chunks/ROUTES.oUoH5fud.js"];
export const stylesheets = ["_app/immutable/assets/0.BJXejs0u.css"];
export const fonts = [];
