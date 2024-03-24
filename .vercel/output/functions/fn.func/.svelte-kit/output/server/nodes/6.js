import * as server from '../entries/pages/(auth)/signout/_page.server.ts.js';

export const index = 6;
let component_cache;
export const component = async () => component_cache ??= (await import('../entries/pages/(auth)/signout/_page.svelte.js')).default;
export { server };
export const server_id = "src/routes/(auth)/signout/+page.server.ts";
export const imports = ["_app/immutable/nodes/6.B-F2aJt9.js","_app/immutable/chunks/scheduler.DV-TwITQ.js","_app/immutable/chunks/index.BKwc0d0r.js","_app/immutable/chunks/client.B3nhgKz2.js","_app/immutable/chunks/paths.Cmkrk8Uh.js","_app/immutable/chunks/index.TEHHQehO.js","_app/immutable/chunks/index.GOXzoJKF.js"];
export const stylesheets = [];
export const fonts = [];
