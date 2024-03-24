import * as server from '../entries/pages/(auth)/signin/_page.server.ts.js';

export const index = 5;
let component_cache;
export const component = async () => component_cache ??= (await import('../entries/pages/(auth)/signin/_page.svelte.js')).default;
export { server };
export const server_id = "src/routes/(auth)/signin/+page.server.ts";
export const imports = ["_app/immutable/nodes/5.Cia4_LQE.js","_app/immutable/chunks/scheduler.DV-TwITQ.js","_app/immutable/chunks/index.BKwc0d0r.js","_app/immutable/chunks/client.B3nhgKz2.js","_app/immutable/chunks/paths.Cmkrk8Uh.js","_app/immutable/chunks/index.TEHHQehO.js","_app/immutable/chunks/index.GOXzoJKF.js"];
export const stylesheets = [];
export const fonts = [];
