import * as server from '../entries/pages/(app)/app/_layout.server.ts.js';

export const index = 2;
let component_cache;
export const component = async () => component_cache ??= (await import('../entries/pages/(app)/app/_layout.svelte.js')).default;
export { server };
export const server_id = "src/routes/(app)/app/+layout.server.ts";
export const imports = ["_app/immutable/nodes/2.ygopxgRg.js","_app/immutable/chunks/scheduler.DV-TwITQ.js","_app/immutable/chunks/index.BKwc0d0r.js"];
export const stylesheets = [];
export const fonts = [];
