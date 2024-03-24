

export const index = 3;
let component_cache;
export const component = async () => component_cache ??= (await import('../entries/pages/_page.svelte.js')).default;
export const imports = ["_app/immutable/nodes/3.CUTiXjeV.js","_app/immutable/chunks/scheduler.DV-TwITQ.js","_app/immutable/chunks/index.BKwc0d0r.js"];
export const stylesheets = [];
export const fonts = [];
