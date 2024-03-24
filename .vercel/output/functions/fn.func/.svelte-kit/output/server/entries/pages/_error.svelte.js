import { c as create_ssr_component, a as subscribe, v as validate_component, e as escape } from "../../chunks/ssr.js";
import { p as page } from "../../chunks/stores.js";
import { r as route } from "../../chunks/ROUTES.js";
import { B as Button } from "../../chunks/index3.js";
const Error = create_ssr_component(($$result, $$props, $$bindings, slots) => {
  let $page, $$unsubscribe_page;
  $$unsubscribe_page = subscribe(page, (value) => $page = value);
  $$unsubscribe_page();
  return `<div class="grid place-items-center gap-5 text-center">${$page.status === 404 ? `<h1 class="text-2xl font-bold" data-svelte-h="svelte-1uis431">404 - Page Not Found</h1> <p class="text-muted-foreground" data-svelte-h="svelte-1drg3tx">Oops! The page you&#39;re looking for does not exist. It might have been moved, renamed, or might
			never existed.</p> ${validate_component(Button, "Button").$$render($$result, { href: route("/"), class: "w-fit" }, {}, {
    default: () => {
      return `Go to Home Page`;
    }
  })}` : `<h1>${escape($page.status)}: ${escape($page.error?.message)}</h1>`}</div>`;
});
export {
  Error as default
};
