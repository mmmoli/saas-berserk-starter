import { c as create_ssr_component, a as subscribe, e as escape } from "../../../../chunks/ssr.js";
import { p as page } from "../../../../chunks/stores.js";
const Page = create_ssr_component(($$result, $$props, $$bindings, slots) => {
  let $page, $$unsubscribe_page;
  $$unsubscribe_page = subscribe(page, (value) => $page = value);
  $$unsubscribe_page();
  return `<h1 data-svelte-h="svelte-ut1nuf">App</h1> ${$page.data.session ? `<pre>${escape(JSON.stringify($page.data.session, null, 2))}</pre>` : ``}`;
});
export {
  Page as default
};
