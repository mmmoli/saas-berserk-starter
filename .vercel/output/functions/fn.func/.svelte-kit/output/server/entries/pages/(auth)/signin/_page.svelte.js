import { c as create_ssr_component, v as validate_component } from "../../../../chunks/ssr.js";
import { B as Button } from "../../../../chunks/index3.js";
const Page = create_ssr_component(($$result, $$props, $$bindings, slots) => {
  return `<h1 data-svelte-h="svelte-2pvnq6">Sign In</h1> ${validate_component(Button, "Button").$$render($$result, {}, {}, {
    default: () => {
      return `Sign in`;
    }
  })}`;
});
export {
  Page as default
};
