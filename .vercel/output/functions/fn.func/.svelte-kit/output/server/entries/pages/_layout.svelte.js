import { c as create_ssr_component, v as validate_component } from "../../chunks/ssr.js";
import { B as Button } from "../../chunks/index3.js";
import { r as route } from "../../chunks/ROUTES.js";
const Layout = create_ssr_component(($$result, $$props, $$bindings, slots) => {
  return `${validate_component(Button, "Button").$$render($$result, { variant: "link", href: route("/app") }, {}, {
    default: () => {
      return `App`;
    }
  })} ${slots.default ? slots.default({}) : ``}`;
});
export {
  Layout as default
};
