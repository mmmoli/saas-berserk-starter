import { r as redirect } from "../../../../chunks/index.js";
import { r as route } from "../../../../chunks/ROUTES.js";
const load = async (event) => {
  const session = await event.locals.auth();
  if (!session?.user)
    throw redirect(307, route("/signin"));
  return {};
};
export {
  load
};
