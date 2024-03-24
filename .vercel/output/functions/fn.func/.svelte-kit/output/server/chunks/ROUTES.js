const PAGES = {
  "/": `/`,
  "/app": `/app`,
  "/signin": `/signin`,
  "/signout": `/signout`
};
const SERVERS = {};
const ACTIONS = {
  "default /signin": `/signin`,
  "default /signout": `/signout`
};
const LINKS = {};
const AllObjs = { ...PAGES, ...ACTIONS, ...SERVERS, ...LINKS };
function route(key, ...params) {
  if (AllObjs[key] instanceof Function) {
    const element = AllObjs[key];
    return element(...params);
  } else {
    return AllObjs[key];
  }
}
export {
  route as r
};
