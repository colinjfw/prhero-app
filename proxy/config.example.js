const config = {
  keys: {
    encryption: "REPLACEME",
    signing: "REPLACEME",
  },
  audience: "REPLACEME",
  expiresInHours: 2,
  client: {
    id: "REPLACEME",
    secret: "REPLACEME"
  },
  urls: {
    dev: "http://localhost:3000/",
    prod: "https://colinjfw.github.io/prhero/"
  },
  loginUrl(state) {
    return `https://github.com/login/oauth/authorize?scope=user&client_id=${this.client.id}&state=${state}`;
  },
};
