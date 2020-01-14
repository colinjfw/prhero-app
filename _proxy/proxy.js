const encryption = new Encryption(config.keys.signing, config.keys.encryption);
const session = new Session(encryption, config.audience, config.expiresInHours);

addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request));
});

/**
 * Fetches an access token from GitHub.
 *
 * @param {string} code
 * @returns {Promise<string>}
 */
async function accessToken(code) {
  const resp = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "cache-control": "no-cache",
      "accept": "application/json"
    },
    body: JSON.stringify({
      client_id: config.client.id,
      client_secret: config.client.secret,
      code
    })
  });
  const body = await resp.json();
  if (body["error"]) {
    throw new Error(body["error"]);
  }
  return body["access_token"];
}

/**
 * Fetch querystring from the request.
 *
 * @param {Request} request
 * @returns {Object}
 */
function query(request) {
  const result = {};
  const q = request.url.split("?")[1] || "";
  const vars = q.split("&");
  for (let i = 0; i < vars.length; i++) {
    const pair = vars[i].split("=");
    result[decodeURIComponent(pair[0])] = decodeURIComponent(pair[1]);
  }
  return result;
}

/**
 * Handle the request.
 *
 * @param {Request} req
 * @returns {Promise<Response>}
 */
async function handleRequest(req) {
  try {
    const path = new URL(req.url).pathname;
    switch (path) {
      case "/callback":
        return await handleCode(req);
      case "/login":
        return handleLogin(req);
    }

    if (path.startsWith("/api")) {
      if (req.method === "OPTIONS") {
        return handleOptions(req);
      }
      return wrapWithOptions(await handleApi(req));
    }

    return new Response("NotFound", {
      status: 404,
      headers: { "content-type": "text/plain" }
    });
  } catch (error) {
    return new Response(error.stack, {
      status: 500,
      headers: { "content-type": "text/plain" }
    });
  }
}

/**
 * Handle access code from GitHub.
 *
 * @param {Request} req
 * @returns {Response}
 */
async function handleLogin(req) {
  const q = query(req);
  if (!q.return) {
    throw new Error("Return must be specified");
  }
  const state = await encryption.sign(q.return);
  return Response.redirect(config.loginUrl(encodeURIComponent(state)), 301);
}

/**
 * Substitues the url for proxying to GitHub.
 * @param {string} url
 * @returns {string}
 */
function substituteUrl(url) {
  const out = new URL(url);
  out.pathname = out.pathname.replace("/api/", "");
  out.host = "api.github.com";
  out.protocol = "https";
  return out.href;
}

/**
 *
 * @param {Request} req
 * @returns {Promise<Response>}
 */
async function handleApi(req) {
  const auth = req.headers.get("authorization");
  const token = await session.read(auth.split(" ").pop());
  const next = new Request(substituteUrl(req.url), {
    headers: {
      "accept": req.headers.get("accept"),
      "authorization": `token ${token}`,
      "user-agent": req.headers.get("user-agent"),
    }
  });
  return await fetch(next);
}

/**
 * Handle access code from GitHub.
 *
 * @param {Request} req
 * @returns {Promise<Response>}
 */
async function handleCode(req) {
  const q = query(req);
  const state = await encryption.verify(q.state);
  if (!state) {
    throw new Error("Invalid state");
  }
  const url = config.urls[state];
  if (!url) {
    throw new Error("Invalid return parameter");
  }
  const token = await accessToken(q.code);
  const sess = await session.create(token);
  return Response.redirect(`${url}?token=${encodeURIComponent(sess)}`, 301);
}

const corsHeaders = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, HEAD, POST, OPTIONS',
  'access-control-allow-headers': '*',
}

/**
 * Wraps a response so options can be returned.
 * @param {Response} response
 * @returns {Response}
 */
function wrapWithOptions(response) {
  const out = new Response(response.body, response);
  out.headers.set('access-control-allow-origin', '*');
  return out;
}

/**
 * Handle options request.
 * @param {Request} request
 * @returns {Response}
 */
function handleOptions(request) {
  if (
    request.headers.get('origin') !== null &&
    request.headers.get('access-control-request-method') !== null &&
    request.headers.get('access-control-request-headers') !== null
  ) {
    return new Response(null, {
      headers: corsHeaders,
    })
  } else {
    return new Response(null, {
      headers: {
        Allow: 'GET, HEAD, POST, OPTIONS',
      },
    })
  }
}
