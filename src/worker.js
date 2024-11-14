async function deriveKey(dynamicKey, env) {
  const encoder = new TextEncoder();
  const masterKeyData = encoder.encode(env.MASTER_KEY);
  const dynamicKeyData = Uint8Array.from(atob(dynamicKey), (c) =>
    c.charCodeAt(0),
  );

  const keyMaterial = new Uint8Array([...masterKeyData, ...dynamicKeyData]);
  const baseKey = await crypto.subtle.importKey(
    "raw",
    keyMaterial,
    "HKDF",
    false,
    ["deriveKey"],
  );

  return await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(),
      info: new Uint8Array(),
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encrypt(text, env) {
  const dynamicKey = crypto.getRandomValues(new Uint8Array(32));
  const key = await deriveKey(btoa(String.fromCharCode(...dynamicKey)), env);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(text),
  );

  return {
    encrypted: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    iv: btoa(String.fromCharCode(...iv)),
    dynamicKey: btoa(String.fromCharCode(...dynamicKey)),
  };
}

async function decrypt(encryptedData, iv, dynamicKey, env) {
  const key = await deriveKey(dynamicKey, env);

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: Uint8Array.from(atob(iv), (c) => c.charCodeAt(0)),
    },
    key,
    Uint8Array.from(atob(encryptedData), (c) => c.charCodeAt(0)),
  );

  return new TextDecoder().decode(decrypted);
}

async function generateSecretPage() {
  return `
    <!DOCTYPE html>
    <html>
      <head>
        <title>SuperSecret - View Secret</title>
        <style>
          body {
            font-family: system-ui, -apple-system, sans-serif;
            max-width: 600px;
            margin: 2rem auto;
            padding: 0 1rem;
            background: #f5f5f5;
          }
          button {
            background: #2563eb;
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 0.5rem;
            cursor: pointer;
          }
          button:disabled {
            background: #93c5fd;
          }
          pre {
            background: white;
            padding: 1rem;
            border-radius: 0.5rem;
            white-space: pre-wrap;
          }
          .warning {
            color: #991b1b;
            font-weight: 500;
          }
        </style>
        <script>
          async function revealSecret() {
            try {
              const hash = window.location.hash.substring(1);
              const response = await fetch(window.location.pathname, {
                method: 'POST',
                headers: {
                  'X-Secret-Hash': hash
                }
              });
              if (!response.ok) throw new Error(await response.text());
              const secret = await response.text();
              document.getElementById('secret').textContent = secret;
              document.getElementById('reveal').disabled = true;
            } catch (error) {
              document.getElementById('secret').textContent = 'Error: ' + error.message;
            }
          }
        </script>
      </head>
      <body>
        <h1>SuperSecret</h1>
        <p class="warning">This message will self-destruct after viewing!</p>
        <button id="reveal" onclick="revealSecret()">Reveal Secret</button>
        <pre id="secret"></pre>
      </body>
    </html>
  `;
}

const createPage = `
  <!DOCTYPE html>
  <html>
    <head>
      <title>SuperSecret - Create Secret</title>
      <style>
        body {
          font-family: system-ui, -apple-system, sans-serif;
          max-width: 600px;
          margin: 2rem auto;
          padding: 0 1rem;
          background: #f5f5f5;
        }
        textarea {
          width: 100%;
          height: 150px;
          margin: 1rem 0;
          padding: 0.5rem;
          border-radius: 0.5rem;
          border: 1px solid #e5e7eb;
        }
        button {
          background: #2563eb;
          color: white;
          border: none;
          padding: 0.75rem 1.5rem;
          border-radius: 0.5rem;
          cursor: pointer;
        }
        button:disabled {
          background: #93c5fd;
        }
        #result {
          background: white;
          padding: 1rem;
          border-radius: 0.5rem;
          word-break: break-all;
        }
      </style>
      <script>
        async function createSecret() {
          const button = document.getElementById('create');
          const secret = document.getElementById('secret').value;

          if (!secret.trim()) {
            alert('Please enter a secret message');
            return;
          }

          button.disabled = true;
          try {
            const response = await fetch('/', {
              method: 'POST',
              body: secret
            });
            if (!response.ok) throw new Error('Failed to create secret');
            const url = await response.text();
            document.getElementById('result').textContent = url;
          } catch (error) {
            document.getElementById('result').textContent = 'Error: ' + error.message;
          } finally {
            button.disabled = false;
          }
        }
      </script>
    </head>
    <body>
      <h1>SuperSecret</h1>
      <p>Share sensitive information securely. Links expire in 24 hours.</p>
      <textarea id="secret" placeholder="Enter your secret message..."></textarea><br>
      <button id="create" onclick="createSecret()">Generate Secret Link</button>
      <p id="result"></p>
    </body>
  </html>
`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/") {
      if (request.method === "GET") {
        return new Response(createPage, {
          headers: { "Content-Type": "text/html" },
        });
      }

      if (request.method === "POST") {
        try {
          const secret = await request.text();
          if (!secret.trim()) {
            return new Response("Secret cannot be empty", { status: 400 });
          }

          const id = crypto.randomUUID();
          const { encrypted, iv, dynamicKey } = await encrypt(secret, env);

          await env.SUPER_SECRETS.put(
            id,
            JSON.stringify({
              encrypted,
              iv,
              createdAt: Date.now(),
            }),
            {
              expirationTtl: 86400,
            },
          );

          return new Response(`${url.origin}/secret/${id}#${dynamicKey}`);
        } catch (error) {
          return new Response("Failed to create secret: " + error.message, {
            status: 500,
          });
        }
      }
    }

    if (url.pathname.startsWith("/secret/")) {
      const id = url.pathname.split("/").pop();

      if (request.method === "GET") {
        return new Response(await generateSecretPage(), {
          headers: { "Content-Type": "text/html" },
        });
      }

      if (request.method === "POST") {
        try {
          const secretData = await env.SUPER_SECRETS.get(id);
          if (!secretData) {
            return new Response("Secret not found or expired", { status: 404 });
          }

          const dynamicKey = request.headers.get("X-Secret-Hash");
          if (!dynamicKey) {
            return new Response("Invalid key", { status: 400 });
          }

          const data = JSON.parse(secretData);
          await env.SUPER_SECRETS.delete(id);

          const secret = await decrypt(
            data.encrypted,
            data.iv,
            dynamicKey,
            env,
          );
          return new Response(secret);
        } catch (error) {
          return new Response("Failed to decrypt secret", { status: 500 });
        }
      }
    }

    return new Response("Not found", { status: 404 });
  },
};
