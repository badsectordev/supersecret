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
  return await fetch("/view-secret.html").then((res) => res.text());
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/create" && request.method === "POST") {
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
