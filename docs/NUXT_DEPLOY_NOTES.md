# Nuxt SSR Deployment Notes

Findings from debugging a Nuxt 3 + Nitro production deployment on Ubuntu via PM2 + nginx.

---

## 1. Nuxt devtools leaks into production builds

**Symptom:** `ERR_MODULE_NOT_FOUND` on every page request:
```
Cannot find module '/Users/<you>/node_modules/@nuxt/vite-builder/dist/runtime/vite-node.mjs'
```

**Cause:** `devtools: { enabled: true }` in `nuxt.config.ts` causes Nuxt 3.17.x to embed
absolute `file:///` local-machine paths into the production SSR `renderer.mjs`:
```js
import viteNode_mjs from 'file:///Users/<you>/project/node_modules/@nuxt/vite-builder/...';
import client_manifest_mjs from 'file:///Users/<you>/project/node_modules/@nuxt/vite-builder/...';
```
These are dev-only vite-node fetchers. Without them, the client manifest (needed for SSR
hydration) is a proper static file: `.output/server/chunks/build/client.manifest.mjs`.

**Fix:** In `nuxt.config.ts`:
```ts
devtools: { enabled: false },
```

**Safety net in deployvm:** `NpmApp._fix_absolute_imports()` scans the dist dir after local
builds and replaces any remaining `file:///` imports with `null` stubs.

---

## 2. nginx static file serving — framework-specific paths

The `--static-subdir` parameter controls which subdirectory nginx serves directly.
It is relative to the app dir (`/home/deploy/<app-name>/`).

| Framework | `--dist-dir` | `--static-subdir` | Notes |
|-----------|-------------|-------------------|-------|
| Nuxt      | `.output`   | *(default)*       | defaults to `{dist_dir}/public` = `.output/public` |
| SvelteKit | `build`     | `build/client`    | SSR adapter-node output |
| Next.js   | `.next`     | `public`          | `.next/static` is under `/_next/` handled by Nitro |
| Remix     | `build`     | `build/client`    | |
| Vite SPA  | `dist`      | `dist`            | entire dist dir is static |
| API only  | *(any)*     | `""`              | empty string disables static serving |

Example for SvelteKit:
```bash
uv run deployvm npm deploy myapp ../my-sveltekit-app \
    --start-script "build/index.js" \
    --build-command "npm run build" \
    --dist-dir "build" \
    --static-subdir "build/client" \
    ...
```

---

## 3. nginx must serve static files directly

**Symptom:** Static assets (`/_nuxt/*.js`, `/_nuxt/*.css`) served with `application/json`
MIME type, causing "Refused to apply style..." and "Failed to fetch dynamically imported
module" browser errors.

**Cause:** Without a static root, all requests go to the Nitro backend which returns JSON
error responses for unknown paths.

**Fix:** nginx `location /` block with `root` pointing at `.output/public`:
```nginx
location / {
    root /home/deploy/<app>/.output/public;
    try_files $uri @backend;
}
location @backend {
    proxy_pass http://127.0.0.1:<port>;
    ...
}
```

**Critical:** Use `try_files $uri @backend` — NOT `$uri $uri/`. The `$uri/` variant tries
to match directories; for SSR apps with no `index.html`, nginx returns 403 on `/`.

---

## 4. nginx cannot traverse the home directory by default

**Symptom:** `403 Forbidden` from nginx when `root` is inside `/home/deploy/`.

**Cause:** Ubuntu home directories are created with `750` permissions. nginx runs as
`www-data` which has no execute bit and cannot traverse into `/home/deploy/`.

**Fix:** `chmod o+x /home/deploy` (added to `create_user` in `server.py`).

---

## 5. `su - deploy` fails in non-interactive SSH sessions

**Symptom:** `[ERROR] SSH script failed:` silently, or `su: Authentication failure`.

**Cause:** When already SSH'd in as `deploy`, running `su - deploy` requires a password
even though you're the same user. Non-interactive sessions have no TTY for password entry.

**Fix:** Run PM2 commands directly (no `su -` wrapper) since we're already the right user:
```python
# Before (broken):
su - {user} -c "cd {app_dir} && pm2 start ..."

# After (fixed):
pm2 start ...
```

---

## 6. PM2 restart must be per-app, not nuclear

**Symptom:** Deploying one app kills all PM2-managed apps on a shared instance.

**Cause:** `pkill -u deploy -f pm2` kills the entire PM2 daemon, taking down all apps.

**Fix:** Use per-app PM2 operations:
```bash
if pm2 describe <app_name> > /dev/null 2>&1; then
    pm2 reload <app_name>
else
    cd <app_dir> && pm2 start ecosystem.config.cjs && pm2 save
fi
```

---

## Nitro asset path note (historical)

Nitro 2.x resolves `readAsset()` relative to `dirname(fileURLToPath(import.meta.url))`
of `nitro.mjs`. When run via PM2 cluster mode, `import.meta.url` may resolve incorrectly,
causing `ENOENT` for public assets. The now-removed `NuxtApp` class had a sed fix:
```bash
sed -i 's/dirname(fileURLToPath(import.meta.url))/dirname(fileURLToPath(globalThis._importMeta_.url))/g' \
    <app_dir>/.output/server/chunks/nitro/nitro.mjs
```
This is no longer needed since nginx serves `.output/public` directly and Nitro never
handles static file requests.
