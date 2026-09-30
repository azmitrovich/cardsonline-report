(function () {
  const VAULT_URL = 'assets/p.751747a64526.bin';
  const SESSION_KEY = 'doc-session';
  const form = document.getElementById('gate');
  const input = document.getElementById('pw');
  const submit = document.getElementById('submit');
  const statusEl = document.getElementById('status');
  const errEl = document.getElementById('err');
  const toggle = document.getElementById('toggle');

  function setStatus(text) {
    statusEl.textContent = text || '';
  }
  function setError(text) {
    if (!text) {
      errEl.hidden = true;
      errEl.textContent = '';
      input.removeAttribute('aria-invalid');
      return;
    }
    errEl.hidden = false;
    errEl.textContent = text;
    input.setAttribute('aria-invalid', 'true');
  }
  function fail(code) {
    const error = new Error(code);
    error.code = code;
    return error;
  }

  toggle.addEventListener('click', () => {
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    toggle.textContent = show ? 'Скрыть пароль' : 'Показать пароль';
    toggle.setAttribute('aria-pressed', show ? 'true' : 'false');
    input.focus();
  });

  function mime(path) {
    const ext = (path.split('.').pop() || '').toLowerCase();
    const types = {
      html: 'text/html; charset=utf-8',
      css: 'text/css; charset=utf-8',
      js: 'text/javascript; charset=utf-8',
      svg: 'image/svg+xml',
      png: 'image/png',
      jpg: 'image/jpeg',
      jpeg: 'image/jpeg',
      webp: 'image/webp',
      gif: 'image/gif',
      md: 'text/plain; charset=utf-8',
      txt: 'text/plain; charset=utf-8',
      json: 'application/json'
    };
    return types[ext] || 'application/octet-stream';
  }

  function unpack(raw) {
    const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
    const files = new Map();
    let offset = 0;
    const decoder = new TextDecoder();
    while (offset + 8 <= raw.length) {
      const pathLen = view.getUint32(offset, true);
      const bodyLen = view.getUint32(offset + 4, true);
      offset += 8;
      if (pathLen < 0 || bodyLen < 0 || offset + pathLen + bodyLen > raw.length) throw fail('corrupt');
      const path = decoder.decode(raw.subarray(offset, offset + pathLen));
      offset += pathLen;
      const body = raw.slice(offset, offset + bodyLen);
      offset += bodyLen;
      files.set(path, body);
    }
    return files;
  }

  async function deriveKey(password, salt, iterations) {
    const baseKey = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
  }

  async function decryptVault(password) {
    if (!crypto.subtle) throw fail('insecure');
    const response = await fetch(VAULT_URL, { cache: 'no-store' });
    if (!response.ok) throw fail('missing');
    const data = new Uint8Array(await response.arrayBuffer());
    if (data.length < 52 || new TextDecoder().decode(data.subarray(0, 4)) !== 'CRV1') throw fail('corrupt');
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const iterations = view.getUint32(4, true);
    if (iterations < 100000 || iterations > 1000000) throw fail('corrupt');
    const salt = data.subarray(8, 24);
    const iv = data.subarray(24, 36);
    const cipher = data.subarray(36);
    const key = await deriveKey(password, salt, iterations);
    let plain;
    try {
      plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipher));
    } catch (e) {
      throw fail('bad-password');
    }
    const stream = new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'));
    const raw = new Uint8Array(await new Response(stream).arrayBuffer());
    return unpack(raw);
  }

  function resolveRelative(fromPath, url) {
    if (!url || url.startsWith('#') || /^(https?:|data:|mailto:|blob:)/i.test(url)) return null;
    const trailing = url.endsWith('/');
    const dir = fromPath.includes('/') ? fromPath.slice(0, fromPath.lastIndexOf('/') + 1) : '';
    const joined = url.startsWith('/') ? url.replace(/^\/+/, '') : dir + url;
    const out = [];
    for (const part of joined.split('/')) {
      if (!part || part === '.') continue;
      if (part === '..') out.pop();
      else out.push(part);
    }
    let next = out.join('/');
    if (trailing) next += '/index.html';
    return next;
  }

  function rewrite(html, fromPath, urls) {
    return html.replace(/(href|src|data-full)="([^"]*)"/gi, (full, attr, url) => {
      const hashAt = url.indexOf('#');
      const hash = hashAt >= 0 ? url.slice(hashAt) : '';
      const base = (hashAt >= 0 ? url.slice(0, hashAt) : url).split('?')[0];
      const resolved = resolveRelative(fromPath, base);
      const mapped = resolved && urls.get(resolved);
      if (!mapped) return full;
      return attr + '="' + mapped + hash + '"';
    });
  }

  function blobUrl(bytes, type) {
    return URL.createObjectURL(new Blob([bytes], { type }));
  }

  function showDocument(html) {
    const frame = document.createElement('iframe');
    frame.title = 'Документ';
    frame.style.cssText = 'position:fixed;inset:0;width:100%;height:100%;border:0;background:#f3efe6';
    frame.srcdoc = html;
    frame.addEventListener('load', () => {
      try {
        const sync = () => {
          if (frame.contentDocument && frame.contentDocument.title) document.title = frame.contentDocument.title;
        };
        sync();
        const title = frame.contentDocument.querySelector('title');
        if (title) new MutationObserver(sync).observe(title, { childList: true, characterData: true, subtree: true });
      } catch (e) {}
    });
    document.body.replaceChildren(frame);
    document.body.style.margin = '0';
  }

  async function unlock(password) {
    setStatus('Проверяем пароль…');
    submit.disabled = true;
    const packed = await decryptVault(password);
    const htmlBytes = packed.get('index.html');
    if (!htmlBytes) throw fail('corrupt');
    setStatus('Открываем документ…');
    const decoder = new TextDecoder();
    const urls = new Map();
    const htmlLater = new Set(['index.html', 'assets/screenshots/index.html']);
    for (const [path, body] of packed) {
      if (htmlLater.has(path)) continue;
      urls.set(path, blobUrl(body, mime(path)));
    }
    const shots = packed.get('assets/screenshots/index.html');
    if (shots) {
      const shotHtml = rewrite(decoder.decode(shots), 'assets/screenshots/index.html', urls);
      urls.set('assets/screenshots/index.html', blobUrl(new TextEncoder().encode(shotHtml), mime('assets/screenshots/index.html')));
    }
    let html = decoder.decode(htmlBytes);
    const css = decoder.decode(packed.get('assets/report.css') || new Uint8Array()).replace(/<\/style/gi, '<\\/style');
    const i18n = decoder.decode(packed.get('assets/i18n.js') || new Uint8Array()).replace(/<\/script/gi, '<\\/script');
    const report = decoder.decode(packed.get('assets/report.js') || new Uint8Array()).replace(/<\/script/gi, '<\\/script');
    html = html.replace('<link rel="stylesheet" href="assets/report.css">', '<style>' + css + '</style>');
    html = html.replace('<script src="assets/i18n.js"></script>', '<script>' + i18n + '</script>');
    html = html.replace('<script src="assets/report.js"></script>', '<script>' + report + '</script>');
    html = rewrite(html, 'index.html', urls);
    sessionStorage.setItem(SESSION_KEY, password);
    showDocument(html);
  }

  async function clearLeftovers() {
    try {
      if ('serviceWorker' in navigator) {
        const regs = await navigator.serviceWorker.getRegistrations();
        await Promise.all(regs.map((reg) => reg.unregister()));
      }
      if ('caches' in window) {
        const keys = await caches.keys();
        await Promise.all(keys.map((key) => caches.delete(key)));
      }
    } catch (e) {}
  }

  async function start() {
    input.focus();
    await clearLeftovers();
    const saved = sessionStorage.getItem(SESSION_KEY);
    if (saved) {
      setStatus('Открываем документ…');
      try {
        await unlock(saved);
        return;
      } catch (e) {
        sessionStorage.removeItem(SESSION_KEY);
        submit.disabled = false;
        setStatus('');
        setError('Сессия истекла. Введите пароль ещё раз.');
      }
    }
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      setError('');
      try {
        await unlock(input.value);
      } catch (e) {
        submit.disabled = false;
        setStatus('');
        setError(e.code === 'bad-password' ? 'Неверный пароль' : 'Не удалось открыть документ');
      }
    });
  }

  start();
})();
