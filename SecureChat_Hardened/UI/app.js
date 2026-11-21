/* SecureChat web UI logic.
 *
 * The browser never touches the socket or the AES key. client_ui.py does the
 * Diffie-Hellman exchange and encryption, and this page talks to it with
 * simple JSON requests plus one long-polling request for incoming events.
 */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);

  const els = {
    auth: $('auth'),
    authForm: $('auth-form'),
    username: $('username'),
    password: $('password'),
    authError: $('auth-error'),
    authSubmit: $('auth-submit'),
    tabs: Array.from(document.querySelectorAll('.tab')),

    app: $('app'),
    meAvatar: $('me-avatar'),
    meName: $('me-name'),
    meConn: $('me-conn'),
    logout: $('logout-btn'),
    search: $('search'),
    onlineCount: $('online-count'),
    contacts: $('contacts'),

    chat: $('chat'),
    backBtn: $('back-btn'),
    peer: $('peer'),
    peerAvatar: $('peer-avatar'),
    peerName: $('peer-name'),
    peerStatus: $('peer-status'),
    chatConn: $('chat-conn'),
    banner: $('banner'),
    empty: $('empty'),
    messages: $('messages'),
    composer: $('composer'),
    input: $('message-input'),
    sendBtn: $('send-btn'),
  };

  const STORAGE_KEY = 'securechat.session';
  const USER_REFRESH_MS = 15000;

  const state = {
    mode: 'login',        // 'login' or 'register'
    token: null,
    me: null,
    users: [],            // [{name, online}] for everyone except me
    chats: new Map(),     // peer name -> {messages: [], unread: 0}
    active: null,         // peer name currently open
    bridgeOk: true,       // can we reach client_ui.py?
    serverOk: true,       // is client_ui.py connected to server.py?
    loopId: 0,            // changes on logout so old poll loops stop
    usersTimer: null,
  };

  // ---------- Authenticated, encrypted link to the bridge ----------
  // Group: RFC 7919 ffdhe3072 (same as config.py), generator 2.
  // The bridge signs its DH value with RSA-PSS; the page checks that signature
  // against the pinned key in ui_public_key.js before it trusts the exchange.
  // Session key: HKDF-SHA256 over the shared secret, salted with SHA-256 of
  // both public values. Each body: AES-256-GCM, layout nonce(12) || ciphertext || tag.
  const DH_P = BigInt('0xFFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF');
  const DH_Q = (DH_P - 1n) / 2n;   // p is a safe prime: p = 2q + 1
  const DH_G = 2n;
  const DH_BYTES = 384;            // 3072 bits
  const GCM_IV_BYTES = 12;
  const HKDF_INFO = new TextEncoder().encode('SecureChat AES-256-GCM v1');
  let channel = null;   // {id, key}: the encrypted link for this tab

  function modPow(base, exp, mod) {
    let result = 1n;
    let b = base % mod;
    let e = exp;
    while (e > 0n) {
      if (e & 1n) result = (result * b) % mod;
      b = (b * b) % mod;
      e >>= 1n;
    }
    return result;
  }

  function randomPrivateValue() {
    const bytes = crypto.getRandomValues(new Uint8Array(DH_BYTES));
    let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    return (value % (DH_P - 3n)) + 2n;
  }

  function bigIntToBytes(value, length) {
    const out = new Uint8Array(length);
    let v = value;
    for (let i = length - 1; i >= 0; i--) {
      out[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    return out;
  }

  // Errors that mean the connection cannot be trusted. Marked so the page can show them.
  function securityError(message) {
    const error = new Error(message);
    error.security = true;
    return error;
  }

  // Reject values outside [2, p-2] or outside the order-q subgroup (value^q must be 1).
  function validatePublic(value) {
    if (value < 2n || value > DH_P - 2n) throw securityError('Invalid key exchange value from server.');
    if (modPow(value, DH_Q, DH_P) !== 1n) throw securityError('Key exchange value is not in the valid subgroup.');
  }

  // Same bytes the server signs: client public || server public, fixed width.
  function transcriptBytes(clientPublic, serverPublic) {
    const out = new Uint8Array(DH_BYTES * 2);
    out.set(bigIntToBytes(clientPublic, DH_BYTES), 0);
    out.set(bigIntToBytes(serverPublic, DH_BYTES), DH_BYTES);
    return out;
  }

  async function deriveKey(sharedBytes, clientPublic, serverPublic) {
    const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', transcriptBytes(clientPublic, serverPublic)));
    const base = await crypto.subtle.importKey('raw', sharedBytes, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info: HKDF_INFO },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  let pinnedKeyPromise = null;
  function pinnedBridgeKey() {
    if (!pinnedKeyPromise) {
      if (!window.SECURECHAT_UI_KEY_SPKI) {
        throw new Error('Missing pinned bridge key (UI/ui_public_key.js). Run gen_keys.py.');
      }
      pinnedKeyPromise = crypto.subtle.importKey(
        'spki',
        fromBase64(window.SECURECHAT_UI_KEY_SPKI),
        { name: 'RSA-PSS', hash: 'SHA-256' },
        false,
        ['verify']
      );
    }
    return pinnedKeyPromise;
  }

  function toBase64(bytes) {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
  }

  function fromBase64(text) {
    return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
  }

  async function sealJson(key, payload) {
    const iv = crypto.getRandomValues(new Uint8Array(GCM_IV_BYTES));
    const plain = new TextEncoder().encode(JSON.stringify(payload));
    const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain));
    const out = new Uint8Array(GCM_IV_BYTES + cipher.length);
    out.set(iv, 0);
    out.set(cipher, GCM_IV_BYTES);
    return toBase64(out);
  }

  async function openJson(key, text) {
    const bytes = fromBase64(text);
    const iv = bytes.slice(0, GCM_IV_BYTES);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, bytes.slice(GCM_IV_BYTES));
    return JSON.parse(new TextDecoder().decode(plain));
  }

  async function ensureChannel() {
    if (channel) return channel;
    if (!window.crypto || !window.crypto.subtle) {
      throw new Error('Encryption needs the page opened at http://127.0.0.1:8000 or http://localhost:8000.');
    }

    const privateValue = randomPrivateValue();
    const clientPublic = modPow(DH_G, privateValue, DH_P);
    const response = await fetch('/api/handshake', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dh_public: clientPublic.toString() }),
    });
    const data = await response.json();
    if (!data.ok) throw new Error(data.message || 'Key exchange failed.');

    const serverPublic = BigInt(data.dh_public);
    validatePublic(serverPublic);

    const verifyKey = await pinnedBridgeKey();
    const signatureOk = await crypto.subtle.verify(
      { name: 'RSA-PSS', saltLength: 32 },
      verifyKey,
      fromBase64(data.signature || ''),
      transcriptBytes(clientPublic, serverPublic)
    );
    if (!signatureOk) {
      throw securityError('Could not verify the server. The connection was refused.');
    }

    const shared = bigIntToBytes(modPow(serverPublic, privateValue, DH_P), DH_BYTES);
    const key = await deriveKey(shared, clientPublic, serverPublic);
    channel = { id: data.channel, key };
    return channel;
  }

  // Every request and response body is AES encrypted with this tab's key.
  async function api(path, body) {
    const ch = await ensureChannel();
    const sealed = await sealJson(ch.key, body);
    const response = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ channel: ch.id, data: sealed }),
    });

    let raw = {};
    try {
      raw = await response.json();
    } catch (error) {
      raw = {};
    }

    if (response.status === 401) channel = null;   // bridge forgot this link

    let data = raw;
    if (raw && typeof raw.data === 'string') {
      try {
        data = await openJson(ch.key, raw.data);
      } catch (error) {
        data = { ok: false, message: 'Could not decrypt the server reply.' };
      }
    }
    return { status: response.status, data };
  }

  // ---------- Small helpers ----------

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  function makeId() {
    if (window.crypto && typeof window.crypto.randomUUID === 'function') {
      return window.crypto.randomUUID();
    }
    return Date.now().toString(36) + Math.random().toString(36).slice(2);
  }

  function initial(name) {
    const first = (name || '').trim().charAt(0);
    return first ? first.toUpperCase() : '?';
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function avatar(name) {
    return el('div', 'avatar', initial(name));
  }

  function findUser(name) {
    return state.users.find((user) => user.name === name) || null;
  }

  function sortUsers() {
    state.users.sort((a, b) => (Number(b.online) - Number(a.online)) || a.name.localeCompare(b.name));
  }

  function getChat(peer) {
    if (!state.chats.has(peer)) {
      state.chats.set(peer, { messages: [], unread: 0 });
    }
    return state.chats.get(peer);
  }

  function findMessage(id) {
    if (id === null || id === undefined) return null;
    for (const chat of state.chats.values()) {
      const message = chat.messages.find((item) => item.id === id);
      if (message) return message;
    }
    return null;
  }

  function updateMessage(id, change) {
    const message = findMessage(id);
    if (!message) return;
    change(message);
    renderMessages();
  }

  function isViewing(peer) {
    return state.active === peer && !document.hidden;
  }

  // ---------- Saved session ----------
  // Sessions are not stored in the browser, because the encryption key
  // must stay in memory. Refreshing the page means logging in again.
  function clearSession() {}

  // ---------- Login / registration ----------

  function setMode(mode) {
    state.mode = mode;
    els.tabs.forEach((tab) => {
      const selected = tab.dataset.mode === mode;
      tab.classList.toggle('active', selected);
      tab.setAttribute('aria-selected', String(selected));
    });
    els.authSubmit.textContent = mode === 'login' ? 'Log in' : 'Create account';
    els.password.autocomplete = mode === 'login' ? 'current-password' : 'new-password';
    showAuthError('');
  }

  function showAuthError(message) {
    els.authError.textContent = message || '';
    els.authError.hidden = !message;
  }

  els.tabs.forEach((tab) => {
    tab.addEventListener('click', () => setMode(tab.dataset.mode));
  });

  els.authForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const username = els.username.value.trim();
    const password = els.password.value;

    if (!username || !password) {
      showAuthError('Enter a username and password.');
      return;
    }

    els.authSubmit.disabled = true;
    showAuthError('');
    try {
      const path = state.mode === 'login' ? '/api/login' : '/api/register';
      const { data } = await api(path, { username, password });
      if (!data.ok) {
        showAuthError(data.message || 'Could not sign in.');
        return;
      }
      els.password.value = '';
      startSession(data.token, data.username);
    } catch (error) {
      showAuthError(error.security ? error.message : 'Cannot reach the web client. Is client_ui.py still running?');
    } finally {
      els.authSubmit.disabled = false;
    }
  });

  // ---------- Session lifecycle ----------

  function startSession(token, user) {
    state.token = token;
    state.me = user;
    state.users = [];
    state.chats = new Map();
    state.active = null;
    state.bridgeOk = true;
    state.serverOk = true;

    els.auth.hidden = true;
    els.app.hidden = false;
    els.meAvatar.textContent = initial(user);
    els.meName.textContent = user;
    els.search.value = '';
    els.app.classList.remove('chat-open');

    const loop = ++state.loopId;
    pollEvents(loop);
    refreshUsers();
    clearInterval(state.usersTimer);
    state.usersTimer = setInterval(refreshUsers, USER_REFRESH_MS);

    renderAll();
  }

  function endSession(message) {
    channel = null;
    state.token = null;
    state.loopId += 1;
    clearInterval(state.usersTimer);
    clearSession();
    state.users = [];
    state.chats = new Map();
    state.active = null;

    els.app.hidden = true;
    els.auth.hidden = false;
    setMode('login');
    showAuthError(message || '');
    els.username.focus();
  }

  els.logout.addEventListener('click', async () => {
    const token = state.token;
    endSession('');
    try {
      await api('/api/logout', { token });
    } catch (error) {
      /* The bridge will drop the session when it goes idle. */
    }
  });

  async function refreshUsers() {
    if (!state.token) return;
    try {
      await api('/api/users', { token: state.token });
    } catch (error) {
      /* The event loop reports connection problems. */
    }
  }

  // ---------- Incoming events (long polling) ----------

  async function pollEvents(loop) {
    let failures = 0;

    while (state.token && loop === state.loopId) {
      try {
        const { status, data } = await api('/api/events', { token: state.token });
        if (loop !== state.loopId) return;

        if (status === 401) {
          endSession(data.message || 'Your session has ended. Please log in again.');
          return;
        }
        if (status !== 200) throw new Error('Unexpected status ' + status);

        failures = 0;
        state.bridgeOk = true;
        state.serverOk = data.connected !== false;
        (data.events || []).forEach(handleEvent);
        updateConnection();
      } catch (error) {
        if (loop !== state.loopId) return;
        failures += 1;
        state.bridgeOk = false;
        updateConnection();
        await sleep(Math.min(5000, 500 * failures));
      }
    }
  }

  function handleEvent(event) {
    switch (event.type) {
      case 'message':
        onIncoming(event);
        break;
      case 'ack':
        // Single tick: the server has received and forwarded the message.
        updateMessage(event.id, (message) => {
          if (message.status === 'pending') message.status = 'delivered';
        });
        break;
      case 'read':
        // Double tick: the recipient has displayed the message.
        updateMessage(event.id, (message) => {
          message.status = 'read';
        });
        break;
      case 'error':
        updateMessage(event.id, (message) => {
          message.status = 'failed';
        });
        break;
      case 'presence':
        onPresence(event.user, event.online);
        break;
      case 'users':
        onUsers(event.users || []);
        break;
      case 'status':
        state.serverOk = Boolean(event.connected);
        updateConnection();
        break;
      default:
        break;
    }
  }

  function onIncoming(event) {
    const peer = event.from;
    if (!peer || peer === state.me) return;

    const chat = getChat(peer);
    chat.messages.push({
      id: event.id ?? null,
      mine: false,
      text: event.text,
      status: null,
      readSent: false,
    });

    if (!findUser(peer)) {
      refreshUsers();
    }

    if (isViewing(peer)) {
      renderMessages();
      markRead(peer);
    } else {
      chat.unread += 1;
      renderContacts();
    }
  }

  function onPresence(user, online) {
    if (!user || user === state.me) return;
    let entry = findUser(user);
    if (!entry) {
      entry = { name: user, online: false };
      state.users.push(entry);
    }
    entry.online = Boolean(online);
    sortUsers();
    renderContacts();
    if (state.active === user) {
      renderHeader();
      updateComposer();
    }
  }

  function onUsers(list) {
    state.users = list
      .filter((item) => item.name !== state.me)
      .map((item) => ({ name: item.name, online: Boolean(item.online) }));
    sortUsers();
    renderContacts();
    renderHeader();
    updateComposer();
  }

  // ---------- Sending and read receipts ----------

  async function sendMessage(text) {
    const peer = state.active;
    if (!peer || !state.token) return;

    const id = makeId();
    getChat(peer).messages.push({
      id,
      mine: true,
      text,
      status: 'pending',
      readSent: false,
    });
    renderMessages();

    try {
      const { data } = await api('/api/send', {
        token: state.token,
        to: peer,
        id,
        text,
      });
      if (!data.ok) {
        updateMessage(id, (message) => {
          message.status = 'failed';
        });
      }
    } catch (error) {
      updateMessage(id, (message) => {
        message.status = 'failed';
      });
    }
  }

  function markRead(peer) {
    const chat = state.chats.get(peer);
    if (!chat) return;

    chat.unread = 0;
    chat.messages.forEach((message) => {
      if (message.mine || !message.id || message.readSent) return;
      message.readSent = true;
      api('/api/read', { token: state.token, to: peer, id: message.id }).catch(() => {
        message.readSent = false;
      });
    });
    renderContacts();
  }

  els.composer.addEventListener('submit', (event) => {
    event.preventDefault();
    const text = els.input.value.trim();
    if (!text || els.input.disabled) return;
    els.input.value = '';
    sendMessage(text);
    els.input.focus();
  });

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && state.active) {
      markRead(state.active);
    }
  });

  // ---------- Chat selection ----------

  function openChat(name) {
    state.active = name;
    getChat(name);
    els.app.classList.add('chat-open');
    markRead(name);
    renderAll();
    if (!els.input.disabled) els.input.focus();
  }

  els.backBtn.addEventListener('click', () => {
    state.active = null;
    els.app.classList.remove('chat-open');
    renderAll();
  });

  els.search.addEventListener('input', renderContacts);

  // ---------- Rendering ----------

  function renderAll() {
    renderContacts();
    renderHeader();
    renderMessages();
    updateComposer();
    updateConnection();
  }

  function renderContacts() {
    const query = els.search.value.trim().toLowerCase();
    const visible = state.users.filter((user) => user.name.toLowerCase().includes(query));
    const onlineTotal = state.users.filter((user) => user.online).length;

    els.onlineCount.textContent = `${onlineTotal} online`;
    els.contacts.textContent = '';

    if (state.users.length === 0) {
      const item = el('li', 'list-empty',
        'No other users yet. Create a second account in another browser window.');
      els.contacts.appendChild(item);
      return;
    }

    if (visible.length === 0) {
      els.contacts.appendChild(el('li', 'list-empty', 'No matching people.'));
      return;
    }

    visible.forEach((user) => {
      const chat = state.chats.get(user.name);
      const unread = chat ? chat.unread : 0;

      const item = el('li');
      const button = el('button', 'contact' + (state.active === user.name ? ' active' : ''));
      button.type = 'button';
      button.addEventListener('click', () => openChat(user.name));

      const info = el('div', 'info');
      info.appendChild(el('div', 'name', user.name));
      info.appendChild(el('div', 'sub', user.online ? 'Online' : 'Offline'));

      const meta = el('div', 'meta');
      if (unread > 0) {
        meta.appendChild(el('span', 'badge', String(unread)));
      }
      meta.appendChild(el('span', 'presence' + (user.online ? ' online' : '')));

      button.append(avatar(user.name), info, meta);
      item.appendChild(button);
      els.contacts.appendChild(item);
    });
  }

  function renderHeader() {
    const peer = state.active;
    const hasPeer = Boolean(peer);

    els.peer.hidden = !hasPeer;
    els.backBtn.hidden = !hasPeer;
    els.empty.hidden = hasPeer;
    els.messages.hidden = !hasPeer;
    els.composer.hidden = !hasPeer;

    if (!hasPeer) return;

    const user = findUser(peer);
    const online = Boolean(user && user.online);
    els.peerAvatar.textContent = initial(peer);
    els.peerName.textContent = peer;
    els.peerStatus.textContent = online ? 'Online' : 'Offline';
  }

  function renderMessages() {
    const chat = state.active ? state.chats.get(state.active) : null;
    const nearBottom = els.messages.scrollHeight - els.messages.scrollTop - els.messages.clientHeight < 120;

    els.messages.textContent = '';
    if (!chat) return;

    if (chat.messages.length === 0) {
      els.messages.appendChild(el('p', 'messages-empty', 'No messages yet. Say hello!'));
      return;
    }

    chat.messages.forEach((message) => {
      const wrapper = el('div', 'msg ' + (message.mine ? 'mine' : 'theirs'));
      wrapper.appendChild(el('div', 'bubble', message.text));
      if (message.mine) {
        wrapper.appendChild(ticksFor(message));
      }
      els.messages.appendChild(wrapper);
    });

    if (nearBottom || chat.messages[chat.messages.length - 1].mine) {
      els.messages.scrollTop = els.messages.scrollHeight;
    }
  }

  function ticksFor(message) {
    switch (message.status) {
      case 'delivered':
        return el('div', 'ticks', '✓');          // single tick
      case 'read':
        return el('div', 'ticks read', '✓✓'); // double tick
      case 'failed':
        return el('div', 'ticks failed', 'Not delivered');
      default:
        return el('div', 'ticks');                    // still sending
    }
  }

  function updateComposer() {
    const peer = state.active;
    const user = peer ? findUser(peer) : null;
    const connected = state.serverOk && state.bridgeOk;
    const canSend = Boolean(peer) && connected && Boolean(user && user.online);

    els.input.disabled = !canSend;
    els.sendBtn.disabled = !canSend;

    if (!peer) {
      els.input.placeholder = 'Write a message...';
    } else if (!connected) {
      els.input.placeholder = 'Disconnected. Log out and log in again to send messages.';
    } else if (!user || !user.online) {
      els.input.placeholder = `${peer} is offline. Messages can't be delivered right now.`;
    } else {
      els.input.placeholder = 'Write a message...';
    }
  }

  function setConnection(node, ok) {
    node.classList.toggle('online', ok);
    node.classList.toggle('offline', !ok);
    node.lastElementChild.textContent = ok ? 'Connected' : 'Disconnected';
  }

  function updateConnection() {
    const ok = state.bridgeOk && state.serverOk;
    setConnection(els.meConn, ok);
    setConnection(els.chatConn, ok);

    els.banner.hidden = ok;
    if (!state.bridgeOk) {
      els.banner.textContent = 'Cannot reach the web client. Retrying...';
    } else {
      els.banner.textContent = 'Disconnected from the chat server. Log out and log in again to reconnect.';
    }

    updateComposer();
  }

  // ---------- Start ----------

  function init() {
    setMode('login');
    els.auth.hidden = false;
    els.app.hidden = true;
  }

  init();
})();
