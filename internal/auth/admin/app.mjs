import {adminApi} from './api.mjs';

const api = adminApi();
const byId = (id) => document.getElementById(id);
const form = byId('login');
const queue = byId('queue');
const preview = byId('preview');
let selected;
let imageURL;
let busy = false;

function clearPreview() {
  if (imageURL) URL.revokeObjectURL(imageURL);
  imageURL = undefined;
  preview.removeAttribute('src');
  preview.hidden = true;
}

function clearSelection() {
  selected = undefined;
  clearPreview();
  byId('documents').replaceChildren();
  byId('reason').value = '';
  byId('selection').hidden = true;
}

function signedOut() {
  clearSelection();
  byId('items').replaceChildren();
  queue.hidden = true;
  byId('logout').hidden = true;
  form.hidden = false;
}

async function run(action) {
  if (busy) return;
  busy = true;
  byId('message').textContent = '';
  try { await action(); }
  catch (error) {
    if (error.status === 401 || error.status === 403) {
      signedOut();
      await api.logout();
      byId('message').textContent = 'Sign in with an authorized reviewer account.';
    } else if (error.status === 409) {
      clearSelection();
      byId('message').textContent = 'This version is no longer available. Refresh the queue.';
    } else {
      byId('message').textContent = error.message;
    }
  } finally { busy = false; }
}

function select(item) {
  if (busy) return;
  clearSelection();
  selected = {kind: item.kind, user_id: item.user_id, vehicle_id: item.vehicle_id, version: item.version};
  byId('title').textContent = `${item.label} · Version ${item.version}`;
  const sides = item.kind === 'identity' ? ['front', 'back'] : ['registration', 'insurance'];
  for (const side of sides) {
    const button = document.createElement('button');
    button.textContent = `View ${side}`;
    button.addEventListener('click', () => run(async () => {
      clearPreview();
      const image = await api.document(selected, side);
      if (!['image/jpeg', 'image/png'].includes(image.mime)) throw new Error('Unexpected document format.');
      const bytes = Uint8Array.from(atob(image.data), (value) => value.charCodeAt(0));
      imageURL = URL.createObjectURL(new Blob([bytes], {type: image.mime}));
      preview.src = imageURL;
      preview.hidden = false;
    }));
    byId('documents').append(button);
  }
  byId('selection').hidden = false;
}

function render(result) {
  clearSelection();
  const list = byId('items');
  list.replaceChildren();
  if (!result.submissions.length) {
    const empty = document.createElement('li');
    empty.textContent = 'No pending submissions.';
    list.append(empty);
    return;
  }
  for (const item of result.submissions) {
    const row = document.createElement('li');
    const button = document.createElement('button');
    button.textContent = `${item.kind === 'identity' ? 'Identity' : 'Vehicle'} · ${item.label} · Version ${item.version}`;
    button.addEventListener('click', () => select(item));
    row.append(button);
    list.append(row);
  }
}

form.addEventListener('submit', (event) => {
  event.preventDefault();
  run(async () => {
    const fields = new FormData(form);
    form.reset();
    render(await api.login(String(fields.get('phone')), String(fields.get('password'))));
    form.hidden = true;
    queue.hidden = false;
    byId('logout').hidden = false;
  });
});
byId('logout').addEventListener('click', () => run(async () => {
  signedOut();
  await api.logout();
}));
byId('reload').addEventListener('click', () => run(async () => render(await api.queue())));

async function decide(decision) {
  if (!selected) return;
  const reason = decision === 'rejected' ? byId('reason').value.trim() : '';
  if (decision === 'rejected' && !reason) throw new Error('Enter a reason for rejection.');
  await api.decision(selected, decision, reason);
  clearSelection();
  try {
    render(await api.queue());
    byId('message').textContent = 'Decision recorded.';
  } catch (error) {
    if (error.status === 401 || error.status === 403) throw error;
    byId('message').textContent = 'Decision recorded. Refresh the queue to see the remaining submissions.';
  }
}
byId('approve').addEventListener('click', () => run(() => decide('approved')));
byId('reject').addEventListener('click', () => run(() => decide('rejected')));
window.addEventListener('pagehide', clearPreview);
