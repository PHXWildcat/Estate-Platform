import { installOffscreenListener } from './offscreen-router.js';
import { VaultHost } from './vault-host.js';
import { WorkerKeyHolder } from './worker-key-holder.js';

/**
 * The offscreen document: spawn the worker, wire the host to it, listen.
 *
 * Its whole existence is the worker — which is what makes the manifest's
 * `WORKERS` reason true rather than convenient. A teardown of this document
 * takes the worker with it, and with it the key: an offscreen teardown IS a
 * lock, and nothing here persists anything that could re-open a vault.
 */
const worker = new Worker(chrome.runtime.getURL('vault-worker.js'), { type: 'module' });
const host = new VaultHost({ holder: new WorkerKeyHolder(worker) });

installOffscreenListener(host, (listener) => {
  chrome.runtime.onMessage.addListener(listener);
});
