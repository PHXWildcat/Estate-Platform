import { handleWorkerRequest, type WorkerRequest } from './worker-protocol.js';
import { VaultKeyHolder } from './vault-worker-core.js';

/**
 * The worker entry: four lines around `handleWorkerRequest`, which the suite
 * drives directly. What is not testable here is `self.onmessage` itself, and
 * a test that stubbed it would only prove the stub.
 *
 * THE KEY LIVES BEHIND THIS BOUNDARY and never crosses it. Nothing in the
 * protocol returns one, and there is no variant that could.
 */
const holder = new VaultKeyHolder();

self.addEventListener('message', (event: MessageEvent) => {
  void handleWorkerRequest(holder, event.data as WorkerRequest).then((response) => {
    self.postMessage(response);
  });
});
