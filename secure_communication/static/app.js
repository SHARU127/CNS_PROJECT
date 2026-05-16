document.addEventListener('DOMContentLoaded', () => {

    // =====================================================================
    // TAB SWITCHING
    // =====================================================================
    const navButtons = document.querySelectorAll('.nav-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    navButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.getAttribute('data-tab');
            navButtons.forEach(b => b.classList.remove('active'));
            tabContents.forEach(t => t.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        });
    });

    // =====================================================================
    // IMAGE DROP ZONES
    // =====================================================================
    function setupDropZone(dropZoneId, inputId, previewId) {
        const dropZone = document.getElementById(dropZoneId);
        const input    = document.getElementById(inputId);
        const preview  = document.getElementById(previewId);

        dropZone.addEventListener('click', () => input.click());
        dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
        dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
        dropZone.addEventListener('drop', e => {
            e.preventDefault();
            dropZone.classList.remove('drag-over');
            if (e.dataTransfer.files.length) {
                input.files = e.dataTransfer.files;
                showImagePreview(e.dataTransfer.files[0], preview);
            }
        });
        input.addEventListener('change', e => {
            if (e.target.files.length) showImagePreview(e.target.files[0], preview);
        });
    }

    function showImagePreview(file, preview) {
        if (file && file.type.startsWith('image/')) {
            const reader = new FileReader();
            reader.onload = e => {
                preview.src = e.target.result;
                preview.classList.remove('hidden');
            };
            reader.readAsDataURL(file);
        }
    }

    setupDropZone('encode-drop-zone', 'encode-image-input', 'encode-preview');
    setupDropZone('decode-drop-zone', 'decode-image-input', 'decode-preview');

    // =====================================================================
    // PEM FILE DROP ZONES (for key files)
    // =====================================================================
    function setupPemDrop(triggerId, inputId, filenameId, okId, okNameId) {
        const trigger  = document.getElementById(triggerId);
        const input    = document.getElementById(inputId);
        const fnSpan   = document.getElementById(filenameId);
        const okDiv    = document.getElementById(okId);
        const okName   = document.getElementById(okNameId);
        const dropRow  = trigger.closest('.file-drop-row');

        trigger.addEventListener('click', () => input.click());
        dropRow.addEventListener('dragover', e => { e.preventDefault(); dropRow.classList.add('drag-over'); });
        dropRow.addEventListener('dragleave', () => dropRow.classList.remove('drag-over'));
        dropRow.addEventListener('drop', e => {
            e.preventDefault();
            dropRow.classList.remove('drag-over');
            if (e.dataTransfer.files.length) {
                // Manually set the file on the input
                const dt = new DataTransfer();
                dt.items.add(e.dataTransfer.files[0]);
                input.files = dt.files;
                showPemLoaded(e.dataTransfer.files[0].name, trigger, okDiv, okName);
            }
        });
        input.addEventListener('change', e => {
            if (e.target.files.length) {
                showPemLoaded(e.target.files[0].name, trigger, okDiv, okName);
            }
        });
    }

    function showPemLoaded(filename, trigger, okDiv, okName) {
        trigger.classList.add('hidden');
        okDiv.classList.remove('hidden');
        okName.textContent = filename;
    }

    setupPemDrop('pubkey-drop-trigger',  'encode-pubkey-input',  'pubkey-filename',  'pubkey-ok',  'pubkey-ok-name');
    setupPemDrop('privkey-drop-trigger', 'decode-privkey-input', 'privkey-filename', 'privkey-ok', 'privkey-ok-name');

    // =====================================================================
    // LOADER
    // =====================================================================
    const loader     = document.getElementById('loading-overlay');
    const loaderText = document.getElementById('loader-text');
    const showLoader = text => { loaderText.textContent = text; loader.classList.remove('hidden'); };
    const hideLoader = ()   => loader.classList.add('hidden');

    // =====================================================================
    // TOAST
    // =====================================================================
    function showToast(message, type = 'info') {
        document.querySelector('.toast-notification')?.remove();
        const toast = document.createElement('div');
        toast.className = `toast-notification toast-${type}`;
        const icons = { success: 'fa-check-circle', error: 'fa-exclamation-circle', info: 'fa-info-circle' };
        toast.innerHTML = `<i class="fas ${icons[type] || icons.info}"></i><span>${message}</span>`;
        document.body.appendChild(toast);
        setTimeout(() => toast.classList.add('toast-visible'), 10);
        setTimeout(() => { toast.classList.remove('toast-visible'); setTimeout(() => toast.remove(), 400); }, 3500);
    }

    // =====================================================================
    // KEY VAULT — Generate RSA Key Pair
    // =====================================================================
    let generatedKeys = { private_key: null, public_key: null };

    document.getElementById('keygen-btn').addEventListener('click', async () => {
        showLoader('Generating RSA-2048 key pair...');
        try {
            const res = await fetch('/vault/keygen', { method: 'POST' });
            if (!res.ok) throw new Error((await res.json()).detail);
            const data = await res.json();

            generatedKeys = { private_key: data.private_key, public_key: data.public_key };
            document.getElementById('key-fingerprint').textContent = data.fingerprint;

            document.getElementById('keygen-result').classList.remove('hidden');
            document.getElementById('keygen-result').scrollIntoView({ behavior: 'smooth' });
            showToast('RSA-2048 key pair ready. Download both files.', 'success');
        } catch (err) {
            showToast('Error: ' + err.message, 'error');
        } finally {
            hideLoader();
        }
    });

    document.getElementById('download-pubkey').addEventListener('click', () => {
        if (!generatedKeys.public_key) return;
        downloadText(generatedKeys.public_key, 'ghost_public.pem');
        showToast('Public key downloaded. Share this with the sender.', 'info');
    });

    document.getElementById('download-privkey').addEventListener('click', () => {
        if (!generatedKeys.private_key) return;
        downloadText(generatedKeys.private_key, 'ghost_private.pem');
        showToast('Private key downloaded. Keep this secret!', 'info');
    });

    function downloadText(text, filename) {
        const blob = new Blob([text], { type: 'text/plain' });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href = url; a.download = filename;
        document.body.appendChild(a); a.click();
        setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 100);
    }

    // =====================================================================
    // THE FORGE — Encode with recipient's RSA public key
    // =====================================================================
    let stegoBlob = null;

    document.getElementById('encode-btn').addEventListener('click', async () => {
        const imageInput  = document.getElementById('encode-image-input');
        const pubkeyInput = document.getElementById('encode-pubkey-input');
        const message     = document.getElementById('encode-message').value.trim();
        const resultArea  = document.getElementById('encode-result');

        if (!imageInput.files[0]) {
            showToast('Please upload a carrier image.', 'error'); return;
        }
        if (!pubkeyInput.files[0]) {
            showToast("Please load the recipient's public key (.pem file).", 'error'); return;
        }
        if (!message) {
            showToast('Please type a secret message.', 'error'); return;
        }

        showLoader('Forging Ghost image... AES-256 key being sealed with RSA public key...');

        const formData = new FormData();
        formData.append('image', imageInput.files[0]);
        formData.append('recipient_pubkey', pubkeyInput.files[0]);
        formData.append('secret_message', message);

        try {
            const res = await fetch('/vault/forge', { method: 'POST', body: formData });
            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || 'Forge failed');
            }
            stegoBlob = await res.blob();
            resultArea.classList.remove('hidden');
            resultArea.scrollIntoView({ behavior: 'smooth' });
            showToast('Ghost forged! The AES key is sealed inside — no separate key to share.', 'success');
        } catch (err) {
            showToast('Error: ' + err.message, 'error');
        } finally {
            hideLoader();
        }
    });

    document.getElementById('download-stego').addEventListener('click', e => {
        e.preventDefault();
        if (!stegoBlob) return;
        const url = URL.createObjectURL(stegoBlob);
        const a   = document.createElement('a');
        a.href = url; a.download = 'ghost_vault.png';
        document.body.appendChild(a); a.click();
        setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 100);
    });

    // =====================================================================
    // THE ORACLE — Decode with recipient's RSA private key
    // =====================================================================
    document.getElementById('decode-btn').addEventListener('click', async () => {
        const imageInput   = document.getElementById('decode-image-input');
        const privkeyInput = document.getElementById('decode-privkey-input');
        const resultArea   = document.getElementById('decode-result');
        const messageText  = document.getElementById('decoded-message-text');

        if (!imageInput.files[0]) {
            showToast('Please upload the Ghost image.', 'error'); return;
        }
        if (!privkeyInput.files[0]) {
            showToast('Please load your private key file (.pem).', 'error'); return;
        }

        showLoader('Invoking Oracle... RSA private key unlocking AES session key...');

        const formData = new FormData();
        formData.append('image', imageInput.files[0]);
        formData.append('private_key', privkeyInput.files[0]);

        try {
            const res = await fetch('/vault/oracle', { method: 'POST', body: formData });
            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || 'Oracle failed');
            }
            const data    = await res.json();
            messageText.textContent = data.message;
            resultArea.classList.remove('hidden');
            resultArea.scrollIntoView({ behavior: 'smooth' });
            showToast('Secret revealed!', 'success');
        } catch (err) {
            showToast('Error: ' + err.message, 'error');
        } finally {
            hideLoader();
        }
    });

    // Copy revealed message
    document.getElementById('copy-btn').addEventListener('click', () => {
        const text = document.getElementById('decoded-message-text').textContent;
        navigator.clipboard.writeText(text).then(() => {
            const icon = document.querySelector('#copy-btn i');
            icon.classList.replace('fa-copy', 'fa-check');
            showToast('Copied!', 'success');
            setTimeout(() => icon.classList.replace('fa-check', 'fa-copy'), 2000);
        });
    });
});
