document.addEventListener('DOMContentLoaded', () => {
    // TAB SWITCHING
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

    // PASSWORD TOGGLE
    document.querySelectorAll('.toggle-pass').forEach(toggle => {
        toggle.addEventListener('click', () => {
            const input = toggle.previousElementSibling;
            if (input.type === 'password') {
                input.type = 'text';
                toggle.classList.replace('fa-eye-slash', 'fa-eye');
            } else {
                input.type = 'password';
                toggle.classList.replace('fa-eye', 'fa-eye-slash');
            }
        });
    });

    // IMAGE PREVIEW & DROP ZONE
    function setupDropZone(dropZoneId, inputId, previewId) {
        const dropZone = document.getElementById(dropZoneId);
        const input = document.getElementById(inputId);
        const preview = document.getElementById(previewId);

        dropZone.addEventListener('click', () => input.click());

        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('drag-over');
        });

        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('drag-over');
        });

        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('drag-over');
            if (e.dataTransfer.files.length) {
                input.files = e.dataTransfer.files;
                handleFile(e.dataTransfer.files[0], preview);
            }
        });

        input.addEventListener('change', (e) => {
            if (e.target.files.length) {
                handleFile(e.target.files[0], preview);
            }
        });
    }

    function handleFile(file, preview) {
        if (file && file.type.startsWith('image/')) {
            const reader = new FileReader();
            reader.onload = (e) => {
                preview.src = e.target.result;
                preview.classList.remove('hidden');
            };
            reader.readAsDataURL(file);
        }
    }

    setupDropZone('encode-drop-zone', 'encode-image-input', 'encode-preview');
    setupDropZone('decode-drop-zone', 'decode-image-input', 'decode-preview');

    // LOADER HELPER
    const loader = document.getElementById('loading-overlay');
    const loaderText = document.getElementById('loader-text');

    function showLoader(text) {
        loaderText.textContent = text;
        loader.classList.remove('hidden');
    }

    function hideLoader() {
        loader.classList.add('hidden');
    }

    // ENCODE ACTION
    const encodeBtn = document.getElementById('encode-btn');
    encodeBtn.addEventListener('click', async () => {
        const fileInput = document.getElementById('encode-image-input');
        const passwordInput = document.getElementById('encode-password');
        const messageInput = document.getElementById('encode-message');
        const resultArea = document.getElementById('encode-result');

        if (!fileInput.files[0] || !passwordInput.value || !messageInput.value) {
            alert('Please fill all fields and upload an image.');
            return;
        }

        showLoader('Engraving secret into digital residue...');

        const formData = new FormData();
        formData.append('image', fileInput.files[0]);
        formData.append('secret_message', messageInput.value);
        formData.append('password', passwordInput.value);

        try {
            const response = await fetch('/vault/encode', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Failed to encode');
            }

            const blob = await response.blob();
            const url = window.URL.createObjectURL(new Blob([blob], { type: 'image/png' }));
            
            const downloadBtn = document.getElementById('download-stego');
            downloadBtn.onclick = (e) => {
                e.preventDefault();
                const a = document.createElement('a');
                a.href = url;
                a.download = 'ghost_vault.png';
                document.body.appendChild(a);
                a.click();
                setTimeout(() => {
                    document.body.removeChild(a);
                    window.URL.revokeObjectURL(url);
                }, 100);
            };

            resultArea.classList.remove('hidden');
            resultArea.scrollIntoView({ behavior: 'smooth' });

        } catch (err) {
            alert('Error: ' + err.message);
        } finally {
            hideLoader();
        }
    });

    // DECODE ACTION
    const decodeBtn = document.getElementById('decode-btn');
    decodeBtn.addEventListener('click', async () => {
        const fileInput = document.getElementById('decode-image-input');
        const passwordInput = document.getElementById('decode-password');
        const resultArea = document.getElementById('decode-result');
        const messageText = document.getElementById('decoded-message-text');

        if (!fileInput.files[0] || !passwordInput.value) {
            alert('Please upload the Ghost image and enter the key.');
            return;
        }

        showLoader('Invoking the Oracle for truth...');

        const formData = new FormData();
        formData.append('image', fileInput.files[0]);
        formData.append('password', passwordInput.value);

        try {
            const response = await fetch('/vault/decode', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Failed to decode');
            }

            const result = await response.json();
            messageText.textContent = result.message;
            resultArea.classList.remove('hidden');
            resultArea.scrollIntoView({ behavior: 'smooth' });

        } catch (err) {
            alert('Error: ' + err.message);
        } finally {
            hideLoader();
        }
    });

    // COPY BUTTON
    document.getElementById('copy-btn').addEventListener('click', () => {
        const text = document.getElementById('decoded-message-text').textContent;
        navigator.clipboard.writeText(text).then(() => {
            const icon = document.querySelector('#copy-btn i');
            icon.classList.replace('fa-copy', 'fa-check');
            setTimeout(() => icon.classList.replace('fa-check', 'fa-copy'), 2000);
        });
    });
});
