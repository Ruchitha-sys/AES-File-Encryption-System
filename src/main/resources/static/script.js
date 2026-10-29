
const fileForm = document.getElementById("fileForm");
const fileTitle = document.getElementById("fileTitle");
const dropZone = document.getElementById("dropZone");
const fileDescription = document.getElementById("fileDescription");
const fileInput = document.getElementById("fileInput");
const fileInfo = document.getElementById("fileInfo");
const fileName = document.getElementById("fileName");
const removeFile = document.getElementById("removeFile");
const passwordInput = document.getElementById("password");
const passwordHint = document.getElementById("passwordHint");
const confirmLabel = document.getElementById("confirmLabel");
const confirmPassword = document.getElementById("confirmPassword");
const submitButton = document.getElementById("submitButton");
const statusBox = document.getElementById("status");
const tabs = document.querySelectorAll(".tab");

let mode = "encrypt";
let selectedFile = null;

function showStatus(message, type) {
    statusBox.textContent = message;
    statusBox.className = "status visible " + type;
}

function clearStatus() {
    statusBox.textContent = "";
    statusBox.className = "status";
}

function updateMode(newMode) {
    mode = newMode;

    tabs.forEach((tab) => {
        tab.classList.toggle("active", tab.dataset.mode === mode);
    });

    submitButton.innerHTML =
        mode === "encrypt"
            ? 'Encrypt File <span>→</span>'
            : 'Decrypt File <span>→</span>';

    fileTitle.textContent =
        mode === "encrypt"
            ? "Choose a file to protect"
            : "Choose a file to decrypt";

    fileDescription.textContent =
        mode === "encrypt"
            ? "Click here to browse your files"
            : "Select a previously encrypted .encrypt file";

    passwordHint.textContent =
        mode === "encrypt"
            ? "Use at least 12 characters and remember your password."
            : "Enter the password used to encrypt this file.";

    passwordInput.autocomplete =
        mode === "encrypt" ? "new-password" : "current-password";

    const isDecrypt = mode === "decrypt";

    confirmLabel.hidden = isDecrypt;
    confirmPassword.hidden = isDecrypt;
    confirmPassword.required = !isDecrypt;
    clearStatus();
}

function displaySelectedFile(file) {
    if (!file) {
        return;
    }

    selectedFile = file;
    fileName.textContent = file.name;
    fileInfo.hidden = false;
    dropZone.hidden = true;

    clearStatus();
}

function resetSelectedFile() {
    selectedFile = null;
    fileInput.value = "";
    fileName.textContent = "";
    fileInfo.hidden = true;
    dropZone.hidden = false;

    clearStatus();
}

tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
        updateMode(tab.dataset.mode);
    });
});

fileInput.addEventListener("change", () => {
    displaySelectedFile(fileInput.files[0]);
});

removeFile.addEventListener("click", resetSelectedFile);

["dragenter", "dragover"].forEach((eventName) => {
    dropZone.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropZone.classList.add("dragging");
    });
});

["dragleave", "drop"].forEach((eventName) => {
    dropZone.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropZone.classList.remove("dragging");
    });
});

dropZone.addEventListener("drop", (event) => {
    const file = event.dataTransfer.files[0];

    if (!file) {
        return;
    }

    try {
        const transfer = new DataTransfer();
        transfer.items.add(file);
        fileInput.files = transfer.files;

        displaySelectedFile(file);
    } catch {
        showStatus(
            "Please use the file picker to select your file.",
            "error"
        );
    }
});

function getDownloadFilename(response) {
    const disposition =
        response.headers.get("Content-Disposition") || "";

    const encodedMatch =
        disposition.match(/filename\*=UTF-8''([^;]+)/i);

    if (encodedMatch) {
        try {
            return decodeURIComponent(encodedMatch[1]);
        } catch {
            // Use the ordinary filename if decoding fails.
        }
    }

    const ordinaryMatch =
        disposition.match(/filename="?([^";]+)"?/i);

    if (ordinaryMatch) {
        return ordinaryMatch[1];
    }

    return mode === "encrypt"
        ? selectedFile.name + ".enc"
        : "decrypted-" + selectedFile.name;
}

async function readError(response) {
    const message = await response.text();

    if (response.status === 400 && mode === "decrypt") {
        return "Decryption failed! Incorrect password or the encrypted file has been modified or corrupted.";
    }

    if (response.status === 400) {
        return message || "Encryption failed. Please check your file.";
    }

    if (response.status === 413) {
        return "The file is too large. Please choose a smaller file.";
    }

    if (response.status === 404) {
        return "API endpoint not found. Check your backend controller.";
    }

    if (response.status >= 500) {
        return "A server error occurred. Please try again.";
    }

    return message || "The operation failed. Please try again.";


}

fileForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearStatus();

    if (!selectedFile) {
        showStatus("Please select a file first.", "error");
        return;
    }

    const password = passwordInput.value;

    if (!password) {
        showStatus("Please enter your password.", "error");
        return;
    }

    if (mode === "encrypt") {
        if (password.length < 12) {
            showStatus(
                "Use a password with at least 12 characters.",
                "error"
            );
            return;
        }

        if (password !== confirmPassword.value) {
            showStatus("The passwords do not match.", "error");
            return;
        }
    }

    const formData = new FormData();
    formData.append("file", selectedFile);
    formData.append("password", password);

    const currentMode = mode;
    const endpoint =
        currentMode === "encrypt"
            ? "/api/files/encrypt"
            : "/api/files/decrypt";

    submitButton.disabled = true;
    submitButton.textContent =
        currentMode === "encrypt" ? "Encrypting..." : "Decrypting...";

    showStatus(
        "Processing your file. Please wait and keep this page open.",
        "info"
    );

    try {
        const response = await fetch(endpoint, {
            method: "POST",
            body: formData
        });

        if (!response.ok) {
            const errorMessage = await readError(response);
            showStatus(errorMessage, "error");
            return;
        }

        const blob = await response.blob();

        if (blob.size === 0) {
            throw new Error(
                "The server returned an empty file. Please try again."
            );
        }

        const downloadUrl = URL.createObjectURL(blob);
        const link = document.createElement("a");

        link.href = downloadUrl;
        link.download = getDownloadFilename(response);

        document.body.appendChild(link);
        link.click();
        link.remove();

        setTimeout(() => {
            URL.revokeObjectURL(downloadUrl);
        }, 1000);

        showStatus(
            currentMode === "encrypt"
                ? "Encryption successful! Your encrypted file has been downloaded."
                : "Decryption successful! Your original file has been downloaded.",
            "success"
        );

        passwordInput.value = "";
        confirmPassword.value = "";

    } catch (error) {
        showStatus(
            error.message ||
            "Unable to process the file. Please try again.",
            "error"
        );
    } finally {
        submitButton.disabled = false;

        submitButton.innerHTML =
            mode === "encrypt"
                ? 'Encrypt File <span>→</span>'
                : 'Decrypt File <span>→</span>';
    }
});

updateMode("encrypt");
