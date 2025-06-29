<script setup lang="ts">
    import { ref } from 'vue';
    import { Menu, InputText, Textarea, FileUpload, Button, type FileUploadUploadEvent, type FileUploadBeforeSendEvent, Message, ToggleSwitch } from 'primevue';
    import utils from '../utils';

    let props = defineProps(["username", "icon", "bio"]);
    let emits = defineEmits(["notify"]);
    const PROT_NAME = 'Solarixum Protocol';
    const PROT_VER = '0.1.0';
    let menu = ref("user");

    const settingsMenu = ref([
        {
            label: "User settings",
            command: () => {
                menu.value = "user";
            }
        },
        {
            label: "Your Keys",
            command: () => {
                menu.value = "keys";
                resetBegin.value = false;
                resetDone.value = false;
            }
        },
        {
            label: "Log out",
            command: () => {
                menu.value = "logout";
            }
        }
    ])
    let bio = ref(props.bio)
    let fileupload = ref();
    let resetBegin = ref(false);
    let sucMsg = ref("");
    let alertMsg = ref("");
    let alertShown = ref(false);
    let resetDone = ref(false);
    let logouteverywhere = ref(false);
    let forgetkey = ref(false);

    async function updateUser() {
        if (fileupload.value.hasFiles) {
            fileupload.value.upload();
        } else {
            await sendUserData();
        }
    }
    async function sendUserData(icon?: string) {
        const token = localStorage.getItem("token");
        if (!token) {
            localStorage.setItem("state", "1")
            window.location.href = "";
            return;
        }

        let req = await fetch("/api/user/update", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                bio: bio.value,
                icon: icon || props.icon,
                token: token,
                protocol: PROT_NAME,
                protocolVersion: PROT_VER
            })
        });
        let res = await req.json();
        if (!res.ok) {
            if (res.error === "Invalid token") {
                localStorage.setItem("state", "1")
                window.location.href = "";
                return
            }
            emits("notify", { severity: "error", summary: "Error", detail: res.error || "Failed to update user data.", life: 5000 });
            return;
        }
        emits("notify", { severity: "success", summary: "Success", detail: "User data updated successfully.", life: 3000 });
        window.location.href = ""
    }
    async function onUpload(e: FileUploadUploadEvent) {
        let resT = e.xhr.responseText
        let res = JSON.parse(resT);
        if (!res.ok) {
            emits("notify", { severity: "error", summary: "Error", detail: res.error || "Failed to upload profile picture.", life: 5000 });
            return;
        }
        sendUserData(res.body.fileId)
    }
    async function beforeSend(e: FileUploadBeforeSendEvent) {
        const token = localStorage.getItem("token");
        if (!token) {
            localStorage.setItem("state", "1")
            window.location.href = "";
            return;
        }
        e.xhr.setRequestHeader("Authorization", token);
    }

    async function resetAccount() {
        const passKey = localStorage.getItem("passwordKey");
        if (!passKey) {
            localStorage.setItem("state", "1");
            window.location.href = "";
            return;
        }
        const token = localStorage.getItem("token");
        if (!token) {
            localStorage.setItem("state", "1");
            window.location.href = "";
            return;
        }
        const recoveryWord = utils.generateRandomString(32);
        console.log("Recovery word:", recoveryWord);

        let key = await crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 4096,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: "SHA-256",
            },
            true,
            ["encrypt", "decrypt"]
        );
        
        let exportedPrivKey = await crypto.subtle.exportKey("pkcs8", key.privateKey);
        let iv = await utils.passwordToIV(passKey)
        let keyBuffer = await crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(recoveryWord),
            { name: "AES-CBC" },
            false,
            ["encrypt"]
        );
        let encryptedPrivKey = await crypto.subtle.encrypt(
            {
                name: "AES-CBC",
                iv: iv,
            },
            keyBuffer,
            exportedPrivKey
        );
        let privateKeyHex = utils.dataToBase64(encryptedPrivKey);
        let exportedPubKey = await crypto.subtle.exportKey("spki", key.publicKey);
        let publicKeyHex = utils.dataToBase64(exportedPubKey);

        let req = await fetch("/api/reset", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                token: token,
                privateKey: privateKeyHex,
                publicKey: publicKeyHex,
                protocol: PROT_NAME,
                protocolVersion: PROT_VER,
            }),
        });
        let res = await req.json();
        if (!res.ok) {
            alertMsg.value = res.error || "An unknown error occurred.";
            alertShown.value = true;
            return;
        }
        console.log(res);

        utils.encryptPrivateKey(key.privateKey)
        localStorage.setItem("token", res.body.token);
        localStorage.setItem("publicKey", publicKeyHex);
        localStorage.setItem("state", "5");
        
        sucMsg.value = "Reset successful! Recovery word: " + recoveryWord;
        alertMsg.value = "You can only view this once! Please save it securely.";
        resetDone.value = true;
        alertShown.value = true;
    }
    function reloadWp() {
        window.location.href = "";
    }
    async function downloadKey() {
        const privateKey = await utils.decryptPrivateKey()
        if (!privateKey) {
            emits("notify", { severity: "error", summary: "Error", detail: "Failed to decrypt private key.", life: 5000 });
            return;
        }
        const exported = await crypto.subtle.exportKey("pkcs8", privateKey);
        const blob = new Blob([utils.dataToBase64(exported)], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'solarixum_key.txt';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        emits("notify", { severity: "success", summary: "Success", detail: "Private key downloaded successfully.", life: 3000 });
    }
    async function logout() {
        if (logouteverywhere.value) {
            let req = await fetch("/api/logout", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    token: localStorage.getItem("token"),
                    protocol: PROT_NAME,
                    protocolVersion: PROT_VER,
                }),
            });
            let res = await req.json();
            if (!res.ok) {
                if (res.error === "Invalid token") {
                    localStorage.setItem("state", "1");
                    window.location.href = "";
                    return;
                }
                emits("notify", { severity: "error", summary: "Error", detail: res.error || "Failed to log out from all devices.", life: 5000 });
                return;
            }
        }
        if (forgetkey.value) {
            localStorage.removeItem("privateKey");
            localStorage.removeItem("publicKey");
        }
        localStorage.removeItem("token");
        localStorage.removeItem("state");
        localStorage.removeItem("passwordKey");
        window.location.href = "";
    }
</script>

<template>
    <div class="flex items-start">
        <Menu class="w-fit" :model="settingsMenu" />
        <div class="ml-5" v-if="menu == 'user'">
            <div class="flex items-center mb-5">
                <div class="self-center">
                    <img :src="props.icon" :alt="props.username" :title="props.username" draggable="false" class="pfp" />
                </div>
                <div class="self-center ml-5">
                    <h3 class="text-2xl mb-2">{{ props.username }}</h3>
                </div>
            </div>
            <p class="mb-2 block">Upload a profile picture: </p>
            <FileUpload ref="fileupload" mode="basic" name="profilepicture" url="/api/upload" accept="image/*" class="mb-2" @upload="onUpload" @before-send="beforeSend" />
            <InputText class="w-full" :value="props.username" disabled />
            <Textarea class="w-full mt-2" placeholder="Tell us something about yourself..." v-model="bio" />
            <Button class="float-end" @click="updateUser()">Update</Button>
        </div>
        <div class="ml-5" v-if="menu == 'keys'">
            <h3 class="text-2xl mb-2">Your Keys</h3>
            <p class="mb-2">You can download your keys here. Make sure to keep them safe, as they are required to decrypt your messages.</p>
            <Message severity="error" v-if="resetBegin">
                <span class="text-2xl">Warning!</span>
                <p>Restetting your keys will remove you from every room and universe you were in!<br>You will need an invite to join back!<br>It won't delete your messages though!<br>It can't be reverted!<br><br>Press the button again to confirm!</p>
            </Message>
            <Message severity="error" v-if="alertShown">{{ alertMsg }}</Message>
            <Message severity="success" v-if="resetDone">
                {{ sucMsg }}<br>
                <Button @click="reloadWp">Continue</Button>
            </Message>
            <div class="flex items-center mt-2" v-if="!resetBegin">
                <Button severity="danger" @click="resetBegin = true">Reset Keys</Button>
                <Button class="ml-auto" @click="downloadKey()">Download Keys</Button>
            </div>
            <div class="flex items-center mt-2" v-if="resetBegin">
                <Button class="ml-auto" severity="danger" @click="resetAccount()">Reset Keys</Button>
            </div>
        </div>
        <div class="ml-5" v-if="menu == 'logout'">
            <h3 class="text-2xl mb-2">Log out</h3>
            <Message severity="warn" class="mb-2" v-if="forgetkey">
                <span class="text-2xl">Warning!</span>
                <p>Next time you log in, you will need to recover your account with your private key!<br>If you don't have it, you won't be able to log in again!</p>
            </Message>
            <div class="flex items-center mb-2">
                <span>Log out from every device</span>
                <ToggleSwitch class="ml-2" v-model="logouteverywhere" />
            </div>
            <div class="flex items-center">
                <span>Forget the key</span>
                <ToggleSwitch class="ml-2" v-model="forgetkey" />
            </div>
            <Button class="mt-2 float-end" severity="danger" @click="logout()">Log out</Button>
        </div>
    </div>
</template>

<style scoped>
.pfp {
    width: 100px;
    height: 100px;
    border-radius: 50%;
    user-select: none;
}
</style>