<script setup lang="ts">
    import { InputText, Button, Message } from 'primevue';
    import { ref } from 'vue';
    import utils from '../utils';
    let alertMsg = ref("")
    let alerthidden = ref(true)
    let sucMsg = ref("")
    let sucHidden = ref(true)
    let username = ref("")
    let password = ref("");

    const PROT_NAME = 'Solarixum Protocol';
    const PROT_VER = '0.1.0';

    async function register() {
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

        let passKey = await utils.derivePasswordKey(password.value)
        let exportedPassKey = await crypto.subtle.exportKey("raw", passKey);
        localStorage.setItem("passwordKey", utils.dataToBase64(exportedPassKey));
        
        let exportedPrivKey = await crypto.subtle.exportKey("pkcs8", key.privateKey);
        let iv = await utils.passwordToIV(utils.dataToBase64(exportedPassKey));
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

        let req = await fetch("/api/register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                username: username.value,
                password: password.value,
                privateKey: privateKeyHex,
                publicKey: publicKeyHex,
                protocol: PROT_NAME,
                protocolVersion: PROT_VER,
            }),
        });
        let res = await req.json();
        if (!res.ok) {
            alertMsg.value = res.error || "An unknown error occurred.";
            alerthidden.value = false;
            return;
        }
        console.log(res);

        utils.encryptPrivateKey(key.privateKey)
        localStorage.setItem("token", res.body.token);
        localStorage.setItem("publicKey", publicKeyHex);
        localStorage.setItem("state", "5");
        
        sucMsg.value = "Registration successful! Recovery word: " + recoveryWord;
        alertMsg.value = "You can only view this once! Please save it securely.";
        sucHidden.value = false;
        alerthidden.value = false;
    }
    function toLogin() {
        localStorage.setItem("state", "1");
        window.location.href = "";
    }
    function reloadWp() {
        window.location.href = "";
    }
</script>

<template>
    <div class="bg">
        <main class="w-full h-full md:w-50px">
            <div class="flex flex-col gap-2">
                <h1 class="text-4xl">Solarixum Register</h1>
                <Message severity="error" :hidden="alerthidden">{{ alertMsg }}</Message>
                <Message severity="success" :hidden="sucHidden">
                    {{ sucMsg }}<br>
                    <Button @click="reloadWp">Continue</Button>
                </Message>
                <label for="username">Username</label>
                <InputText type="text" name="username" placeholder="Username" style="margin-block: 5px;" v-model="username" />
                <label for="password">Password</label>
                <InputText type="password" name="password" placeholder="Password" style="margin-block: 5px;" v-model="password" />
                <p>You accept the Terms of service and the Privacy policy by pressing the button below.</p>
                <Button style="float: right;margin-top: 5px;" @click="register()">Register</Button>
                <p>Already have an account? <a href="#" @click="toLogin()">Log in</a></p>
            </div>
        </main>
    </div>
</template>

<style scoped>
.bg {
    background-image: url('../assets/loginbackground.jpg');
    background-size: cover;
    background-position: center;
    height: 100vh;
    width: 100%;
}
main {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background-color: rgba(0, 0, 0, 0.5);
    border-radius: 10px;
    backdrop-filter: blur(10px) saturate(150%);
    padding-inline: auto;
    padding: 25px;
}
input {
    background-color: rgba(0,0,0,.75);
}
@media (width >= 48rem) {
    main {
        min-width: fit-content;
        width: 25%;
        height: fit-content;
    }
}
a {
    color: rgb(50, 100, 200);
    text-decoration: underline;
}
</style>