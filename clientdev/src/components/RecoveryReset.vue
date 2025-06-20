<script setup lang="ts">
    import { Button, Message } from 'primevue';
    import { ref } from 'vue';
    import utils from '../utils';

    const props = defineProps(["hidden"]);
    const PROT_NAME = 'Solarixum Protocol';
    const PROT_VER = '0.1.0';
    let alertMsg = ref("");
    let alerthidden = ref(true);
    let sucMsg = ref("");
    let sucHidden = ref(true);

    async function reset() {
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
            alerthidden.value = false;
            return;
        }
        console.log(res);

        utils.encryptPrivateKey(key.privateKey)
        localStorage.setItem("token", res.body.token);
        localStorage.setItem("publicKey", publicKeyHex);
        localStorage.setItem("state", "5");
        
        sucMsg.value = "Reset successful! Recovery word: " + recoveryWord;
        alertMsg.value = "You can only view this once! Please save it securely.";
        sucHidden.value = false;
        alerthidden.value = false;
    }
    function reloadWp() {
        window.location.href = "";
    }
</script>

<template>
    <div class="flex flex-col gap-2 mt-2" :hidden="props.hidden">
        <Message severity="error">
            <span class="text-2xl">Warning!</span>
            <p>This action will remove you from every room and universe you were in!<br>You will need an invite to join back!<br>It won't delete your messages though!<br>It can't be reverted!</p>
        </Message>
        <Message severity="error" :hidden="alerthidden">{{ alertMsg }}</Message>
        <Message severity="success" :hidden="sucHidden">
            {{ sucMsg }}<br>
            <Button @click="reloadWp">Continue</Button>
        </Message>
        <Button style="float: right;margin-top: 5px;" @click="reset()" severity="danger">Reset account</Button>
    </div>
</template>

<style scoped>

</style>