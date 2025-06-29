<script setup lang="ts">
    import { Textarea, Button, Message } from 'primevue';
    import { ref } from 'vue';
    import utils from '../utils';

    const props = defineProps(["hidden"]);
    let pKey = ref("")
    let alertMsg = ref("");
    let alerthidden = ref(true);
    const PROT_NAME = 'Solarixum Protocol';
    const PROT_VER = '0.1.0';

    async function recover() {
        const token = localStorage.getItem("token");
        if (!token) {
            console.error("No token found in local storage.");
            return;
        }
        let req = await fetch("/api/recover", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ token, protocol: PROT_NAME, protocolVersion: PROT_VER }),
        });
        let res = await req.json();
        if (!res.ok) {
            alertMsg.value = res.error || "An unknown error occurred.";
            alerthidden.value = false;
            return;
        }
        console.log(res);

        let publicKey = utils.base64ToData(res.body.publicKey);
        let privateKey;
        try {
            privateKey = await crypto.subtle.importKey("pkcs8", utils.base64ToData(pKey.value), {
                name: "RSA-OAEP",
                hash: "SHA-256",
            }, true, ["decrypt"]);
        } catch (e) {
            console.error(e);
            alertMsg.value = "Invalid private key.";
            alerthidden.value = false;
            return
        }

        try {
            let decryptedKeyVerifier = await crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP",
                },
                privateKey,
                utils.base64ToArray(res.body.encryptedKeyVerifier)
            );
            if (new TextDecoder().decode(decryptedKeyVerifier) == res.body.keyVerifier) {
                localStorage.setItem("state", "5")
                window.location.href = ""
            } else {
                alertMsg.value = "Key verifier mismatch.";
                alerthidden.value = false;
                return
            }
        } catch (e) {
            console.error(e);
            alertMsg.value = "Key verifier mismatch.";
            alerthidden.value = false;
            return
        }

        utils.encryptPrivateKey(privateKey)
        localStorage.setItem("publicKey", utils.dataToBase64(publicKey));
        localStorage.setItem("state", "5");
        window.location.href = "";
    }
</script>

<template>
    <div class="flex flex-col gap-2" :hidden="props.hidden">
        <p>Enter private key to continue:</p>
        <Message severity="error" :hidden="alerthidden">{{ alertMsg }}</Message>
        <label for="privateKey">Private key</label>
        <Textarea v-model="pKey" name="privateKey" />
        <Button style="float: right;margin-top: 5px;" @click="recover()" severity="danger">Recover account</Button>
    </div>
</template>

<style scoped>

</style>