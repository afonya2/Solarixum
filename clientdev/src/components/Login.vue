<script setup lang="ts">
    import { InputText, Button, Message } from 'primevue';
    import { ref } from 'vue';
    import utils from '../utils';
    let alertMsg = ref("")
    let alerthidden = ref(true)
    let username = ref("")
    let password = ref("");

    const PROT_NAME = 'Solarixum Protocol';
    const PROT_VER = '0.1.0';

    async function login() {
        let req = await fetch("/api/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ username: username.value, password: password.value, protocol: PROT_NAME, protocolVersion: PROT_VER }),
        });
        let res = await req.json();
        if (!res.ok) {
            alertMsg.value = res.error || "An unknown error occurred.";
            alerthidden.value = false;
            return;
        }
        console.log(res);
        localStorage.setItem("password", password.value);

        let key;
        try {
            key = await utils.decryptPrivateKey();
            if (!key) {
                alertMsg.value = "Failed to decrypt private key. Recovery needed!";
                alerthidden.value = false;
                localStorage.setItem("state", "3")
                window.location.href = ""
                return
            }
        } catch (e) {
            console.error(e);
            alertMsg.value = "Failed to decrypt private key. Recovery needed!";
            alerthidden.value = false;
            localStorage.setItem("state", "3")
            window.location.href = ""
            return;
        }

        try {
            let decryptedKeyVerifier = await crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP",
                },
                key,
                utils.base64ToArray(res.body.encryptedKeyVerifier)
            );
            if (new TextDecoder().decode(decryptedKeyVerifier) == res.body.keyVerifier) {
                localStorage.setItem("state", "5")
                window.location.href = ""
            } else {
                alertMsg.value = "Key verifier mismatch. Recovery needed!";
                localStorage.setItem("state", "3")
                window.location.href = ""
                alerthidden.value = false;
            }
        } catch (e) {
            console.error(e);
            alertMsg.value = "Key verifier mismatch. Recovery needed!";
            localStorage.setItem("state", "3")
            window.location.href = ""
            alerthidden.value = false;
        }
        localStorage.setItem("token", res.body.token);
    }
    function toRegister() {
        localStorage.setItem("state", "2");
        window.location.href = "";
    }
</script>

<template>
    <div class="bg">
        <main class="w-full h-full md:w-50px">
            <div class="flex flex-col gap-2">
                <h1 class="text-4xl">Log in</h1>
                <Message severity="error" :hidden="alerthidden">{{ alertMsg }}</Message>
                <label for="username">Username</label>
                <InputText type="text" name="username" placeholder="Username" style="margin-block: 5px;" v-model="username" />
                <label for="password">Password</label>
                <InputText type="password" name="password" placeholder="Password" style="margin-block: 5px;" v-model="password" />
                <a href="javascript:alert('skill issue')">Forgot your password?</a>
                <Button style="float: right;margin-top: 5px;" @click="login()">Log in</Button>
                <p>Don't have an account? <a href="#" @click="toRegister()">Register</a></p>
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