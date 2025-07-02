<script setup lang="ts">
    import { Card, Badge } from 'primevue';
    import { ref } from 'vue';
    import RecoveryWord from './RecoveryWord.vue';
    import RecoveryKey from './RecoveryKey.vue';
    import RecoveryReset from './RecoveryReset.vue';
    
    let mainhidden = ref(false);
    let wordhidden = ref(true);
    let keyhidden = ref(true);
    let resethidden = ref(true);

    function useRecoveryWord() {
        wordhidden.value = false;
        mainhidden.value = true;
    }
    function usePrivateKey() {
        keyhidden.value = false;
        mainhidden.value = true;
    }
    function resetAccount() {
        resethidden.value = false;
        mainhidden.value = true;
    }
    async function logout() {
        localStorage.removeItem("token");
        localStorage.removeItem("state");
        localStorage.removeItem("passwordKey");
        window.location.href = "";
    }
</script>

<template>
    <div class="bg">
        <main class="w-full h-full md:w-50px">
            <h1 class="text-4xl">Solarixum Account recovery</h1>
            <p>Don't want to? <a href="#" @click="logout()">Log out</a></p>
            <div class="flex flex-col gap-2" :hidden="mainhidden">
                <p>Please select one of the recovery methods:</p>
                <Card @click="useRecoveryWord()">
                    <template #content>Use recovery word</template>
                </Card>
                <Card @click="usePrivateKey()">
                    <template #content>Use private key</template>
                </Card>
                <Card @click="resetAccount()">
                    <template #content>Reset account <Badge severity="danger">Your messages will be lost!</Badge></template>
                </Card>
            </div>
            <RecoveryWord :hidden="wordhidden" />
            <RecoveryKey :hidden="keyhidden" />
            <RecoveryReset :hidden="resethidden" />
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
.p-card {
    background-color: rgba(0, 0, 0, 0.75);
    cursor: pointer;
    user-select: none;
}
.p-card:hover {
    background-color: rgba(0, 0, 0, 0.5);
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