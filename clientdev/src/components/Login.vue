<script setup lang="ts">
    import { InputText, Button } from 'primevue';
</script>

<template>
    <div class="bg">
        <main class="w-full h-full md:w-50px">
            <div class="flex flex-col gap-2">
                <label for="username">Username</label>
                <InputText type="text" placeholder="Username" id="username" style="margin-block: 5px;" />
                <label for="password">Password</label>
                <InputText type="password" placeholder="Password" id="password" style="margin-block: 5px;" />
                <a href="javascript:alert('skill issue')">Forgot your password?</a>
                <Button style="float: right;margin-top: 5px;">Log in</Button>
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
    background-color: rgba(255, 255, 255, 0.5);
    border-radius: 10px;
    backdrop-filter: blur(10px) saturate(150%);
    padding-inline: auto;
    padding: 25px;
    color: black;
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