<script setup lang="ts">
    import { ref, type Ref } from 'vue';
    import { Button } from 'primevue';

    function generateRandomColor(): string {
        const letters = '6789ABCDEF';
        let color = '#';
        for (let i = 0; i < 6; i++) {
            color += letters[Math.floor(Math.random() * letters.length)];
        }
        color += 'FF';
        return color;
    }
    function isInRange(x: number, y: number, tx: number, ty: number, range: number): boolean {
        return Math.abs(x - tx) <= range && Math.abs(y - ty) <= range;
    }

    const dots: Ref<{x: number, y: number, tx: number, ty: number, color: string}[]> = ref([])
    const dotCount = (window.innerWidth+window.innerHeight)/40;
    console.log(dotCount);
    
    function genDots() {
        for (let i = 0; i < dotCount; i++) {
            dots.value.push({
                x: Math.random() * (window.innerWidth - 200),
                y: Math.random() * (window.innerHeight - 200),
                tx: Math.random() * (window.innerWidth - 200),
                ty: Math.random() * (window.innerHeight - 200),
                color: generateRandomColor()
            });
        }
    }
    function moveDots() {
        for (let i = 0; i < dots.value.length; i++) {
            const dot = dots.value[i];
            if (dot.x < dot.tx) {
                dot.x += 1;
            } else if (dot.x > dot.tx) {
                dot.x -= 1;
            }
            if (dot.y < dot.ty) {
                dot.y += 1;
            } else if (dot.y > dot.ty) {
                dot.y -= 1;
            }
            if (isInRange(dot.x, dot.y, dot.tx, dot.ty, 5)) {
                dot.tx = Math.random() * (window.innerWidth - 200)
                dot.ty = Math.random() * (window.innerHeight - 200)
            }
        }
    }
    window.onmousemove = (e: MouseEvent) => {
        let glower = document.getElementById("glower");
        if (!glower) return;
        glower.style.top = `${e.clientY}px`;
        glower.style.left = `${e.clientX}px`;
    }
    setInterval(() => {
        moveDots()
    }, 10);
    genDots()

    function toLogin() {
        window.location.href = "/client/";
    }
    function toSource() {
        window.open("https://github.com/afonya2/Solarixum", "_blank")
    }
</script>

<template>
    <div class="bg">
        <div v-for="dot in dots" class="dot" :style="`top: ${dot.y}px;left: ${dot.x}px;background: radial-gradient(${dot.color}, #00000000)`"></div>
        <div class="bg-front">
            <div class="glower" id="glower"></div>
            <div class="card">
                <div class="flex items-center ml-auto mr-auto w-fit h-fit mb-5">
                    <img src="/logo.svg" alt="Solarixum Logo">
                    <h1 class="text-4xl">Solarixum</h1>
                </div>
                <p class="text-center text-xl mb-2">An end-2-end encrypted chat platform.</p>
                <div class="flex items-center ml-auto mr-auto w-fit h-fit">
                    <Button class="!text-xl" @click="toLogin()">Try it!</Button>
                    <Button class="ml-5 !text-xl" severity="secondary" @click="toSource()">
                        <span class="material-symbols-rounded">
                            commit
                        </span>
                        Check the source code
                    </Button>
                </div>
                <div class="flex gap-5 items-center w-fit h-fit ml-auto mr-auto mt-10 flex-wrap">
                    <div class="card-in w-full md:w-fit mx-auto md:mx-0">
                        <h2 class="text-2xl text-center">Features</h2>
                        <ul class="list-disc ml-5">
                            <li>End-to-end encryption</li>
                            <li>Rooms</li>
                            <li>Universes</li>
                            <li>(And more!)</li>
                        </ul>
                    </div>
                    <div class="card-in w-full md:w-fit mx-auto md:mx-0">
                        <h2 class="text-2xl text-center">Technologies</h2>
                        <ul class="list-disc ml-5">
                            <li>Vue.js</li>
                            <li>Node.js</li>
                            <li>WebSockets</li>
                            <li>And more!</li>
                        </ul>
                    </div>
                    <div class="card-in w-full md:w-fit mx-auto md:mx-0">
                        <h2 class="text-2xl text-center">About</h2>
                        <p>Solarixum is a chat platform that focuses on security and privacy. It is built with modern web technologies and is open source.<br>Made by: Afonya</p>
                    </div>
                </div>
                <div class="flex gap-5 items-center w-fit h-fit ml-auto mr-auto mt-10">
                    <a href="/client/terms" target="_blank">Terms of Service & Privacy Policy</a>
                    <span>|</span>
                    <a href="https://github.com/afonya2/Solarixum/issues" target="_blank">Found an issue?</a>
                </div>
            </div>
        </div>
    </div>
</template>

<style scoped>
.bg {
    width: 100vw;
    height: 100vh;
    overflow: hidden;
    background-color: #0a1428;
}
.bg-front {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    backdrop-filter: blur(40px);
}
.dot {
    position: absolute;
    width: 100px;
    height: 100px;
    border-radius: 50%;
}
.card {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 100%;
    min-width: fit-content;
    height: fit-content;
    background-color: rgba(255, 255, 255, 0.1);
    border-radius: 20px;
    border: 1px solid rgba(255, 255, 255, 0.2);
    padding: 20px;
    overflow: auto;
    backdrop-filter: saturate(150%) blur(10px);
}
.card-in {
    padding: 10px;
    background-color: rgba(255, 255, 255, 0.1);
    border-radius: 10px;
    border: 1px solid rgba(255, 255, 255, 0.2);
    backdrop-filter: saturate(150%) blur(10px);
    max-width: 400px;
}
img {
    width: 100px;
    height: 100px;
    border-radius: 50%;
    margin-right: 20px;
}
a {
    color: #7093d9;
    text-decoration: underline;
}
@media (width >= 48rem) {
    .card {
        width: 30%;
        height: fit-content;
    }
}
</style>