<script setup lang="ts">
    import ChatMessage from './components/ChatMessage.vue';
import RoomButton from './components/RoomButton.vue';
    import SolarButton from './components/SolarButton.vue';
    import { Divider } from 'primevue';
</script>

<template>
    <div class="bg">
        <div class="solar-select">
            <SolarButton label="Home" icon="../logo.svg" active="true" />
            <Divider />
            <SolarButton label="Home" icon="../logo.svg" active="false" />
            <SolarButton label="Home" icon="../logo.svg" active="false" />
        </div>
        <div class="content">
            <div class="content-head">
                <h2 class="text-2xl">Example text</h2>
            </div>
            <div class="room-select">
                <RoomButton label="Test" icon="../logo.svg" active="true" />
                <RoomButton label="Test2" icon="../logo.svg" active="false" />
            </div>
            <div class="content-body">
                <ChatMessage username="tester" message="Test message" icon="../logo.svg" timestamp="1750419409000" />
                <ChatMessage username="tester" message="Test message2" icon="../logo.svg" timestamp="1750419409000" />
            </div>
        </div>
    </div>
</template>

<style scoped>
.bg {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: var(--color-slate-900);
    z-index: 1;
}
.content {
    position: fixed;
    top: 10px;
    left: 90px;
    width: calc(100% - 100px);
    height: calc(100% - 20px);
    flex-direction: column;
    background-color: var(--color-slate-950);
    border-radius: 20px;
    z-index: 3;
}
.content-head {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 74px;
    border-top-left-radius: 20px;
    border-top-right-radius: 20px;
    border-bottom: 3px solid var(--color-slate-900);
    padding: 20px;
    display: flex;
    align-items: center;
}
.room-select {
    position: absolute;
    top: 74px;
    left: 0;
    width: 350px;
    height: calc(100% - 74px);
    border-right: 3px solid var(--color-slate-900);
    padding: 20px;
    border-bottom-left-radius: 20px;
}
.content-body {
    position: absolute;
    top: 74px;
    left: 350px;
    width: calc(100% - 350px);
    height: calc(100% - 74px);
    border-bottom-right-radius: 20px;
    padding: 20px;
}
.solar-select {
    position: fixed;
    top: 0;
    left: 0;
    width: 75px;
    height: 100%;
    z-index: 2;
    margin-left: 5px;
    padding-block: 10px;
}
</style>