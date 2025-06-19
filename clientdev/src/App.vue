<script setup lang="ts">
    import ChannelButton from './components/RoomButton.vue';
import SolarButton from './components/SolarButton.vue';
    import { Divider } from 'primevue';
</script>

<template>
    <div class="top-bar">

    </div>
    <div class="solar-bar">
        <h2 class="text-2xl">Home</h2>
    </div>
    <div class="solar-select">
        <SolarButton label="Home" icon="../logo.svg" active="true" />
        <Divider />
        <SolarButton label="Home" icon="../logo.svg" active="false" />
        <SolarButton label="Home" icon="../logo.svg" active="false" />
    </div>
    <div class="rooms-select">
        <ChannelButton label="test" icon="../logo.svg" active="true" />
        <ChannelButton label="test2" icon="../logo.svg" active="false" />
    </div>
    <main>

    </main>
</template>

<style scoped>
.top-bar {
    position: fixed;
    top: 0;
    left: 475px;
    width: 100%;
    height: 84px;
    border: 1px solid rgb(50, 50, 50);
}
.solar-select {
    position: fixed;
    top: 0;
    left: 0;
    width: 75px;
    height: 100%;
    border: 1px solid rgb(50, 50, 50);
    padding: 5px;
}
.solar-bar {
    position: fixed;
    top: 0;
    left: 75px;
    width: 400px;
    height: 84px;
    border: 1px solid rgb(50, 50, 50);
    padding: 10px;
    display: flex;
    align-items: center;
}
.rooms-select {
    position: fixed;
    top: 84px;
    left: 75px;
    width: 400px;
    height: calc(100% - 50px);
    border: 1px solid rgb(50, 50, 50);
    padding: 10px;
    padding-top: 18px;
}
main {
    position: fixed;
    top: 84px;
    left: 475px;
    width: calc(100% - 475px);
    height: calc(100% - 50px);
    border: 1px solid rgb(50, 50, 50);
}
</style>