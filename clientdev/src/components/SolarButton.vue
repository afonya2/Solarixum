<script setup lang="ts">
    let props = defineProps(["label", "icon", "active"]);
</script>

<template>
    <div class="frame" :selected="props.active">
        <img :src="props.icon" :alt="props.label" :title="props.label" class="icon" draggable="false" />
    </div>
</template>

<style scoped>
.frame {
    margin-top: 5px;
    margin-inline: auto;
    width: fit-content;
    border-radius: 10px;
    border: 1px solid rgb(50, 50, 50);
    padding: 2px;
    cursor: pointer;
}
.frame:hover {
    background-color: rgba(255, 255, 255, 0.1);
}
.frame[selected="true"] {
    background-color: rgba(255, 255, 255, 0.2);
    border-color: rgb(100, 100, 100);
}
.icon {
    width: 50px;
    height: 50px;
    border-radius: 50%;
}
</style>