<script setup lang="ts">
    let props = defineProps(["label", "icon", "active"]);
</script>

<template>
    <div class="frame" :selected="props.active">
        <img :src="props.icon" :alt="props.label" :title="props.label" class="icon" draggable="false" />
        <p>{{ props.label }}</p>
    </div>
</template>

<style scoped>
.frame {
    width: 100%;
    height: fit-content;
    padding: 5px;
    margin-bottom: 10px;
    border-radius: 5px;
    cursor: pointer;
    display: flex;
    align-items: center;
    box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
}
.frame[selected="true"] {
    background-color: rgba(50, 50, 50, .5);
}
.frame:hover {
    background-color: rgba(50, 50, 50, .5);
}
img {
    width: 40px;
    height: 40px;
    border-radius: 50%;
}
p {
    margin-left: 10px;
    font-size: 108%;
}
</style>