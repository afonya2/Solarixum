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
    border: 1px solid rgb(50, 50, 50);
    display: flex;
    align-items: center;
}
.frame[selected="true"] {
    background-color: rgb(50, 50, 50);
}
.frame:hover {
    background-color: rgb(50, 50, 50);
}
img {
    width: 40px;
    height: 40px;
}
p {
    margin-left: 10px;
    font-size: 108%;
}
</style>