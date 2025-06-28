<script setup lang="ts">
    let props = defineProps(["label", "icon", "bio"]);
</script>

<template>
    <div class="flex items-center">
        <div class="self-center">
            <img :src="props.icon" :alt="props.label" :title="props.label" draggable="false" />
        </div>
        <div class="self-center ml-5">
            <h3 class="text-2xl mb-2">{{ props.label }}</h3>
            <p>{{ props.bio }}</p>
        </div>
    </div>
</template>

<style scoped>
img {
    width: 100px;
    height: 100px;
    border-radius: 50%;
    user-select: none;
}
</style>