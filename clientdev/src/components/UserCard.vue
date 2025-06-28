<script setup lang="ts">
    import { Tag } from 'primevue'
    let props = defineProps(["label", "icon", "rank"]);
    let severity = "secondary"
    if (props.rank === "owner") {
        severity = "danger";
    } else if (props.rank === "admin") {
        severity = "warn";
    } else if (props.rank === "moderator") {
        severity = "info";
    } else if (props.rank === "member") {
        severity = "success";
    }
</script>

<template>
    <div class="frame">
        <img :src="props.icon" :alt="props.label" :title="props.label" class="icon" draggable="false" />
        <p>{{ props.label }}</p>
        <Tag :severity="severity" :value="props.rank == null ? 'unknown' : props.rank" class="tag" />
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
    user-select: none;
    background-color: var(--color-slate-900);
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
.tag {
    margin-left: 10px;
    align-self: center;
}
</style>