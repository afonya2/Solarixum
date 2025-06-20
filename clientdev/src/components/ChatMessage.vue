<script setup lang="ts">
    let props = defineProps(["username", "icon", "message", "timestamp"]);
</script>

<template>
    <div class="frame">
        <img :src="props.icon" :alt="props.username" :title="props.username" class="icon" draggable="false" />
        <div class="message-content">
            <div class="username-part">
                <p class="username">{{ props.username }}</p>
                <p class="timestamp">{{ new Date(Number(props.timestamp)).toLocaleString() }}</p>
            </div>
            <p class="message">{{ props.message }}</p>
        </div>
    </div>
</template>

<style scoped>
.frame {
    width: 100%;
    height: fit-content;
    padding: 10px;
    margin-bottom: 10px;
    border-radius: 5px;
    display: flex;
    align-items: center;
}
.frame:hover {
    background-color: var(--color-slate-800);
}
.icon {
    width: 40px;
    height: 40px;
    border-radius: 50%;
}
.message-content {
    margin-left: 10px;
    display: flex;
    flex-direction: column;
}
.username-part {
    display: flex;
    align-items: center;
}
.username {
    font-weight: bold;
    margin: 0;
}
.username:hover {
    text-decoration: underline;
    cursor: pointer;
}
.message {
    margin: 0;
    color: var(--color-slate-300);
}
.timestamp {
    margin: 0;
    font-size: 0.8em;
    color: var(--color-slate-500);
    margin-left: 10px;
}
</style>