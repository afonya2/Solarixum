<script setup lang="ts">
    import { Button } from 'primevue';
    let props = defineProps(["username", "icon", "message", "timestamp"]);
    let emits = defineEmits(["editMessage", "deleteMessage"]);

    async function editMessage() {
        emits("editMessage");
    }
    async function deleteMessage() {
        emits("deleteMessage")
    }
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
        <div class="msg-options">
            <Button class="btn" @click="editMessage()">
                <span class="material-symbols-rounded text-slate-300">
                    edit
                </span>
            </Button>
            <Button class="btn" @click="deleteMessage()">
                <span class="material-symbols-rounded text-red-900">
                    delete
                </span>
            </Button>
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
    position: relative;
}
.frame:hover {
    background-color: var(--color-slate-800);
}
.icon {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    user-select: none;
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
.msg-options {
    position: absolute;
    right: 10px;
    top: 0px;
    background-color: var(--color-slate-900);
    width: fit-content;
    height: fit-content;
    display: none;
    box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
    border-radius: 5px;
    transform: translateY(-50%);
    padding: 5px;
}
.frame:hover .msg-options {
    display: block;
}
.btn {
    background-color: transparent;
    border: none;
    padding: 5px;
}
.btn:hover {
    background-color: rgba(255, 255, 255, .1) !important;
    border: none !important;
    border-radius: 5px;
}
</style>