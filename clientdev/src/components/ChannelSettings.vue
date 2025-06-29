<script setup lang="ts">
    import { ref } from 'vue';
    import { InputText, FileUpload, Button, type FileUploadUploadEvent, type FileUploadBeforeSendEvent } from 'primevue';

    let props = defineProps(["name", "icon", "id"]);
    let emits = defineEmits(["notify", "close"]);
    const PROT_NAME = 'Solarixum Protocol';
    const PROT_VER = '0.1.0';
    let menu = ref("user");

    let fileupload = ref();
    let roomName = ref(props.name);

    async function updateRoom() {
        if (fileupload.value.hasFiles) {
            fileupload.value.upload();
        } else {
            await sendRoomData();
        }
    }
    async function sendRoomData(icon?: string) {
        const token = localStorage.getItem("token");
        if (!token) {
            localStorage.setItem("state", "1")
            window.location.href = "";
            return;
        }

        let req = await fetch("/api/room/update", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                roomId: props.id,
                roomName: roomName.value,
                icon: icon,
                token: token,
                protocol: PROT_NAME,
                protocolVersion: PROT_VER
            })
        });
        let res = await req.json();
        if (!res.ok) {
            if (res.error === "Invalid token") {
                localStorage.setItem("state", "1")
                window.location.href = "";
                return
            }
            emits("notify", { severity: "error", summary: "Error", detail: res.error || "Failed to update room data.", life: 5000 });
            return;
        }
        emits("notify", { severity: "success", summary: "Success", detail: "Room data updated successfully.", life: 3000 });
        emits("close");
    }
    async function onUpload(e: FileUploadUploadEvent) {
        let resT = e.xhr.responseText
        let res = JSON.parse(resT);
        if (!res.ok) {
            emits("notify", { severity: "error", summary: "Error", detail: res.error || "Failed to upload icon picture.", life: 5000 });
            return;
        }
        sendRoomData(res.body.fileId)
    }
    async function beforeSend(e: FileUploadBeforeSendEvent) {
        const token = localStorage.getItem("token");
        if (!token) {
            localStorage.setItem("state", "1")
            window.location.href = "";
            return;
        }
        e.xhr.setRequestHeader("Authorization", token);
    }
</script>

<template>
    <div class="ml-5" v-if="menu == 'user'">
        <div class="flex items-center mb-5">
            <div class="self-center">
                <img :src="props.icon" :alt="props.name" :title="props.name" draggable="false" class="pfp" />
            </div>
            <div class="self-center ml-5">
                <h3 class="text-2xl mb-2">{{ props.name }}</h3>
            </div>
        </div>
        <p class="mb-2 block">Upload a picture: </p>
        <FileUpload ref="fileupload" mode="basic" name="channelicon" url="/api/upload" accept="image/*" class="mb-2" @upload="onUpload" @before-send="beforeSend" />
        <InputText class="w-full" v-model="roomName" />
        <div class="flex items-center">
            <Button class="float-end mt-2 block ml-auto" @click="" severity="danger">Delete</Button>
            <Button class="float-end mt-2 block ml-2" @click="updateRoom()">Update</Button>
        </div>
    </div>
</template>

<style scoped>
.pfp {
    width: 100px;
    height: 100px;
    border-radius: 50%;
    user-select: none;
}
</style>