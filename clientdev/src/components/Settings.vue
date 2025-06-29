<script setup lang="ts">
    import { ref } from 'vue';
    import { Menu, InputText, Textarea, FileUpload, Button, type FileUploadUploadEvent, type FileUploadBeforeSendEvent } from 'primevue';

    let props = defineProps(["username", "icon", "bio"]);
    let emits = defineEmits(["downloadKey", "resetKey", "logout", "notify"]);
    const PROT_NAME = 'Solarixum Protocol';
    const PROT_VER = '0.1.0';

    const settingsMenu = ref([
        {
            label: "User settings"
        },
        {
            label: "Your Keys"
        },
        {
            label: "Log out"
        }
    ])
    let bio = ref(props.bio)
    let fileupload = ref();

    async function updateUser() {
        if (fileupload.value.hasFiles) {
            fileupload.value.upload();
        } else {
            await sendUserData();
        }
    }
    async function sendUserData(icon?: string) {
        const token = localStorage.getItem("token");
        if (!token) {
            localStorage.setItem("state", "1")
            window.location.href = "";
            return;
        }

        let req = await fetch("/api/user/update", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                bio: bio.value,
                icon: icon || props.icon,
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
            emits("notify", { severity: "error", summary: "Error", detail: res.error || "Failed to update user data.", life: 5000 });
            return;
        }
        emits("notify", { severity: "success", summary: "Success", detail: "User data updated successfully.", life: 3000 });
        window.location.href = ""
    }
    async function onUpload(e: FileUploadUploadEvent) {
        let resT = e.xhr.responseText
        let res = JSON.parse(resT);
        if (!res.ok) {
            emits("notify", { severity: "error", summary: "Error", detail: res.error || "Failed to upload profile picture.", life: 5000 });
            return;
        }
        sendUserData(res.body.fileId)
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
    <div class="flex items-start">
        <Menu class="w-fit" :model="settingsMenu" />
        <div class="ml-5">
            <div class="flex items-center mb-5">
                <div class="self-center">
                    <img :src="props.icon" :alt="props.username" :title="props.username" draggable="false" class="pfp" />
                </div>
                <div class="self-center ml-5">
                    <h3 class="text-2xl mb-2">{{ props.username }}</h3>
                </div>
            </div>
            <p class="mb-2 block">Upload a profile picture: </p>
            <FileUpload ref="fileupload" mode="basic" name="profilepicture" url="/api/upload" accept="image/*" class="mb-2" @upload="onUpload" @before-send="beforeSend" />
            <InputText class="w-full" :value="props.username" disabled />
            <Textarea class="w-full mt-2" placeholder="Tell us something about yourself..." v-model="bio" />
            <Button class="float-end" @click="updateUser()">Update</Button>
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