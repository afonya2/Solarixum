<script setup lang="ts">
    import { ref } from 'vue';
    import { Menu, InputText, Textarea, FileUpload, Button } from 'primevue';

    let props = defineProps(["username", "icon", "bio"]);
    let emits = defineEmits(["updateUser", "downloadKey", "resetKey", "logout"]);
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
    let bio = ref(props.bio);
    let fileupload = ref();
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
            <FileUpload ref="fileupload" mode="basic" name="profilepicture" url="/api/pfp" accept="image/*" class="mb-2" />
            <InputText class="w-full" :value="props.username" disabled />
            <Textarea class="w-full mt-2" placeholder="Tell us something about yourself..." v-model="bio" />

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