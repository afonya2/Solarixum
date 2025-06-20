<script setup lang="ts">
    import { ref, type Ref } from 'vue';
    import ChatMessage from './components/ChatMessage.vue';
    import RoomButton from './components/RoomButton.vue';
    import UniverseButton from './components/UniverseButton.vue';
    import { Divider, Toast, useToast, InputText, Dialog, Button } from 'primevue';
    import utils from './utils';
    import plussvg from './assets/plus.svg';

    const PROT_NAME = 'Solarixum Protocol';
    const PROT_VER = '0.1.0';
    const toast = useToast()
    let messages: Ref<{ username: string, message: string, icon: string, timestamp: number }[]> = ref([])
    let rooms: Ref<{ id: string, label: string, icon: string, active: boolean }[]> = ref([])
    let universes: Ref<{ id: string, label: string, icon: string, active: boolean }[]> = ref([]);
    let selectedRoom = ref(0);
    let selectedUniverse = ref(-1);
    let messageInput = ref("")
    let newRoomModal = ref(false);
    let roomName = ref("");
    let newUniverseModal = ref(false);
    let universeName = ref("");
    let inviteModal = ref(false);
    let inviteName = ref("");

    function selectRoom(index: number) {
        selectedRoom.value = index;
        rooms.value.forEach((room, i) => {
            room.active = i === index;
        });
        getMessages()
    }
    function selectUniverse(index: number) {
        selectedUniverse.value = index;
        universes.value.forEach((universe, i) => {
            universe.active = i === index;
        });
        getRooms()
    }
    async function getRooms() {
        rooms.value = [];
        if (universes.value.length <= selectedUniverse.value && selectedUniverse.value != -1) {
            return
        }
        let req = await fetch(`/api/rooms${selectedUniverse.value != -1 ? "?universeId="+encodeURIComponent(universes.value[selectedUniverse.value].id) : ""}`, {
            method: "GET",
            headers: {
                'Content-Type': 'application/json',
                'Authorization': localStorage.getItem('token') || '',
                'protocol': PROT_NAME,
                'protocol-version': PROT_VER
            }
        })
        let res = await req.json();
        if (!res.ok) {
            if (res.error === "Invalid token") {
                localStorage.setItem("state", "1")
                window.location.href = "";
                return
            }
            toast.add({ severity: 'error', summary: 'Error', detail: res.error || "An unknown error occurred.", life: 3000 });
            return;
        }
        console.log(res);
        
        rooms.value = res.body.map((room: any) => ({
            id: room.id,
            label: room.name,
            icon: '../logo.svg',
            active: false
        }));
        selectRoom(0)
    }
    async function getMessages() {
        messages.value = [];
        if (rooms.value.length <= selectedRoom.value) {
            return
        }
        const roomId = rooms.value[selectedRoom.value].id;
        const token = localStorage.getItem('token');
        if (!token) {
            localStorage.setItem("state", "1")
            window.location.href = "";
            return
        }

        let req1 = await fetch(`/api/room/getKey?roomId=${encodeURIComponent(roomId)}`, {
            method: "GET",
            headers: {
                Authorization: token,
                protocol: PROT_NAME,
                "protocol-version": PROT_VER,
            },
        });
        let res1 = await req1.json();
        if (!res1.ok) {
            if (res1.error === "Invalid token") {
                localStorage.setItem("state", "1")
                window.location.href = "";
                return
            }
            toast.add({ severity: 'error', summary: 'Error', detail: res1.error || "An unknown error occurred.", life: 3000 });
            return;
        }
        console.log(res1);

        const privateKey = await utils.decryptPrivateKey()
        if (!privateKey) {
            localStorage.setItem("state", "1")
            window.location.href = "";
            return;
        }
        let decryptedIv
        let keyBuffer
        try {
            let decryptedKey = await crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP",
                },
                privateKey,
                utils.base64ToArray(res1.body.key)
            );
            decryptedIv = await crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP",
                },
                privateKey,
                utils.base64ToArray(res1.body.iv)
            );
            keyBuffer = await crypto.subtle.importKey("raw", decryptedKey, { name: "AES-CBC" }, false, [
                "encrypt",
                "decrypt",
            ]);
        } catch (e) {
            toast.add({ severity: 'error', summary: 'Error', detail: "Failed to decrypt the room key.", life: 3000 });
            return
        }

        let req2 = await fetch(`/api/room/readMessages?roomId=${encodeURIComponent(roomId)}`, {
            method: "GET",
            headers: {
                Authorization: token,
                protocol: PROT_NAME,
                "protocol-version": PROT_VER,
            },
        });
        let res2 = await req2.json();
        if (!res2.ok) {
            if (res1.error === "Invalid token") {
                localStorage.setItem("state", "1")
                window.location.href = "";
                return
            }
            toast.add({ severity: 'error', summary: 'Error', detail: res2.error || "An unknown error occurred.", life: 3000 });
            return;
        }
        console.log(res2);
        for (let i = 0; i < res2.body.messages.length; i++) {
            const message = res2.body.messages[i];
            try {
                const decryptedMessage = await crypto.subtle.decrypt(
                    {
                        name: "AES-CBC",
                        iv: decryptedIv,
                    },
                    keyBuffer,
                    utils.base64ToData(message.message)
                );
                messages.value.push({
                    message: new TextDecoder().decode(decryptedMessage),
                    username: message.user,
                    icon: '../logo.svg',
                    timestamp: new Date(message.createdAt).getTime()
                })
            } catch (e) {
                messages.value.push({
                    message: "Failed to decrypt message",
                    username: message.user,
                    icon: '../logo.svg',
                    timestamp: new Date(message.createdAt).getTime()
                });
            }
        }
        console.log("Messages:", messages);
    }
    async function createRoom() {
        const token = localStorage.getItem("token");
        const publicKey = localStorage.getItem("publicKey");
        if (!token) {
            localStorage.setItem("state", "1")
            window.location.href = "";
            return;
        }
        if (!publicKey) {
            localStorage.setItem("state", "1")
            window.location.href = "";
            return;
        }

        let roomKey = utils.generateRandomString(32);
        let iv = crypto.getRandomValues(new Uint8Array(16));
        const pKey = utils.base64ToData(publicKey);
        let encryptedRoomKey
        let encryptedIv
        try {
            const keyBuffer = await crypto.subtle.importKey(
                "spki",
                pKey,
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256",
                },
                false,
                ["encrypt"]
            );
            encryptedRoomKey = await crypto.subtle.encrypt(
                {
                    name: "RSA-OAEP",
                },
                keyBuffer,
                new TextEncoder().encode(roomKey)
            );
            encryptedIv = await crypto.subtle.encrypt(
                {
                    name: "RSA-OAEP",
                },
                keyBuffer,
                iv
            ); 
        } catch (e) {
            toast.add({ severity: 'error', summary: 'Error', detail: "Failed to encrypt the room key.", life: 3000 });
            return
        }

        let req = await fetch(`/api/room/create${selectedUniverse.value != -1 ? "?universeId="+encodeURIComponent(universes.value[selectedUniverse.value].id) : ""}`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                token,
                roomName: roomName.value,
                roomKey: utils.dataToBase64(encryptedRoomKey),
                iv: utils.dataToBase64(encryptedIv),
                protocol: PROT_NAME,
                protocolVersion: PROT_VER,
            }),
        });
        let res = await req.json();
        if (!res.ok) {
            if (res.error === "Invalid token") {
                localStorage.setItem("state", "1")
                window.location.href = "";
                return
            }
            toast.add({ severity: 'error', summary: 'Error', detail: res.error || "An unknown error occurred.", life: 3000 });
            return;
        }
        console.log(res);
        roomName.value = "";
        newRoomModal.value = false;
        toast.add({ severity: 'success', summary: 'Success', detail: 'Room created successfully!', life: 3000 });
        getRooms()
    }
    async function sendMessage() {
        if (selectedRoom.value >= rooms.value.length) {
            toast.add({ severity: 'error', summary: 'Error', detail: "No room selected.", life: 3000 });
            return;
        }
        const roomId = rooms.value[selectedRoom.value].id;
        const token = localStorage.getItem('token');
        if (!token) {
            localStorage.setItem("state", "1")
            window.location.href = "";
            return
        }
        const privateKey = await utils.decryptPrivateKey()
        if (!privateKey) {
            localStorage.setItem("state", "1")
            window.location.href = "";
            return;
        }

        let req1 = await fetch(`/api/room/getKey?roomId=${encodeURIComponent(roomId)}`, {
            method: "GET",
            headers: {
                Authorization: token,
                protocol: PROT_NAME,
                "protocol-version": PROT_VER,
            },
        });
        let res1 = await req1.json();
        if (!res1.ok) {
            if (res1.error === "Invalid token") {
                localStorage.setItem("state", "1")
                window.location.href = "";
                return
            }
            toast.add({ severity: 'error', summary: 'Error', detail: res1.error || "An unknown error occurred.", life: 3000 });
            return;
        }
        console.log(res1);

        let encryptedMessage
        try {
            let decryptedKey = await crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP",
                },
                privateKey,
                utils.base64ToArray(res1.body.key)
            );
            let decryptedIv = await crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP",
                },
                privateKey,
                utils.base64ToArray(res1.body.iv)
            );
            const keyBuffer = await crypto.subtle.importKey("raw", decryptedKey, { name: "AES-CBC" }, false, [
                "encrypt",
                "decrypt",
            ]);
            encryptedMessage = await crypto.subtle.encrypt(
                {
                    name: "AES-CBC",
                    iv: decryptedIv,
                },
                keyBuffer,
                new TextEncoder().encode(messageInput.value)
            );
        } catch (e) {
            toast.add({ severity: 'error', summary: 'Error', detail: "Failed to encrypt the message.", life: 3000 });
            return;
        }

        let req2 = await fetch("/api/room/sendMessage", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                token,
                roomId,
                message: utils.dataToBase64(encryptedMessage),
                protocol: PROT_NAME,
                protocolVersion: PROT_VER,
            }),
        });
        let res2 = await req2.json();
        if (!res2.ok) {
            if (res2.error === "Invalid token") {
                localStorage.setItem("state", "1")
                window.location.href = "";
                return
            }
            toast.add({ severity: 'error', summary: 'Error', detail: res2.error || "An unknown error occurred.", life: 3000 });
            return;
        }
        console.log(res2);
        messageInput.value = ""
        getMessages()
    }
    async function getUniverses() {
        rooms.value = [];
        if (universes.value.length <= selectedUniverse.value && selectedUniverse.value != -1) {
            return
        }
        let req = await fetch("/api/universes", {
            method: "GET",
            headers: {
                'Content-Type': 'application/json',
                'Authorization': localStorage.getItem('token') || '',
                'protocol': PROT_NAME,
                'protocol-version': PROT_VER
            }
        })
        let res = await req.json();
        if (!res.ok) {
            if (res.error === "Invalid token") {
                localStorage.setItem("state", "1")
                window.location.href = "";
                return
            }
            toast.add({ severity: 'error', summary: 'Error', detail: res.error || "An unknown error occurred.", life: 3000 });
            return;
        }
        console.log(res);
        
        universes.value = res.body.map((universe: any) => ({
            id: universe.id,
            label: universe.name,
            icon: '../logo.svg',
            active: false
        }));
        selectUniverse(-1)
    }
    async function createUniverse() {
        const token = localStorage.getItem("token");
        const publicKey = localStorage.getItem("publicKey");
        if (!token) {
            localStorage.setItem("state", "1")
            window.location.href = "";
            return;
        }
        if (!publicKey) {
            localStorage.setItem("state", "1")
            window.location.href = "";
            return;
        }

        let universeKey = utils.generateRandomString(32);
        let iv = crypto.getRandomValues(new Uint8Array(16));
        const pKey = utils.base64ToData(publicKey);
        let encryptedUniverseKey
        let encryptedIv
        try {
            const keyBuffer = await crypto.subtle.importKey(
                "spki",
                pKey,
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256",
                },
                false,
                ["encrypt"]
            );
            encryptedUniverseKey = await crypto.subtle.encrypt(
                {
                    name: "RSA-OAEP",
                },
                keyBuffer,
                new TextEncoder().encode(universeKey)
            );
            encryptedIv = await crypto.subtle.encrypt(
                {
                    name: "RSA-OAEP",
                },
                keyBuffer,
                iv
            ); 
        } catch (e) {
            toast.add({ severity: 'error', summary: 'Error', detail: "Failed to encrypt the universe key.", life: 3000 });
            return
        }

        let req = await fetch("/api/universe/create", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                token,
                universeName: universeName.value,
                universeKey: utils.dataToBase64(encryptedUniverseKey),
                iv: utils.dataToBase64(encryptedIv),
                protocol: PROT_NAME,
                protocolVersion: PROT_VER,
            }),
        });
        let res = await req.json();
        if (!res.ok) {
            if (res.error === "Invalid token") {
                localStorage.setItem("state", "1")
                window.location.href = "";
                return
            }
            toast.add({ severity: 'error', summary: 'Error', detail: res.error || "An unknown error occurred.", life: 3000 });
            return;
        }
        console.log(res);
        universeName.value = "";
        newUniverseModal.value = false;
        toast.add({ severity: 'success', summary: 'Success', detail: 'Universe created successfully!', life: 3000 });
        getUniverses()
    }
    async function inviteUser() {
        const token = localStorage.getItem("token");
        if (!token) {
            localStorage.setItem("state", "1")
            window.location.href = "";
            return;
        }
        if (rooms.value.length <= selectedRoom.value) {
            toast.add({ severity: 'error', summary: 'Error', detail: "No room selected.", life: 3000 });
            return;
        }
        const roomId = rooms.value[selectedRoom.value].id;

        let req1 = await fetch(`/api/user/getKey?username=${encodeURIComponent(inviteName.value)}`, {
            method: "GET",
            headers: {
                Authorization: token,
                protocol: PROT_NAME,
                "protocol-version": PROT_VER,
            },
        });
        let res1 = await req1.json();
        if (!res1.ok) {
            if (res1.error === "Invalid token") {
                localStorage.setItem("state", "1")
                window.location.href = "";
                return
            }
            toast.add({ severity: 'error', summary: 'Error', detail: res1.error || "An unknown error occurred.", life: 3000 });
            return;
        }
        let req2 = await fetch(`/api/room/getKey?roomId=${encodeURIComponent(roomId)}`, {
            method: "GET",
            headers: {
                Authorization: token,
                protocol: PROT_NAME,
                "protocol-version": PROT_VER,
            },
        })
        let res2 = await req2.json();
        if (!res2.ok) {
            if (res2.error === "Invalid token") {
                localStorage.setItem("state", "1")
                window.location.href = "";
                return
            }
            toast.add({ severity: 'error', summary: 'Error', detail: res2.error || "An unknown error occurred.", life: 3000 });
            return;
        }
        
        const privateKey = await utils.decryptPrivateKey()
        if (!privateKey) {
            localStorage.setItem("state", "1")
            window.location.href = "";
            return;
        }
        let decryptedKey
        let decryptedIv
        try {
            decryptedKey = await crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP",
                },
                privateKey,
                utils.base64ToArray(res2.body.key)
            );
            decryptedIv = await crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP",
                },
                privateKey,
                utils.base64ToArray(res2.body.iv)
            );
        } catch (e) {
            toast.add({ severity: 'error', summary: 'Error', detail: "Failed to decrypt the room key.", life: 3000 });
            return;
        }
        
        let encryptedRoomKey
        let encryptedIv
        try {
            let userKey = await crypto.subtle.importKey(
                "spki",
                utils.base64ToData(res1.body.publicKey),
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256",
                },
                false,
                ["encrypt"]
            );
            encryptedRoomKey = await crypto.subtle.encrypt(
                {
                    name: "RSA-OAEP",
                },
                userKey,
                decryptedKey
            );
            encryptedIv = await crypto.subtle.encrypt(
                {
                    name: "RSA-OAEP",
                },
                userKey,
                decryptedIv
            );
        } catch (e) {
            toast.add({ severity: 'error', summary: 'Error', detail: "Failed to encrypt the room key for the user.", life: 3000 });
            return;
        }

        let req3 = await fetch(selectedUniverse.value == -1 ? "/api/room/invite" : "/api/universe/invite", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                token,
                roomId,
                username: inviteName.value,
                key: utils.dataToBase64(encryptedRoomKey),
                iv: utils.dataToBase64(encryptedIv),
                protocol: PROT_NAME,
                protocolVersion: PROT_VER,
                universeId: selectedUniverse.value != -1 ? universes.value[selectedUniverse.value].id : undefined,
            }),
        });
        let res3 = await req3.json();
        if (!res3.ok) {
            if (res3.error === "Invalid token") {
                localStorage.setItem("state", "1")
                window.location.href = "";
                return
            }
            toast.add({ severity: 'error', summary: 'Error', detail: res3.error || "An unknown error occurred.", life: 3000 });
            return;
        }
        toast.add({ severity: 'success', summary: 'Success', detail: `User ${inviteName.value} invited to room!`, life: 3000 });
        inviteName.value = "";
        inviteModal.value = false;
    }
    getUniverses()
</script>

<template>
    <div class="bg">
        <Toast />
        <Dialog v-model:visible="newRoomModal" modal header="Create room" style="width: fit-content;">
            <div class="flex flex-col gap-4">
                <InputText type="text" placeholder="Room name" style="width: 400px" @keypress.enter = "createRoom()" v-model="roomName" />
                <Button style="width: fit-content;margin-left: auto;" @click="createRoom()">Create</Button>
            </div>
        </Dialog>
        <Dialog v-model:visible="newUniverseModal" modal header="Create universe" style="width: fit-content;">
            <div class="flex flex-col gap-4">
                <InputText type="text" placeholder="Universe name" style="width: 400px" @keypress.enter = "createRoom()" v-model="universeName" />
                <Button style="width: fit-content;margin-left: auto;" @click="createUniverse()">Create</Button>
            </div>
        </Dialog>
        <Dialog v-model:visible="inviteModal" modal :header="`Invite to '${selectedRoom < rooms.length ? (selectedUniverse == -1 ? rooms[selectedRoom].label : universes[selectedUniverse].label) : 'Loading...'}'`" style="width: fit-content;">
            <div class="flex flex-col gap-4">
                <InputText type="text" placeholder="Username" style="width: 400px" @keypress.enter = "createRoom()" v-model="inviteName" />
                <Button style="width: fit-content;margin-left: auto;" @click="inviteUser()">Invite</Button>
            </div>
        </Dialog>
        <div class="universe-select">
            <UniverseButton label="Home" icon="../logo.svg" :active="selectedUniverse == -1" @click="selectUniverse(-1)" />
            <Divider />
            <UniverseButton v-for="(universe, i) in universes" :label="universe.label" :icon="universe.icon" :active="universe.active" @click="selectUniverse(i)" />
            <UniverseButton label="Create Universe" :icon="plussvg" active="false" @click="newUniverseModal = true" />
        </div>
        <div class="content">
            <div class="content-head">
                <h2 class="text-2xl">{{ selectedUniverse < universes.length ? (selectedUniverse == -1 ? "Home" : universes[selectedUniverse].label) : "Loading..." }}</h2>
                <a href="#" class="ml-4" @click="inviteModal = true"><span class="material-symbols-rounded align-middle">person_add</span></a>
            </div>
            <div class="room-select">
                <div class="flex items-center mb-4">
                    <h3 class="text-xl text-slate-400 select-none leading-none">Rooms</h3>
                    <a href="#" @click="newRoomModal = true" class="ml-auto block w-fit select-none"><span class="material-symbols-rounded align-middle">add</span></a>
                </div>
                <RoomButton v-for="(room, i) in rooms" :label="room.label" :icon="room.icon" :active="room.active" @click="selectRoom(i)" />
            </div>
            <div class="content-body">
                <div class="messages">
                    <ChatMessage v-for="msg of messages" :username="msg.username" :icon="msg.icon" :message="msg.message" :timestamp="msg.timestamp" />
                </div>
                <div class="message-input">
                    <InputText type="text" placeholder="Send a message..." v-model="messageInput" class="w-full" @keypress.enter="sendMessage()" />
                </div>
            </div>
        </div>
    </div>
</template>

<style scoped>
.bg {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: var(--color-slate-900);
    z-index: 1;
}
.content {
    position: fixed;
    top: 10px;
    left: 90px;
    width: calc(100% - 100px);
    height: calc(100% - 20px);
    flex-direction: column;
    background-color: var(--color-slate-950);
    border-radius: 20px;
    z-index: 3;
}
.content-head {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 74px;
    border-top-left-radius: 20px;
    border-top-right-radius: 20px;
    border-bottom: 3px solid var(--color-slate-900);
    padding: 20px;
    display: flex;
    align-items: center;
    user-select: none;
}
.room-select {
    position: absolute;
    top: 74px;
    left: 0;
    width: 350px;
    height: calc(100% - 74px);
    border-right: 3px solid var(--color-slate-900);
    padding: 20px;
    border-bottom-left-radius: 20px;
}
.content-body {
    position: absolute;
    top: 74px;
    left: 350px;
    width: calc(100% - 350px);
    height: calc(100% - 74px);
    border-bottom-right-radius: 20px;
}
.universe-select {
    position: fixed;
    top: 0;
    left: 0;
    width: 75px;
    height: 100%;
    z-index: 2;
    margin-left: 5px;
    padding-block: 10px;
}
.messages {
    width: 100%;
    height: calc(100% - 60px);
    border-bottom: 3px solid var(--color-slate-900);
    padding: 20px;
}
.message-input {
    position: absolute;
    bottom: 0;
    left: 0;
    width: 100%;
    height: 60px;
    padding: 20px;
    display: flex;
    align-items: center;
}
</style>