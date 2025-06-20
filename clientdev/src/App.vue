<script setup lang="ts">
    import { ref, type Ref } from 'vue';
    import ChatMessage from './components/ChatMessage.vue';
    import RoomButton from './components/RoomButton.vue';
    import SolarButton from './components/SolarButton.vue';
    import { Divider, Toast, useToast } from 'primevue';
import utils from './utils';

    const PROT_NAME = 'Solarixum Protocol';
    const PROT_VER = '0.1.0';
    //const toast = useToast()
    let messages: Ref<{ username: string, message: string, icon: string, timestamp: number }[]> = ref([])
    let rooms: Ref<{ id: string, label: string, icon: string, active: boolean }[]> = ref([])
    let selectedRoom = 0;

    function selectRoom(index: number) {
        selectedRoom = index;
        rooms.value.forEach((room, i) => {
            room.active = i === index;
        });
        getMessages()
    }
    async function getRooms() {
        let req = await fetch("/api/rooms", {
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
            //toast.add({ severity: 'error', summary: 'Error', detail: res.error || "An unknown error occurred.", life: 3000 });
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
        if (rooms.value.length <= selectedRoom) {
            return
        }
        const roomId = rooms.value[selectedRoom].id;
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
            console.error("Failed to get room:", res1.error);
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
            console.error("Failed to decrypt the room key:", e);
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
            console.error("Failed to read messages:", res2.error);
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
                    username: message.username,
                    icon: '../logo.svg',
                    timestamp: new Date(message.createdAt).getTime()
                })
            } catch (e) {
                messages.value.push({
                    message: "Failed to decrypt message",
                    username: message.username,
                    icon: '../logo.svg',
                    timestamp: new Date(message.createdAt).getTime()
                });
            }
        }
        console.log("Messages:", messages);
    }
    getRooms()
    async function createRoom(name: string) {
        const token = localStorage.getItem("token");
        const publicKey = localStorage.getItem("publicKey");
        if (!token) {
            console.error("No token found in local storage.");
            return;
        }
        if (!publicKey) {
            console.error("No public key found in local storage.");
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
            console.error("Failed to encrypt the room key:", e);
            return
        }

        let req = await fetch("/api/room/create", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                token,
                roomName: name,
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
            console.error("Room creation failed:", res.error);
            return;
        }
        console.log(res);
    }
</script>

<template>
    <div class="bg">
        <Toast />
        <div class="solar-select">
            <SolarButton label="Home" icon="../logo.svg" active="true" />
            <Divider />
            <SolarButton label="Home" icon="../logo.svg" active="false" />
            <SolarButton label="Home" icon="../logo.svg" active="false" />
        </div>
        <div class="content">
            <div class="content-head">
                <h2 class="text-2xl">Example text</h2>
            </div>
            <div class="room-select">
                <a href="#" @click="createRoom('test')">Create a room</a>
                <RoomButton v-for="room of rooms" :label="room.label" :icon="room.icon" :active="room.active" />
            </div>
            <div class="content-body">
                <ChatMessage v-for="msg of messages" :username="msg.username" :icon="msg.icon" :message="msg.message" :timestamp="msg.timestamp" />
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
    padding: 20px;
}
.solar-select {
    position: fixed;
    top: 0;
    left: 0;
    width: 75px;
    height: 100%;
    z-index: 2;
    margin-left: 5px;
    padding-block: 10px;
}
</style>