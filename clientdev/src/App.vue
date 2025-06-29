<script setup lang="ts">
    import { ref, type Ref } from 'vue';
    import ChatMessage from './components/ChatMessage.vue';
    import RoomButton from './components/RoomButton.vue';
    import UniverseButton from './components/UniverseButton.vue';
    import { Divider, Toast, useToast, InputText, Dialog, Button, type ToastMessageOptions } from 'primevue';
    import utils from './utils';
    import plussvg from './assets/plus.svg';
    import UserCard from './components/UserCard.vue';
    import UserInformation from './components/UserInformation.vue';
    import Settings from './components/Settings.vue';
    import ChannelSettings from './components/ChannelSettings.vue';
    import UniverseSettings from './components/UniverseSettings.vue';

    const PROT_NAME = 'Solarixum Protocol';
    const PROT_VER = '0.1.0';
    const toast = useToast()
    let messages: Ref<{ username: string, message: string, icon: string, timestamp: number, id: string }[]> = ref([])
    let rooms: Ref<{ id: string, label: string, icon: string, active: boolean }[]> = ref([])
    let universes: Ref<{ id: string, label: string, icon: string, active: boolean }[]> = ref([]);
    let roomMembers: Ref<{ username: string, icon: string, rank: string }[]> = ref([]);
    let selectedRoom = ref(0);
    let selectedUniverse = ref(-1);
    let messageInput = ref("")
    let newRoomModal = ref(false);
    let roomName = ref("");
    let newUniverseModal = ref(false);
    let universeName = ref("");
    let inviteModal = ref(false);
    let inviteName = ref("");
    let editMessageModal = ref(false);
    let editedMessageId = ref("");
    let editedMessageContent = ref("");
    let showMembers = ref(false);
    let userModal = ref(false);
    let userInfo = ref({
        username: '',
        icon: '../logo.svg',
        bio: 'This is a user bio.'
    });
    let messagesLoading = ref(false);
    let roomsLoading = ref(false);
    let socket: WebSocket;
    let ownUser = ref({
        username: '',
        icon: '../logo.svg',
        bio: 'This is your bio.'
    })
    let roomInfo = ref({
        name: '',
        id: '',
        icon: '../logo.svg',
    })
    let universeInfo = ref({
        name: '',
        id: '',
        icon: '../logo.svg',
    })
    let settingsOpen = ref(false);
    let channelSettings = ref(false)
    let universeSettings = ref(false)

    let channelKey: CryptoKey
    let channelIv: ArrayBuffer

    async function selectRoom(index: number) {
        const token = localStorage.getItem('token');
        if (!token) {
            localStorage.setItem("state", "1")
            window.location.href = "";
            return
        }
        
        selectedRoom.value = index;
        rooms.value.forEach((room, i) => {
            room.active = i === index;
        });

        let req = await fetch(`/api/room/info?roomId=${encodeURIComponent(rooms.value[selectedRoom.value].id)}`, {
            method: "GET",
            headers: {
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
        let tempMembers: { username: string, icon: string, rank: string }[] = [];
        for (let i = 0; i < res.body.members.length; i++) {
            let req2 = await fetch(`/api/user/info?username=${encodeURIComponent(res.body.members[i].user)}`, {
                method: "GET",
                headers: {
                    'Authorization': localStorage.getItem('token') || '',
                    'protocol': PROT_NAME,
                    'protocol-version': PROT_VER
                }
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
            tempMembers.push({
                username: res2.body.username,
                icon: res2.body.icon != null ? '/uploads/'+encodeURIComponent(res2.body.icon) : '../logo.svg',
                rank: res.body.members[i].role || 'member'
            });
        }
        roomMembers.value = tempMembers
        roomInfo.value = {
            name: res.body.name,
            id: res.body.id,
            icon: res.body.icon != null ? '/uploads/'+encodeURIComponent(res.body.icon) : '../logo.svg',
        }

        getMessages()
    }
    async function selectUniverse(index: number) {
        const token = localStorage.getItem('token');
        if (!token) {
            localStorage.setItem("state", "1")
            window.location.href = "";
            return
        }

        selectedUniverse.value = index;
        universes.value.forEach((universe, i) => {
            universe.active = i === index;
        });
        if (selectedUniverse.value == -1) {
            getRooms()
            return
        }

        let req = await fetch(`/api/universe/info?universeId=${encodeURIComponent(universes.value[selectedUniverse.value].id)}`, {
            method: "GET",
            headers: {
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
        universeInfo.value = {
            name: res.body.name,
            id: res.body.id,
            icon: res.body.icon != null ? '/uploads/'+encodeURIComponent(res.body.icon) : '../logo.svg',
        }

        getRooms()
    }
    async function getRooms() {
        roomsLoading.value = true;
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
            icon: room.icon != null ? '/uploads/'+encodeURIComponent(room.icon) : '../logo.svg',
            active: false
        }));
        roomsLoading.value = false;
        selectRoom(0)
    }
    async function getMessages() {
        messagesLoading.value = true;
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
        channelKey = keyBuffer
        channelIv = decryptedIv

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
        let preMessages: { username: string, message: string, icon: string, timestamp: number, id: string }[] = [];
        for (let i = 0; i < res2.body.messages.length; i++) {
            const message = res2.body.messages[i];
            let userReq = await fetch(`/api/user/info?username=${encodeURIComponent(message.user)}`, {
                method: "GET",
                headers: {
                    'Authorization': localStorage.getItem('token') || '',
                    'protocol': PROT_NAME,
                    'protocol-version': PROT_VER
                }
            })
            let userRes = await userReq.json();
            if (!userRes.ok) {
                if (userRes.error === "Invalid token") {
                    localStorage.setItem("state", "1")
                    window.location.href = "";
                    return
                }
                toast.add({ severity: 'error', summary: 'Error', detail: userRes.error || "An unknown error occurred.", life: 3000 });
                return;
            }
            try {
                const decryptedMessage = await crypto.subtle.decrypt(
                    {
                        name: "AES-CBC",
                        iv: decryptedIv,
                    },
                    keyBuffer,
                    utils.base64ToData(message.message)
                );
                preMessages.push({
                    message: new TextDecoder().decode(decryptedMessage),
                    username: message.user,
                    icon: userRes.body.icon != null ? '/uploads/'+encodeURIComponent(userRes.body.icon) : '../logo.svg',
                    timestamp: new Date(message.createdAt).getTime(),
                    id: message.id
                })
            } catch (e) {
                preMessages.push({
                    message: "Failed to decrypt message",
                    username: message.user,
                    icon: userRes.body.icon != null ? '/uploads/'+encodeURIComponent(userRes.body.icon) : '../logo.svg',
                    timestamp: new Date(message.createdAt).getTime(),
                    id: message.id
                });
            }
        }
        messages.value = preMessages;
        messagesLoading.value = false;
        console.log("Messages:", messages.value);
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
        //getRooms()
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
        //getMessages()
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
            icon: universe.icon != null ? '/uploads/'+encodeURIComponent(universe.icon) : '../logo.svg',
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
    async function beginEditMessage(id: string) {
        for (let i = 0; i < messages.value.length; i++) {
            if (messages.value[i].id == id) {
                editedMessageContent.value = messages.value[i].message;
                editMessageModal.value = true
                editedMessageId.value = id;
                break;
            }
        }
    }
    async function editMessage() {
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
                new TextEncoder().encode(editedMessageContent.value)
            );
        } catch (e) {
            toast.add({ severity: 'error', summary: 'Error', detail: "Failed to encrypt the message.", life: 3000 });
            return;
        }

        let req2 = await fetch("/api/room/editMessage", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                token,
                roomId,
                message: utils.dataToBase64(encryptedMessage),
                messageId: editedMessageId.value,
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
        editedMessageContent.value = ""
        editMessageModal.value = false;
        //getMessages()
    }
    async function deleteMessage(id: string) {
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

        let req = await fetch("/api/room/deleteMessage", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                token,
                roomId,
                messageId: id,
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
        //getMessages()
    }
    async function selectMember(name: string) {
        let req = await fetch(`/api/user/info?username=${encodeURIComponent(name)}`, {
            method: "GET",
            headers: {
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
        userInfo.value = {
            username: res.body.username,
            icon: res.body.icon != null ? '/uploads/'+encodeURIComponent(res.body.icon) : '../logo.svg',
            bio: res.body.bio || 'This user has no bio.'
        };
        showMembers.value = false;
        userModal.value = true;
    }
    async function connectWs() {
        const token = localStorage.getItem('token');
        if (!token) {
            localStorage.setItem("state", "1")
            window.location.href = "";
            return;
        }
        socket = new WebSocket(`ws://${window.location.host}/ws`);
        socket.onopen = () => {
            console.log("WebSocket connection established");
            socket.send(JSON.stringify({
                type: "auth",
                token: token,
                protocol: PROT_NAME,
                protocolVersion: PROT_VER
            }));
            setInterval(() => {
                if (socket.readyState === WebSocket.OPEN) {
                    socket.send(JSON.stringify({
                        type: "heartbeat",
                        protocol: PROT_NAME,
                        protocolVersion: PROT_VER
                    }));
                }
            }, 60000)
        };
        socket.onmessage = async (event) => {
            let data
            try {
                data = JSON.parse(event.data);
            } catch (e) {
                console.error("Failed to parse WebSocket message:", e);
                return;
            }
            if (data.protocol != PROT_NAME) {
                toast.add({ severity: 'error', summary: 'Error', detail: `Server uses unsupported protocol.`, life: 3000 });
                return;
            }
            if (data.protocolVersion != PROT_VER) {
                toast.add({ severity: 'error', summary: 'Error', detail: `Server uses unsupported protocol version.`, life: 3000 });
                return;
            }
            if (data.type == "error") {
                console.error("WebSocket error:", data.message);
                toast.add({ severity: 'error', summary: 'Error', detail: data.error || "An unknown error occurred.", life: 3000 });
                return;
            } else if (data.type == "message") {
                let currentRoom = rooms.value[selectedRoom.value];
                if (currentRoom && currentRoom.id == data.roomId) {
                    let userReq = await fetch(`/api/user/info?username=${encodeURIComponent(data.user)}`, {
                        method: "GET",
                        headers: {
                            'Authorization': localStorage.getItem('token') || '',
                            'protocol': PROT_NAME,
                            'protocol-version': PROT_VER
                        }
                    })
                    let userRes = await userReq.json();
                    if (!userRes.ok) {
                        if (userRes.error === "Invalid token") {
                            localStorage.setItem("state", "1")
                            window.location.href = "";
                            return
                        }
                        toast.add({ severity: 'error', summary: 'Error', detail: userRes.error || "An unknown error occurred.", life: 3000 });
                        return;
                    }
                    try {
                        const decryptedMessage = await crypto.subtle.decrypt(
                            {
                                name: "AES-CBC",
                                iv: channelIv,
                            },
                            channelKey,
                            utils.base64ToData(data.message)
                        );
                        messages.value.push({
                            message: new TextDecoder().decode(decryptedMessage),
                            username: data.user,
                            icon: userRes.body.icon != null ? '/uploads/'+encodeURIComponent(userRes.body.icon) : '../logo.svg',
                            timestamp: new Date(data.createdAt).getTime(),
                            id: data.id
                        })
                    } catch (e) {
                        messages.value.push({
                            message: "Failed to decrypt message",
                            username: data.user,
                            icon: userRes.body.icon != null ? '/uploads/'+encodeURIComponent(userRes.body.icon) : '../logo.svg',
                            timestamp: new Date(data.createdAt).getTime(),
                            id: data.id
                        });
                    }
                }
            } else if (data.type == "roomInvite") {
                if (selectedUniverse.value == -1) {
                    rooms.value.push({
                        id: data.roomId,
                        label: data.roomName,
                        icon: data.icon != null ? '/uploads/'+encodeURIComponent(data.icon) : '../logo.svg',
                        active: false
                    })
                }
            } else if (data.type == "universeInvite") {
                universes.value.push({
                    id: data.universeId,
                    label: data.universeName,
                    icon: data.icon != null ? '/uploads/'+encodeURIComponent(data.icon) : '../logo.svg',
                    active: false
                })
            } else if (data.type == "roomCreated") {
                if (data.universeId == "&0" && selectedUniverse.value == -1) {
                    rooms.value.push({
                        id: data.roomId,
                        label: data.roomName,
                        icon: data.icon != null ? '/uploads/'+encodeURIComponent(data.icon) : '../logo.svg',
                        active: false
                    })
                } else if (data.universeId == universes.value[selectedUniverse.value].id) {
                    rooms.value.push({
                        id: data.roomId,
                        label: data.roomName,
                        icon: data.icon != null ? '/uploads/'+encodeURIComponent(data.icon) : '../logo.svg',
                        active: false
                    })
                }
            } else if (data.type == "messageUpdate") {
                let currentRoom = rooms.value[selectedRoom.value];
                if (currentRoom && currentRoom.id == data.roomId) {
                    try {
                        const decryptedMessage = await crypto.subtle.decrypt(
                            {
                                name: "AES-CBC",
                                iv: channelIv,
                            },
                            channelKey,
                            utils.base64ToData(data.message)
                        );
                        for (let i = 0; i < messages.value.length; i++) {
                            if (messages.value[i].id == data.id) {
                                messages.value[i].message = new TextDecoder().decode(decryptedMessage);
                                break;
                            }
                        }
                    } catch (e) {
                        for (let i = 0; i < messages.value.length; i++) {
                            if (messages.value[i].id == data.id) {
                                messages.value[i].message = "Failed to decrypt message";
                                break;
                            }
                        }
                    }
                }
            } else if (data.type == "messageDelete") {
                let currentRoom = rooms.value[selectedRoom.value];
                if (currentRoom && currentRoom.id == data.roomId) {
                    for (let i = 0; i < messages.value.length; i++) {
                        if (messages.value[i].id == data.id) {
                            messages.value.splice(i, 1);
                            break;
                        }
                    }
                }
            } else if (data.type == "roomUpdate") {
                if (data.universeId == "&0" && selectedUniverse.value == -1) {
                    for (let i = 0; i < rooms.value.length; i++) {
                        if (rooms.value[i].id == data.roomId) {
                            rooms.value[i].label = data.roomName;
                            rooms.value[i].icon = data.icon != null ? '/uploads/'+encodeURIComponent(data.icon) : '../logo.svg';
                            break;
                        }
                    }
                } else if (data.universeId == universes.value[selectedUniverse.value].id) {
                    for (let i = 0; i < rooms.value.length; i++) {
                        if (rooms.value[i].id == data.roomId) {
                            rooms.value[i].label = data.roomName;
                            rooms.value[i].icon = data.icon != null ? '/uploads/'+encodeURIComponent(data.icon) : '../logo.svg';
                            break;
                        }
                    }
                }
            } else if (data.type == "roomDelete") {
                if (data.universeId == "&0" && selectedUniverse.value == -1) {
                    for (let i = 0; i < rooms.value.length; i++) {
                        if (rooms.value[i].id == data.roomId) {
                            rooms.value.splice(i, 1);
                            break;
                        }
                    }
                } else if (data.universeId == universes.value[selectedUniverse.value].id) {
                    for (let i = 0; i < rooms.value.length; i++) {
                        if (rooms.value[i].id == data.roomId) {
                            rooms.value.splice(i, 1);
                            break;
                        }
                    }
                }
            } else if (data.type == "universeUpdate") {
                for (let i = 0; i < universes.value.length; i++) {
                    if (universes.value[i].id == data.universeId) {
                        universes.value[i].label = data.universeName;
                        universes.value[i].icon = data.icon != null ? '/uploads/'+encodeURIComponent(data.icon) : '../logo.svg';
                        break;
                    }
                }
            } else if (data.type == "universeDelete") {
                for (let i = 0; i < universes.value.length; i++) {
                    if (universes.value[i].id == data.universeId) {
                        universes.value.splice(i, 1);
                        break;
                    }
                }
            }
        }
        socket.onclose = (event) => {
            console.log("WebSocket connection closed:", event);
            toast.add({ severity: 'error', summary: 'Error', detail: 'WebSocket connection lost. Please refresh the page.', life: 5000 });
        };
        socket.onerror = (error) => {
            console.error("WebSocket error:", error);
            toast.add({ severity: 'error', summary: 'Error', detail: 'WebSocket error occurred. Please refresh the page.', life: 5000 });
        };
    }
    async function getOwnInfo() {
        const token = localStorage.getItem('token');
        if (!token) {
            localStorage.setItem("state", "1")
            window.location.href = "";
            return;
        }
        
        let req = await fetch("/api/me", {
            method: "GET",
            headers: {
                'Authorization': token,
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
        ownUser.value = {
            username: res.body.username,
            icon: res.body.icon != null ? '/uploads/'+encodeURIComponent(res.body.icon) : '../logo.svg',
            bio: res.body.bio || ''
        };
    }
    function notify(message: ToastMessageOptions) {
        toast.add(message)
    }
    getUniverses()
    connectWs()
    getOwnInfo()
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
                <InputText type="text" placeholder="Universe name" style="width: 400px" @keypress.enter = "createUniverse()" v-model="universeName" />
                <Button style="width: fit-content;margin-left: auto;" @click="createUniverse()">Create</Button>
            </div>
        </Dialog>
        <Dialog v-model:visible="inviteModal" modal :header="`Invite to '${selectedRoom < rooms.length ? (selectedUniverse == -1 ? rooms[selectedRoom].label : universes[selectedUniverse].label) : 'Loading...'}'`" style="width: fit-content;">
            <div class="flex flex-col gap-4">
                <InputText type="text" placeholder="Username" style="width: 400px" @keypress.enter = "inviteUser()" v-model="inviteName" />
                <Button style="width: fit-content;margin-left: auto;" @click="inviteUser()">Invite</Button>
            </div>
        </Dialog>
        <Dialog v-model:visible="editMessageModal" modal header="Edit message" style="width: fit-content;">
            <div class="flex flex-col gap-4">
                <InputText type="text" placeholder="Message" style="width: 400px" @keypress.enter = "editMessage()" v-model="editedMessageContent" />
                <Button style="width: fit-content;margin-left: auto;" @click="editMessage()">Save</Button>
            </div>
        </Dialog>
        <Dialog v-model:visible="showMembers" modal :header="`Members of '${selectedRoom < rooms.length ? (selectedUniverse == -1 ? rooms[selectedRoom].label : universes[selectedUniverse].label) : 'Loading...'}'`" style="width: 25%;min-width: fit-content;max-height: 25%;overflow: auto;">
            <div class="flex flex-col gap-4">
                <UserCard v-for="member in roomMembers" :label="member.username" :icon="member.icon" :rank="member.rank" @click="selectMember(member.username)" />
            </div>
        </Dialog>
        <Dialog v-model:visible="userModal" modal :header="`Profile of '${userInfo.username.substring(1)}'`" style="width: fit-content;">
            <UserInformation :label="userInfo.username" :icon="userInfo.icon" :bio="userInfo.bio" />
        </Dialog>
        <Dialog v-model:visible="settingsOpen" modal header="Settings" style="width: fit-content;">
            <Settings :username="ownUser.username" :icon="ownUser.icon" :bio="ownUser.bio" @notify="notify" />
        </Dialog>
        <Dialog v-model:visible="channelSettings" modal header="Channel settings" style="width: fit-content;">
            <ChannelSettings :name="roomInfo.name" :icon="roomInfo.icon" :id="roomInfo.id" @notify="notify" @close="channelSettings = false" />
        </Dialog>
        <Dialog v-model:visible="universeSettings" modal header="Universe settings" style="width: fit-content;">
            <UniverseSettings :name="universeInfo.name" :icon="universeInfo.icon" :id="universeInfo.id" @notify="notify" @close="universeSettings = false" />
        </Dialog>
        <div class="universe-select overflow-auto">
            <UniverseButton label="Home" icon="../logo.svg" :active="selectedUniverse == -1" @click="selectUniverse(-1)" />
            <Divider />
            <UniverseButton v-for="(universe, i) in universes" :label="universe.label" :icon="universe.icon" :active="universe.active" @click="selectUniverse(i)" />
            <UniverseButton label="Create Universe" :icon="plussvg" active="false" @click="newUniverseModal = true" />
        </div>
        <div class="ownuser">
            <UniverseButton :label="`${ownUser.username}(You)`" :icon="ownUser.icon" :active="false" @click="settingsOpen = true" />
        </div>
        <div class="content">
            <div class="content-head">
                <h2 class="text-2xl">{{ selectedUniverse < universes.length ? (selectedUniverse == -1 ? "Home" : universes[selectedUniverse].label) : "Loading..." }}</h2>
                <Button class="btn ml-5" @click="universeSettings = true" v-if="selectedUniverse != -1"><span class="material-symbols-rounded align-middle text-slate-300">settings</span></Button>
                <Button class="btn ml-auto" @click="inviteModal = true"><span class="material-symbols-rounded align-middle text-slate-300">person_add</span></Button>
                <Button class="btn" @click="showMembers = true"><span class="material-symbols-rounded align-middle text-slate-300">group</span></Button>
                <Button class="btn" @click="channelSettings = true"><span class="material-symbols-rounded align-middle text-slate-300">settings</span></Button>
            </div>
            <div class="room-select overflow-auto">
                <div class="flex items-center mb-4">
                    <h3 class="text-xl text-slate-400 select-none leading-none">Rooms</h3>
                    <a href="#" @click="newRoomModal = true" class="ml-auto block w-fit select-none"><span class="material-symbols-rounded align-middle">add</span></a>
                </div>
                <RoomButton v-for="_ in 10" v-if="roomsLoading" loading="true" />
                <RoomButton v-for="(room, i) in rooms" :label="room.label" :icon="room.icon" :active="room.active" @click="selectRoom(i)" :hidden="roomsLoading" loading="false" />
            </div>
            <div class="content-body">
                <div class="messages overflow-auto">
                    <ChatMessage v-for="_ in 10" v-if="messagesLoading" loading="true" />
                    <ChatMessage v-for="msg of messages" :username="msg.username" :icon="msg.icon" :message="msg.message" :timestamp="msg.timestamp" :id="msg.id" @edit-message="beginEditMessage(msg.id)" @delete-message="deleteMessage(msg.id)" @user-info="selectMember(msg.username)" :hidden="messagesLoading" loading="false" :ownusername="ownUser.username" />
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
    height: calc(100% - 104px);
    z-index: 2;
    margin-left: 5px;
    margin-block: 10px;
}
.ownuser {
    position: fixed;
    bottom: 0;
    left: 0;
    width: 75px;
    height: fit-content;
    z-index: 2;
    margin-left: 5px;
    margin-block: 10px;
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