<script setup lang="ts">
    import { Tag, Button, Select } from 'primevue'
    import { ref } from 'vue';
    let props = defineProps(["label", "icon", "rank", "ourRole", "targetId", "isRoom"]);
    let emits = defineEmits(["click", "notify"]);
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

    const PROT_NAME = 'Solarixum Protocol';
    const PROT_VER = '0.1.0';
    let selectedRank = ref();
    let ranks = ref([
        { label: "Admin", value: "admin" },
        { label: "Moderator", value: "moderator" },
        { label: "Member", value: "member" }
    ])
    async function setRank() {
        const targetRank = selectedRank.value.value;
        const token = localStorage.getItem("token");
        if (!token) {
            localStorage.setItem("state", "1")
            window.location.href = "";
            return;
        }
        let bdy: any = {
            target: props.label,
            rank: targetRank,
            token: token,
            protocol: PROT_NAME,
            protocolVersion: PROT_VER
        };
        if (props.isRoom) {
            bdy.roomId = props.targetId;
        } else {
            bdy.universeId = props.targetId;
        }
        let req = await fetch(props.isRoom ? "/api/room/setRank" : "/api/universe/setRank", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(bdy)
        });
        let res = await req.json();
        if (!res.ok) {
            if (res.error === "Invalid token") {
                localStorage.setItem("state", "1")
                window.location.href = "";
                return;
            }
            emits("notify", { severity: "error", summary: "Error", detail: res.error || "Failed to set rank.", life: 5000 });
            return;
        }
        emits("notify", { severity: "success", summary: "Success", detail: `Rank set to ${targetRank}.`, life: 3000 });
    }
    async function kick() {
        const token = localStorage.getItem("token");
        if (!token) {
            localStorage.setItem("state", "1")
            window.location.href = "";
            return;
        }
        let bdy: any = {
            target: props.label,
            token: token,
            protocol: PROT_NAME,
            protocolVersion: PROT_VER
        };
        if (props.isRoom) {
            bdy.roomId = props.targetId;
        } else {
            bdy.universeId = props.targetId;
        }
        let req = await fetch(props.isRoom ? "/api/room/kick" : "/api/universe/kick", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(bdy)
        });
        let res = await req.json();
        if (!res.ok) {
            if (res.error === "Invalid token") {
                localStorage.setItem("state", "1")
                window.location.href = "";
                return;
            }
            emits("notify", { severity: "error", summary: "Error", detail: res.error || "Failed to kick user.", life: 5000 });
            return;
        }
        emits("notify", { severity: "success", summary: "Success", detail: `User ${props.label} kicked successfully.`, life: 3000 });
    }
</script>

<template>
    <div class="frame">
        <div class="flex items-center" @click="emits('click')">
            <img :src="props.icon" :alt="props.label" :title="props.label" class="icon" draggable="false" />
            <p>{{ props.label }}</p>
            <Tag :severity="severity" :value="props.rank == null ? 'unknown' : props.rank" class="tag" />
        </div>
        <Select v-model="selectedRank" :options="ranks" option-label="label" placeholder="Set rank" class="ml-auto w-40" v-if="(ourRole == 'owner' || ourRole == 'admin') && props.rank != 'owner'" @change="setRank()" />
        <Button class="ml-2" severity="danger" v-if="(ourRole == 'owner' || ourRole == 'admin' || ourRole == 'moderator') && props.rank != 'owner'" @click="kick()">Kick</Button>
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