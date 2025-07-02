import http from 'http';
import { WebSocketServer } from 'ws';
import crypto from 'crypto';
import url from 'url'
import fs from 'fs';
import path from 'path';
import { MongoClient } from 'mongodb'
import { ulid } from 'ulid';
import WebSocket from 'ws';
import busboy from 'busboy'

const VER = '0.1.0';
const SERV_NAME = 'Solarixum Server';
const PROT_VER = '0.1.0';
const PROT_NAME = 'Solarixum Protocol';
let limits = {}
let config = {
    "port": 1010,
    "db": {
        "host": "127.0.0.1",
        "port": 27017,
        "database": "solarixum",
        "user": "solarixum",
        "password": "solarixum"
    },
    "trustedProxies": ["127.0.0.1"],
    "limits": {
        "maxFileSize": 10485760,
        "maxRequestsPerHour": 10000,
        "maxRegistrationsPerHour": 2,
        "loginTriesPerHour": 10,
        "messagesPerHour": 1000
    },
    "welcomeRoom": "",
    "welcomeRoomKey": "",
    "welcomeRoomIv": ""
}
const configFile = JSON.parse(fs.readFileSync('config.json', 'utf8'));
function merge(target: any, source: any, deep: boolean) {
    for (const key in source) {
        if (source.hasOwnProperty(key)) {
            if (deep && typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key]) && target[key] !== undefined) {
                merge(target[key], source[key], deep);
            } else {
                target[key] = source[key];
            }
        }
    }
}
merge(config, configFile, true);
if (!fs.existsSync("uploads")) {
    fs.mkdirSync("uploads");
}

const dbClient = new MongoClient(`mongodb://${encodeURIComponent(config.db.user)}:${encodeURIComponent(config.db.password)}@${config.db.host}:${config.db.port}/`, {
    tls: true,
    tlsInsecure: true,
})
const db = dbClient.db(config.db.database);

function sendResponse(ok: boolean, data: any, error?: string) {
    let res: any = {
        ok: ok,
        body: data,
        protocol: PROT_NAME,
        protocolVersion: PROT_VER
    }
    if (!ok) {
        res.error = error
    }
    return JSON.stringify(res)
}

function generateRandomString(length: number): string {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}
function base64ToPem(base64: string): string {
    const lines = base64.match(/.{1,64}/g)?.join('\n') || '';
    return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`;
}
function characterLimit(input: string): boolean {
    let allowedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-";
    for (let i = 0; i < input.length; i++) {
        if (!allowedChars.includes(input[i])) {
            return false;
        }
    }
    return true;
}

let sockets: {[key: string]: { ws: WebSocket, token: string, username: string, lastHeartBeat: number }} = {}
async function transmitRoomUpdate(id: string, data: string) {
    const membersCollection = db.collection("members");
    const roomCollection = db.collection("rooms");
    const room = await roomCollection.findOne({ id: id });
    if (room == null || room.deleted) {
        return;
    }
    let members
    if (room.universeId != "&0") {
        members = await membersCollection.find({ target: room.universeId }).toArray();
    } else {
        members = await membersCollection.find({ target: id }).toArray();
    }
    const memNames = members.map((member: any) => member.user)
    for (let i in sockets) {
        if (memNames.includes(sockets[i].username)) {
            sockets[i].ws.send(data)
        }
    }
}
async function transmitUniverseUpdate(id: string, data: string) {
    const membersCollection = db.collection("members");
    const universeCollection = db.collection("universes");
    const universe = await universeCollection.findOne({ id: id });
    if (universe == null || universe.deleted) {
        return;
    }
    const members = await membersCollection.find({ target: id }).toArray();
    const memNames = members.map((member: any) => member.user)
    for (let i in sockets) {
        if (memNames.includes(sockets[i].username)) {
            sockets[i].ws.send(data)
        }
    }
}
async function transmitToUser(username: string, data: string) {
    for (let i in sockets) {
        if (sockets[i].username == username) {
            sockets[i].ws.send(data);
        }
    }
}
setInterval(() => {
    for (let sid in sockets) {
        if (sockets[sid].lastHeartBeat < Date.now() - 120000) {
            console.log(`Socket ${sid} timed out, closing...`);
            sockets[sid].ws.close();
            delete sockets[sid];
        }
    }
}, 1000)

const httpServer = http.createServer(async (req, res) => {
    const clearUrl = req.url?.split('?')[0];
    const args = url.parse(req.url || "", true).query;
    let ip = req.socket.remoteAddress?.replace("::ffff:", "")
    if (ip == "::1") {
        ip = "127.0.0.1"
    }
    if (ip == undefined) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(sendResponse(false, null, "Failed to determine your IP address. Please try again later."));
        return
    }
    if (req.headers['x-forwarded-for'] != undefined && config.trustedProxies.includes(ip)) {
        ip = req.headers['x-forwarded-for'] as string;
    }
    if (ip == undefined) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(sendResponse(false, null, "Failed to determine your IP address. Please try again later."));
        return
    }
    if (limits[ip] == undefined || limits[ip].reset < Date.now()) {
        limits[ip] = {
            count: 0,
            registers: 0,
            logins: 0,
            messages: 0,
            reset: Date.now() + 3600000
        }
    }
    limits[ip].count++;
    if (limits[ip].count > config.limits.maxRequestsPerHour) {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(sendResponse(false, {
            resetDate: limits[ip].reset
        }, "Too many requests. Please try again later."));
        return;
    }
    if (clearUrl == "/") {
        res.writeHead(301, { 'Location': '/client/' });
        res.end();
        return;
    }
    if (clearUrl == "/version" && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(sendResponse(true, {
            protocol: PROT_NAME,
            protocolVersion: PROT_VER,
            serverVersion: VER,
            serverName: SERV_NAME
        }))
    } else if (clearUrl == "/client") {
        res.writeHead(301, { 'Location': '/client/' });
        res.end();
    } else if (clearUrl == "/logo.svg") {
        res.writeHead(200, { 'Content-Type': 'image/svg+xml', 'cache-control': 'max-age=86400' });
        res.end(fs.readFileSync("./client/logo.svg"));
    } else if (clearUrl?.startsWith("/client/")) {
        let pathRemaining = clearUrl.replace("/client/", "");
        let file = `./client/${path.normalize(pathRemaining)}`;
        if (file == "./client/.") {
            file = "./client/index.html";
        }
        if (file == "./client/terms") {
            file = "./client/index.html";
        }
        if (!fs.existsSync(file)) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Not Found"));
            return;
        }
        let content = fs.readFileSync(file);
        if (file.endsWith(".html")) {
            res.writeHead(200, { 'Content-Type': 'text/html', 'cache-control': 'max-age=86400' });
            res.end(content);
        } else if (file.endsWith(".js")) {
            res.writeHead(200, { 'Content-Type': 'application/javascript', 'cache-control': 'max-age=86400' });
            res.end(content);
        } else if (file.endsWith(".css")) {
            res.writeHead(200, { 'Content-Type': 'text/css', 'cache-control': 'max-age=86400' });
            res.end(content);
        } else if (file.endsWith(".jpg")) {
            res.writeHead(200, { 'Content-Type': 'image/jpeg', 'cache-control': 'max-age=86400' });
            res.end(content);
        } else if (file.endsWith(".svg")) {
            res.writeHead(200, { 'Content-Type': 'image/svg+xml', 'cache-control': 'max-age=86400' });
            res.end(content);
        } else {
            res.writeHead(200, { 'Content-Type': 'text/text', 'cache-control': 'max-age=86400' });
            res.end(content);
        }
    } else if (clearUrl?.startsWith("/assets/")) {
        let pathRemaining = clearUrl.replace("/assets/", "");
        let file = `./client/assets/${path.normalize(pathRemaining)}`;
        if (!fs.existsSync(file)) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Not Found"));
            return;
        }
        let content = fs.readFileSync(file);
        if (file.endsWith(".html")) {
            res.writeHead(200, { 'Content-Type': 'text/html', 'cache-control': 'max-age=86400' });
            res.end(content);
        } else if (file.endsWith(".js")) {
            res.writeHead(200, { 'Content-Type': 'application/javascript', 'cache-control': 'max-age=86400' });
            res.end(content);
        } else if (file.endsWith(".css")) {
            res.writeHead(200, { 'Content-Type': 'text/css', 'cache-control': 'max-age=86400' });
            res.end(content);
        } else if (file.endsWith(".jpg")) {
            res.writeHead(200, { 'Content-Type': 'image/jpeg', 'cache-control': 'max-age=86400' });
            res.end(content);
        } else if (file.endsWith(".svg")) {
            res.writeHead(200, { 'Content-Type': 'image/svg+xml', 'cache-control': 'max-age=86400' });
            res.end(content);
        } else {
            res.writeHead(200, { 'Content-Type': 'text/text', 'cache-control': 'max-age=86400' });
            res.end(content);
        }
    } else if (clearUrl?.startsWith("/uploads/")) {
        let pathRemaining = decodeURIComponent(clearUrl.replace("/uploads/", ""))
        if (!pathRemaining.startsWith("~")) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Invalid file"));
            return;
        }
        pathRemaining = pathRemaining.substring(1)
        const files = fs.readdirSync('./uploads');
        let file = `./uploads/${files.find(f => f.startsWith(pathRemaining))}`;
        if (!fs.existsSync(file)) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Not Found"));
            return;
        }
        let content = fs.readFileSync(file);
        if (file.endsWith(".html")) {
            res.writeHead(200, { 'Content-Type': 'text/html', 'cache-control': 'max-age=86400' });
            res.end(content);
        } else if (file.endsWith(".js")) {
            res.writeHead(200, { 'Content-Type': 'application/javascript', 'cache-control': 'max-age=86400' });
            res.end(content);
        } else if (file.endsWith(".css")) {
            res.writeHead(200, { 'Content-Type': 'text/css', 'cache-control': 'max-age=86400' });
            res.end(content);
        } else if (file.endsWith(".jpg")) {
            res.writeHead(200, { 'Content-Type': 'image/jpeg', 'cache-control': 'max-age=86400' });
            res.end(content);
        } else if (file.endsWith(".svg")) {
            res.writeHead(200, { 'Content-Type': 'image/svg+xml', 'cache-control': 'max-age=86400' });
            res.end(content);
        } else {
            res.writeHead(200, { 'Content-Type': 'text/text', 'cache-control': 'max-age=86400' });
            res.end(content);
        }
    } else if (clearUrl == "/api/info" && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(sendResponse(true, {
            protocol: PROT_NAME,
            protocolVersion: PROT_VER,
            serverVersion: VER,
            serverName: SERV_NAME,
            limits: {
                maxFileSize: config.limits.maxFileSize,
                maxRequestsPerHour: config.limits.maxRequestsPerHour,
                maxRegistrationsPerHour: config.limits.maxRegistrationsPerHour,
                loginTriesPerHour: config.limits.loginTriesPerHour
            }
        }))
    } else if (clearUrl == "/api/register" && req.method === 'POST') {
        let body = '';
        req.on('data', async (data) => {
            body += data.toString();
        })
        req.on('end', async () => {
            let parsedBody: any;
            try {
                parsedBody = JSON.parse(body);
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid JSON"));
                return;
            }
            if (parsedBody.protocol != PROT_NAME) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unknown protocol"));
                return;
            }
            if (parsedBody.protocolVersion != PROT_VER) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unsupported protocol version"));
                return;
            }
            if (parsedBody.username == undefined || typeof parsedBody.username != "string" || parsedBody.username.length < 5 || parsedBody.username.length > 32 || !characterLimit(parsedBody.username)) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid username"));
                return;
            }
            if (parsedBody.password == undefined || typeof parsedBody.password != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid password"));
                return;
            }
            if (parsedBody.privateKey == undefined || typeof parsedBody.privateKey != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid private key"));
                return;
            }
            if (parsedBody.publicKey == undefined || typeof parsedBody.publicKey != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid public key"));
                return;
            }
            limits[ip].registers++;
            if (limits[ip].registers > config.limits.maxRegistrationsPerHour) {
                res.writeHead(429, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, {
                    resetDate: limits[ip].reset
                }, "Too many registrations. Please try again later."));
                return;
            }
            const collection = db.collection("users");
            let existingUser = await collection.findOne({ username: "@"+parsedBody.username });
            if (existingUser != null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Username already exists"));
                return;
            }
            let token: string;
            let check = 0
            while (true) {
                token = generateRandomString(256);
                let existingToken = await collection.findOne({ token: token });
                if (existingToken == null) {
                    break;
                }
                check++;
                if (check > 10) {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "Could not generate token, please try again later..."));
                    return;
                }
            }
            collection.insertOne({
                username: "@"+parsedBody.username,
                password: crypto.createHash('sha256').update(parsedBody.password).digest('hex'),
                privateKey: parsedBody.privateKey,
                publicKey: parsedBody.publicKey,
                bio: "",
                icon: "",
                createdAt: new Date(),
                lastLogin: new Date(),
                lastCommunication: new Date(),
                lastIP: ip,
                token: token,
                suspended: false
            })
            if (config.welcomeRoom != undefined && config.welcomeRoomKey != undefined && config.welcomeRoomIv != undefined && config.welcomeRoom.length > 0 && config.welcomeRoomKey.length > 0 && config.welcomeRoomIv.length > 0) {
                const roomCollection = db.collection("rooms");
                const membersCollection = db.collection("members");
                const keyCollection = db.collection("roomKeys");
                const room = await roomCollection.findOne({ id: config.welcomeRoom });
                if (room == null || room.deleted) {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(true, {
                        username: parsedBody.username,
                        token: token
                    }));
                    return
                }
                try {
                    let encryptedKey = crypto.publicEncrypt({
                        key: base64ToPem(parsedBody.publicKey),
                        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                        oaepHash: 'sha256'
                    }, Buffer.from(config.welcomeRoomKey, 'base64')).toString("base64");
                    let encryptedIv = crypto.publicEncrypt({
                        key: base64ToPem(parsedBody.publicKey),
                        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                        oaepHash: 'sha256'
                    }, Buffer.from(config.welcomeRoomIv, 'base64')).toString("base64");
                    membersCollection.insertOne({
                        user: "@"+parsedBody.username,
                        target: room.id,
                        nick: "",
                        role: "member",
                        joinedAt: new Date(),
                        accepted: false
                    })
                    keyCollection.insertOne({
                        user: "@"+parsedBody.username,
                        roomId: room.id,
                        key: encryptedKey,
                        iv: encryptedIv,
                        createdAt: new Date()
                    })
                } catch (e) {
                    console.error(`Failed to invite: ${'@'+parsedBody.username} to the welcome room! Error: ${e}`);
                }
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(sendResponse(true, {
                username: parsedBody.username,
                token: token
            }));
        })
    } else if (clearUrl == "/api/recover" && req.method === 'POST') {
        let body = '';
        req.on('data', async (data) => {
            body += data.toString();
        })
        req.on('end', async () => {
            let parsedBody: any;
            try {
                parsedBody = JSON.parse(body);
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid JSON"));
                return;
            }
            if (parsedBody.protocol != PROT_NAME) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unknown protocol"));
                return
            }
            if (parsedBody.protocolVersion != PROT_VER) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unsupported protocol version"));
                return;
            }
            if (parsedBody.token == undefined || typeof parsedBody.token != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            const collection = db.collection("users");
            const user = await collection.findOne({ token: parsedBody.token });
            if (user == null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (user.suspended) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is suspended"));
                return;
            }
            collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
            try {
                let keyVerifier = generateRandomString(32);
                let encryped = crypto.publicEncrypt({
                    key: base64ToPem(user.publicKey),
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: 'sha256'
                }, Buffer.from(keyVerifier));
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(sendResponse(true, {
                    username: user.username,
                    privateKey: user.privateKey,
                    publicKey: user.publicKey,
                    keyVerifier: keyVerifier,
                    encryptedKeyVerifier: encryped.toString('base64'),
                }));
            } catch (e) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Failed to encrypt key verifier"));
                return;
            }
        })
    } else if (clearUrl == "/api/login" && req.method === 'POST') {
        let body = '';
        req.on('data', async (data) => {
            body += data.toString();
        })
        req.on('end', async () => {
            let parsedBody: any;
            try {
                parsedBody = JSON.parse(body);
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid JSON"));
                return;
            }
            if (parsedBody.protocol != PROT_NAME) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unknown protocol"));
                return
            }
            if (parsedBody.protocolVersion != PROT_VER) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unsupported protocol version"));
                return;
            }
            if (parsedBody.username == undefined || typeof parsedBody.username != "string" || parsedBody.username.length < 5 || parsedBody.username.length > 32) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid username"));
                return;
            }
            if (parsedBody.password == undefined || typeof parsedBody.password != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid password"));
                return;
            }
            limits[ip].logins++;
            if (limits[ip].logins > config.limits.loginTriesPerHour) {
                res.writeHead(429, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, {
                    resetDate: limits[ip].reset
                }, "Too many login attempts. Please try again later."));
                return;
            }
            const collection = db.collection("users");
            const hashedPassword = crypto.createHash('sha256').update(parsedBody.password).digest('hex');
            const user = await collection.findOne({ username: "@"+parsedBody.username, password: hashedPassword });
            if (user == null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid username or password"));
                return;
            }
            if (user.suspended) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is suspended"));
                return;
            }
            collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
            try {
                let keyVerifier = generateRandomString(32);
                let encryped = crypto.publicEncrypt({
                    key: base64ToPem(user.publicKey),
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: 'sha256'
                }, Buffer.from(keyVerifier));
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(sendResponse(true, {
                    username: user.username,
                    token: user.token,
                    keyVerifier: keyVerifier,
                    encryptedKeyVerifier: encryped.toString('base64'),
                }));
            } catch (e) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Failed to encrypt key verifier"));
                return;
            }
        })
    } else if (clearUrl == "/api/room/create" && req.method === 'POST') {
        let body = '';
        req.on('data', async (data) => {
            body += data.toString();
        })
        req.on('end', async () => {
            let parsedBody: any;
            try {
                parsedBody = JSON.parse(body);
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid JSON"));
                return;
            }
            if (parsedBody.protocol != PROT_NAME) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unknown protocol"));
                return
            }
            if (parsedBody.protocolVersion != PROT_VER) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unsupported protocol version"));
                return;
            }
            if (parsedBody.token == undefined || typeof parsedBody.token != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (parsedBody.roomName == undefined || typeof parsedBody.roomName != "string" || parsedBody.roomName.length < 3 || parsedBody.roomName.length > 32 || !characterLimit(parsedBody.roomName)) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid room name"));
                return;
            }
            if (parsedBody.roomKey == undefined || typeof parsedBody.roomKey != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid room key"));
                return;
            }
            if (parsedBody.iv == undefined || typeof parsedBody.iv != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid IV"));
                return;
            }
            const collection = db.collection("users");
            const user = await collection.findOne({ token: parsedBody.token });
            if (user == null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (user.suspended) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is suspended"));
                return;
            }
            collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date() } })
            const roomsCollection = db.collection("rooms");
            const keyCollection = db.collection("roomKeys");
            const universesCollection = db.collection("universes");
            const membersCollection = db.collection("members");
            const roomId = "#"+ulid();
            if (args.universeId != undefined) {
                if (typeof args.universeId != "string" || !args.universeId.startsWith("&")) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "Invalid universe ID"));
                    return;
                }
                const universe = await universesCollection.findOne({ id: decodeURIComponent(args.universeId) });
                if (universe == null || universe.deleted) {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "Universe not found"));
                    return;
                }
                const member = await membersCollection.findOne({ user: user.username, target: universe.id });
                if (member == null) {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "User is not member of this universe"));
                    return;                    
                }
                if (member.role != "owner" && member.role != "admin") {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "Permission denied"));
                    return;
                }
                roomsCollection.insertOne({
                    id: roomId,
                    name: parsedBody.roomName,
                    owner: user.username,
                    createdAt: new Date(),
                    icon: "",
                    universeId: decodeURIComponent(args.universeId),
                    deleted: false
                })
                transmitUniverseUpdate(universe.id, JSON.stringify({
                    type: "roomCreated",
                    roomId: roomId,
                    roomName: parsedBody.roomName,
                    icon: null,
                    universeId: decodeURIComponent(args.universeId),
                    protocol: PROT_NAME,
                    protocolVersion: PROT_VER
                }))
            } else {
                roomsCollection.insertOne({
                    id: roomId,
                    name: parsedBody.roomName,
                    owner: user.username,
                    icon: "",
                    createdAt: new Date(),
                    universeId: "&0",
                    deleted: false
                })
                keyCollection.insertOne({
                    user: user.username,
                    roomId: roomId,
                    key: parsedBody.roomKey,
                    iv: parsedBody.iv,
                    createdAt: new Date()
                })
                membersCollection.insertOne({
                    user: user.username,
                    target: roomId,
                    nick: "",
                    role: "owner",
                    joinedAt: new Date(),
                    accepted: true
                })
                transmitToUser(user.username, JSON.stringify({
                    type: "roomCreated",
                    roomId: roomId,
                    roomName: parsedBody.roomName,
                    universeId: "&0",
                    protocol: PROT_NAME,
                    protocolVersion: PROT_VER
                }))
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(sendResponse(true, {
                roomId: roomId
            }));
        })
    } else if (clearUrl == "/api/room/getKey" && req.method == 'GET') {
        if (req.headers["protocol"] != PROT_NAME) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Unknown protocol"));
            return;
        }
        if (req.headers["protocol-version"] != PROT_VER) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Unsupported protocol version"));
            return;
        }
        if (args.roomId == undefined || typeof args.roomId != "string" || !args.roomId.startsWith("#")) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Invalid room ID"));
            return;
        }
        const collection = db.collection("users");
        const user = await collection.findOne({ token: req.headers["authorization"] });
        if (user == null) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Invalid token"));
            return;
        }
        if (user.suspended) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "User is suspended"));
            return;
        }
        collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
        const roomsCollection = db.collection("rooms");
        const membersCollection = db.collection("members");
        const room = await roomsCollection.findOne({ id: decodeURIComponent(args.roomId) });
        if (room == null || room.deleted) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Room not found"));
            return;
        }
        let key
        if (room.universeId != "&0") {
            const universesCollection = db.collection("universes");
            const universe = await universesCollection.findOne({ id: room.universeId });
            if (universe == null || universe.deleted) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Universe not found"));
                return;
            }
            const member = await membersCollection.findOne({ user: user.username, target: universe.id });
            if (member == null) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is not member of this universe"));
                return;                    
            }
            const keyCollection = db.collection("universeKeys");
            key = await keyCollection.findOne({ user: user.username, universeId: universe.id });
            if (key == null) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Universe key not found"));
                return;
            }
        } else {
            const member = await membersCollection.findOne({ user: user.username, target: room.id });
            if (member == null) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is not member of this room"));
                return;                    
            }
            const keyCollection = db.collection("roomKeys");
            key = await keyCollection.findOne({ user: user.username, roomId: args.roomId });
            if (key == null) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Room key not found"));
                return;
            }
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(sendResponse(true, {
            roomId: args.roomId,
            key: key.key,
            iv: key.iv
        }));
    } else if (clearUrl == "/api/room/sendMessage" && req.method === 'POST') {
        let body = '';
        req.on('data', async (data) => {
            body += data.toString();
        })
        req.on('end', async () => {
            let parsedBody: any;
            try {
                parsedBody = JSON.parse(body);
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid JSON"));
                return;
            }
            if (parsedBody.protocol != PROT_NAME) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unknown protocol"));
                return
            }
            if (parsedBody.protocolVersion != PROT_VER) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unsupported protocol version"));
                return;
            }
            if (parsedBody.token == undefined || typeof parsedBody.token != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (parsedBody.roomId == undefined || typeof parsedBody.roomId != "string" || !parsedBody.roomId.startsWith("#")) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid room ID"));
                return;
            }
            if (parsedBody.message == undefined || typeof parsedBody.message != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid message"));
                return;
            }
            if (limits[ip].messages > config.limits.messagesPerHour) {
                res.writeHead(429, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, {
                    resetDate: limits[ip].reset
                }, "Please don't spam."));
                return;
            }
            const collection = db.collection("users");
            const user = await collection.findOne({ token: parsedBody.token });
            if (user == null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (user.suspended) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is suspended"));
                return;
            }
            collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
            const roomsCollection = db.collection("rooms");
            const membersCollection = db.collection("members");
            const room = await roomsCollection.findOne({ id: parsedBody.roomId });
            if (room == null || room.deleted) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Room not found"));
                return;
            }
            if (room.universeId != "&0") {
                const universesCollection = db.collection("universes");
                const universe = await universesCollection.findOne({ id: room.universeId });
                if (universe == null || universe.deleted) {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "Universe not found"));
                    return;
                }
                const member = await membersCollection.findOne({ user: user.username, target: universe.id });
                if (member == null) {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "User is not member of this universe"));
                    return;                    
                }
            } else {
                const member = await membersCollection.findOne({ user: user.username, target: room.id });
                if (member == null) {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "User is not member of this room"));
                    return;                    
                }
            }
            const messagesCollection = db.collection("messages");
            let messageId = "$"+ulid();
            messagesCollection.insertOne({
                id: messageId,
                roomId: parsedBody.roomId,
                user: user.username,
                message: parsedBody.message,
                createdAt: new Date(),
                edits: [],
                deleted: false
            })
            transmitRoomUpdate(parsedBody.roomId, JSON.stringify({
                type: "message",
                roomId: parsedBody.roomId,
                id: messageId,
                user: user.username,
                message: parsedBody.message,
                createdAt: new Date(),
                edited: false,
                protocol: PROT_NAME,
                protocolVersion: PROT_VER
            }))
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(sendResponse(true, {
                messageId: messageId,
                roomId: parsedBody.roomId
            }));
        })
    } else if (clearUrl == "/api/room/editMessage" && req.method === 'POST') {
        let body = '';
        req.on('data', async (data) => {
            body += data.toString();
        })
        req.on('end', async () => {
            let parsedBody: any;
            try {
                parsedBody = JSON.parse(body);
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid JSON"));
                return;
            }
            if (parsedBody.protocol != PROT_NAME) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unknown protocol"));
                return
            }
            if (parsedBody.protocolVersion != PROT_VER) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unsupported protocol version"));
                return;
            }
            if (parsedBody.token == undefined || typeof parsedBody.token != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (parsedBody.roomId == undefined || typeof parsedBody.roomId != "string" || !parsedBody.roomId.startsWith("#")) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid room ID"));
                return;
            }
            if (parsedBody.messageId == undefined || typeof parsedBody.messageId != "string" || !parsedBody.messageId.startsWith("$")) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid message ID"));
                return;
            }
            if (parsedBody.message == undefined || typeof parsedBody.message != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid message"));
                return;
            }
            const collection = db.collection("users");
            const user = await collection.findOne({ token: parsedBody.token });
            if (user == null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (user.suspended) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is suspended"));
                return;
            }
            collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
            const roomsCollection = db.collection("rooms");
            const membersCollection = db.collection("members");
            const room = await roomsCollection.findOne({ id: parsedBody.roomId });
            if (room == null || room.deleted) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Room not found"));
                return;
            }
            const messagesCollection = db.collection("messages");
            const message = await messagesCollection.findOne({ id: parsedBody.messageId, roomId: parsedBody.roomId });
            if (message == null) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Message not found"));
                return;
            }
            if (room.universeId != "&0") {
                const universesCollection = db.collection("universes");
                const universe = await universesCollection.findOne({ id: room.universeId });
                if (universe == null || universe.deleted) {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "Universe not found"));
                    return;
                }
                const member = await membersCollection.findOne({ user: user.username, target: universe.id });
                if (member == null) {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "User is not member of this universe"));
                    return;                    
                }
                if (member.role != "owner" && member.role != "admin" && member.role != "moderator" && message.user != user.username) {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "Permission denied"));
                    return;
                }
            } else {
                const member = await membersCollection.findOne({ user: user.username, target: room.id });
                if (member == null) {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "User is not member of this room"));
                    return;                    
                }
                if (member.role != "owner" && member.role != "admin" && member.role != "moderator" && message.user != user.username) {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "Permission denied"));
                    return;
                }
            }
            messagesCollection.updateOne({ id: message.id }, { $set: { message: parsedBody.message }, $addToSet: { edits: message.message } })
            transmitRoomUpdate(parsedBody.roomId, JSON.stringify({
                type: "messageUpdate",
                roomId: parsedBody.roomId,
                id: message.id,
                message: parsedBody.message,
                edited: true,
                protocol: PROT_NAME,
                protocolVersion: PROT_VER
            }))
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(sendResponse(true, {
                messageId: parsedBody.messageId,
                roomId: parsedBody.roomId
            }));
        })
    } else if (clearUrl == "/api/room/deleteMessage" && req.method === 'POST') {
        let body = '';
        req.on('data', async (data) => {
            body += data.toString();
        })
        req.on('end', async () => {
            let parsedBody: any;
            try {
                parsedBody = JSON.parse(body);
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid JSON"));
                return;
            }
            if (parsedBody.protocol != PROT_NAME) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unknown protocol"));
                return
            }
            if (parsedBody.protocolVersion != PROT_VER) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unsupported protocol version"));
                return;
            }
            if (parsedBody.token == undefined || typeof parsedBody.token != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (parsedBody.roomId == undefined || typeof parsedBody.roomId != "string" || !parsedBody.roomId.startsWith("#")) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid room ID"));
                return;
            }
            if (parsedBody.messageId == undefined || typeof parsedBody.messageId != "string" || !parsedBody.messageId.startsWith("$")) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid message ID"));
                return;
            }
            const collection = db.collection("users");
            const user = await collection.findOne({ token: parsedBody.token });
            if (user == null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (user.suspended) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is suspended"));
                return;
            }
            collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
            const roomsCollection = db.collection("rooms");
            const membersCollection = db.collection("members");
            const room = await roomsCollection.findOne({ id: parsedBody.roomId });
            if (room == null || room.deleted) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Room not found"));
                return;
            }
            const messagesCollection = db.collection("messages");
            const message = await messagesCollection.findOne({ id: parsedBody.messageId, roomId: parsedBody.roomId });
            if (message == null) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Message not found"));
                return;
            }
            if (room.universeId != "&0") {
                const universesCollection = db.collection("universes");
                const universe = await universesCollection.findOne({ id: room.universeId });
                if (universe == null || universe.deleted) {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "Universe not found"));
                    return;
                }
                const member = await membersCollection.findOne({ user: user.username, target: universe.id });
                if (member == null) {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "User is not member of this universe"));
                    return;                    
                }
                if (member.role != "owner" && member.role != "admin" && member.role != "moderator" && message.user != user.username) {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "Permission denied"));
                    return;
                }
            } else {
                const member = await membersCollection.findOne({ user: user.username, target: room.id });
                if (member == null) {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "User is not member of this room"));
                    return;                    
                }
                if (member.role != "owner" && member.role != "admin" && member.role != "moderator" && message.user != user.username) {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "Permission denied"));
                    return;
                }
            }
            messagesCollection.updateOne({ id: message.id }, { $set: { deleted: true } })
            transmitRoomUpdate(parsedBody.roomId, JSON.stringify({
                type: "messageDelete",
                roomId: parsedBody.roomId,
                id: message.id,
                protocol: PROT_NAME,
                protocolVersion: PROT_VER
            }))
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(sendResponse(true, {
                messageId: parsedBody.messageId,
                roomId: parsedBody.roomId
            }));
        })
    } else if (clearUrl == "/api/room/readMessages" && req.method == 'GET') {
        if (req.headers["protocol"] != PROT_NAME) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Unknown protocol"));
            return;
        }
        if (req.headers["protocol-version"] != PROT_VER) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Unsupported protocol version"));
            return;
        }
        if (args.roomId == undefined || typeof args.roomId != "string" || !args.roomId.startsWith("#")) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Invalid room ID"));
            return;
        }
        const collection = db.collection("users");
        const user = await collection.findOne({ token: req.headers["authorization"] });
        if (user == null) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Invalid token"));
            return;
        }
        if (user.suspended) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "User is suspended"));
            return;
        }
        collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
        const roomsCollection = db.collection("rooms");
        const membersCollection = db.collection("members");
        const room = await roomsCollection.findOne({ id: decodeURIComponent(args.roomId) });
        if (room == null || room.deleted) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Room not found"));
            return;
        }
        if (room.universeId != "&0") {
            const universesCollection = db.collection("universes");
            const universe = await universesCollection.findOne({ id: room.universeId });
            if (universe == null || universe.deleted) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Universe not found"));
                return;
            }
            const member = await membersCollection.findOne({ user: user.username, target: universe.id });
            if (member == null) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is not member of this universe"));
                return;                    
            }
        } else {
            const member = await membersCollection.findOne({ user: user.username, target: room.id });
            if (member == null) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is not member of this room"));
                return;                    
            }
        }
        const messagesCollection = db.collection("messages");
        const messages = await messagesCollection.find({ roomId: decodeURIComponent(args.roomId) }).toArray();
        let resMessages: any[] = []
        for (let i = 0; i < messages.length; i++) {
            if (messages[i].deleted) {
                continue;
            }
            resMessages.push({
                id: messages[i].id,
                user: messages[i].user,
                message: messages[i].message,
                createdAt: messages[i].createdAt,
                edited: messages[i].edits.length > 0
            });
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(sendResponse(true, {
            roomId: args.roomId,
            messages: resMessages
        }));
    } else if (clearUrl == "/api/user/getKey" && req.method == 'GET') {
        if (req.headers["protocol"] != PROT_NAME) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Unknown protocol"));
            return;
        }
        if (req.headers["protocol-version"] != PROT_VER) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Unsupported protocol version"));
            return;
        }
        if (args.username == undefined || typeof args.username != "string" || args.username.length < 5 || args.username.length > 32 || !args.username.startsWith("@")) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Invalid username"));
            return;
        }
        const collection = db.collection("users");
        const user = await collection.findOne({ token: req.headers["authorization"] });
        if (user == null) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Invalid token"));
            return;
        }
        if (user.suspended) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "User is suspended"));
            return;
        }
        collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
        const targetUser = await collection.findOne({ username: decodeURIComponent(args.username) });
        if (targetUser == null) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "User not found"));
            return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(sendResponse(true, {
            username: targetUser.username,
            publicKey: targetUser.publicKey
        }));
    } else if (clearUrl == "/api/room/invite" && req.method === 'POST') {
        let body = '';
        req.on('data', async (data) => {
            body += data.toString();
        })
        req.on('end', async () => {
            let parsedBody: any;
            try {
                parsedBody = JSON.parse(body);
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid JSON"));
                return;
            }
            if (parsedBody.protocol != PROT_NAME) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unknown protocol"));
                return
            }
            if (parsedBody.protocolVersion != PROT_VER) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unsupported protocol version"));
                return;
            }
            if (parsedBody.token == undefined || typeof parsedBody.token != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (parsedBody.roomId == undefined || typeof parsedBody.roomId != "string" || !parsedBody.roomId.startsWith("#")) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid room ID"));
                return;
            }
            if (parsedBody.username == undefined || typeof parsedBody.username != "string" || parsedBody.username.length < 5 || parsedBody.username.length > 32 || !parsedBody.username.startsWith("@")) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid username"));
                return;
            }
            if (parsedBody.key == undefined || typeof parsedBody.key != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid key"));
                return;
            }
            if (parsedBody.iv == undefined || typeof parsedBody.iv != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid IV"));
                return;
            }
            const collection = db.collection("users");
            const user = await collection.findOne({ token: parsedBody.token });
            if (user == null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (user.suspended) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is suspended"));
                return;
            }
            collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
            const targetUser = await collection.findOne({ username: parsedBody.username });
            if (targetUser == null) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User not found"));
                return;
            }
            const roomsCollection = db.collection("rooms");
            const membersCollection = db.collection("members");
            let room = await roomsCollection.findOne({ id: parsedBody.roomId });
            if (room == null || room.deleted) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Room not found"));
                return;
            }
            if (room.universeId != "&0") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unable to invite users to universe rooms, use /api/universe/invite instead"));
                return;
            }
            const member = await membersCollection.findOne({ user: user.username, target: room.id });
            if (member == null) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is not member of this room"));
                return;                    
            }
            const targetMember = await membersCollection.findOne({ user: targetUser.username, target: room.id });
            if (targetMember != null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is already member of this room"));
                return;
            }
            membersCollection.insertOne({
                user: targetUser.username,
                target: room.id,
                nick: "",
                role: "member",
                joinedAt: new Date(),
                accepted: false
            })
            const keyCollection = db.collection("roomKeys");
            keyCollection.insertOne({
                user: targetUser.username,
                roomId: parsedBody.roomId,
                key: parsedBody.key,
                iv: parsedBody.iv,
                createdAt: new Date()
            })
            if (room.icon == undefined || room.icon.length == 0) {
                room.icon = null
            }
            transmitToUser(targetUser.username, JSON.stringify({
                type: "roomInvite",
                roomId: parsedBody.roomId,
                roomName: room.name,
                icon: room.icon,
                protocol: PROT_NAME,
                protocolVersion: PROT_VER
            }))
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(sendResponse(true, {
                roomId: parsedBody.roomId,
                username: targetUser.username
            }));
        })
    } else if (clearUrl == "/api/me" && req.method == 'GET') {
        if (req.headers["protocol"] != PROT_NAME) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Unknown protocol"));
            return;
        }
        if (req.headers["protocol-version"] != PROT_VER) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Unsupported protocol version"));
            return;
        }
        const collection = db.collection("users");
        let user = await collection.findOne({ token: req.headers["authorization"] });
        if (user == null) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Invalid token"));
            return;
        }
        if (user.suspended) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "User is suspended"));
            return;
        }
        collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
        res.writeHead(200, { 'Content-Type': 'application/json' });
        if (user.icon == undefined || user.icon.length == 0) {
            user.icon = null
        }
        if (user.bio == undefined || user.bio.length == 0) {
            user.bio = null
        }
        res.end(sendResponse(true, {
            username: user.username,
            createdAt: user.createdAt,
            bio: user.bio,
            icon: user.icon
        }));
    } else if (clearUrl == "/api/rooms" && req.method == 'GET') {
        if (req.headers["protocol"] != PROT_NAME) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Unknown protocol"));
            return;
        }
        if (req.headers["protocol-version"] != PROT_VER) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Unsupported protocol version"));
            return;
        }
        const collection = db.collection("users");
        const user = await collection.findOne({ token: req.headers["authorization"] });
        if (user == null) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Invalid token"));
            return;
        }
        if (user.suspended) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "User is suspended"));
            return;
        }
        collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
        const roomsCollection = db.collection("rooms");
        const membersCollection = db.collection("members");
        let rooms
        if (args.universeId != undefined) {
            if (typeof args.universeId != "string" || !args.universeId.startsWith("&")) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid universe ID"));
                return;
            }
            const member = await membersCollection.findOne({ user: user.username, target: decodeURIComponent(args.universeId) });
            if (member == null) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is not member of this universe"));
                return;                    
            }
            rooms = await roomsCollection.find({ universeId: decodeURIComponent(args.universeId) }).toArray();
        } else {
            const roomIds = await membersCollection.find({ user: user.username }).toArray();
            rooms = []
            for (let i = 0; i < roomIds.length; i++) {
                if (roomIds[i].target.startsWith("#")) {
                    let room = await roomsCollection.findOne({ id: roomIds[i].target });
                    if (room != null) {
                        room.inviteAccepted = roomIds[i].accepted;
                        rooms.push(room);
                    }
                }
            }
        }
        let resRooms: any[] = [];
        for (let i = 0; i < rooms.length; i++) {
            if (rooms[i].deleted) {
                continue;
            }
            if (rooms[i].icon == undefined || rooms[i].icon.length == 0) {
                rooms[i].icon = null
            }
            resRooms.push({
                id: rooms[i].id,
                name: rooms[i].name,
                owner: rooms[i].owner,
                icon: rooms[i].icon,
                createdAt: rooms[i].createdAt,
                inviteAccepted: rooms[i].inviteAccepted || false,
            });
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(sendResponse(true, resRooms));
    } else if (clearUrl == "/api/room/info" && req.method == 'GET') {
        if (req.headers["protocol"] != PROT_NAME) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Unknown protocol"));
            return;
        }
        if (req.headers["protocol-version"] != PROT_VER) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Unsupported protocol version"));
            return;
        }
        if (args.roomId == undefined || typeof args.roomId != "string" || !args.roomId.startsWith("#")) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Invalid room ID"));
            return;
        }
        const collection = db.collection("users");
        const user = await collection.findOne({ token: req.headers["authorization"] });
        if (user == null) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Invalid token"));
            return;
        }
        if (user.suspended) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "User is suspended"));
            return;
        }
        collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
        const roomsCollection = db.collection("rooms");
        const membersCollection = db.collection("members");
        let room = await roomsCollection.findOne({ id: decodeURIComponent(args.roomId) });
        if (room == null || room.deleted) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Room not found"));
            return;
        }
        let members
        let inviteAccepted = false;
        if (room.universeId != "&0") {
            const universesCollection = db.collection("universes");
            const universe = await universesCollection.findOne({ id: room.universeId });
            if (universe == null || universe.deleted) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Universe not found"));
                return;
            }
            const member = await membersCollection.findOne({ user: user.username, target: universe.id });
            if (member == null) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is not member of this universe"));
                return;                    
            }
            inviteAccepted = member.accepted;
            members = await membersCollection.find({ target: universe.id }).toArray();
        } else {
            const member = await membersCollection.findOne({ user: user.username, target: room.id });
            if (member == null) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is not member of this room"));
                return;                    
            }
            inviteAccepted = member.accepted;
            members = await membersCollection.find({ target: room.id }).toArray();
        }
        let resMembers: any[] = [];
        for (let i = 0; i < members.length; i++) {
            resMembers.push({
                user: members[i].user,
                nick: members[i].nick,
                role: members[i].role,
                joinedAt: members[i].joinedAt
            });
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        if (room.icon == undefined || room.icon.length == 0) {
            room.icon = null
        }
        res.end(sendResponse(true, {
            id: room.id,
            name: room.name,
            owner: room.owner,
            icon: room.icon,
            createdAt: room.createdAt,
            universeId: room.universeId,
            members: resMembers,
            inviteAccepted: inviteAccepted
        }));
    } else if (clearUrl == "/api/universes" && req.method == 'GET') {
        if (req.headers["protocol"] != PROT_NAME) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Unknown protocol"));
            return;
        }
        if (req.headers["protocol-version"] != PROT_VER) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Unsupported protocol version"));
            return;
        }
        const collection = db.collection("users");
        const user = await collection.findOne({ token: req.headers["authorization"] });
        if (user == null) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Invalid token"));
            return;
        }
        if (user.suspended) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "User is suspended"));
            return;
        }
        collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
        const universesCollection = db.collection("universes");
        const membersCollection = db.collection("members");
        let universes: any[] = []
        const universeIds = await membersCollection.find({ user: user.username }).toArray();
        for (let i = 0; i < universeIds.length; i++) {
            if (universeIds[i].target.startsWith("&")) {
                let universe = await universesCollection.findOne({ id: universeIds[i].target });
                if (universe != null) {
                    universe.inviteAccepted = universeIds[i].accepted;
                    universes.push(universe);
                }
            }
        }
        let resUniverses: any[] = [];
        for (let i = 0; i < universes.length; i++) {
            if (universes[i].deleted) {
                continue;
            }
            if (universes[i].icon == undefined || universes[i].icon.length == 0) {
                universes[i].icon = null
            }
            resUniverses.push({
                id: universes[i].id,
                name: universes[i].name,
                owner: universes[i].owner,
                icon: universes[i].icon,
                createdAt: universes[i].createdAt,
                inviteAccepted: universes[i].inviteAccepted || false
            });
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(sendResponse(true, resUniverses));
    } else if (clearUrl == "/api/universe/create" && req.method === 'POST') {
        let body = '';
        req.on('data', async (data) => {
            body += data.toString();
        })
        req.on('end', async () => {
            let parsedBody: any;
            try {
                parsedBody = JSON.parse(body);
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid JSON"));
                return;
            }
            if (parsedBody.protocol != PROT_NAME) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unknown protocol"));
                return
            }
            if (parsedBody.protocolVersion != PROT_VER) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unsupported protocol version"));
                return;
            }
            if (parsedBody.token == undefined || typeof parsedBody.token != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (parsedBody.universeName == undefined || typeof parsedBody.universeName != "string" || parsedBody.universeName.length < 3 || parsedBody.universeName.length > 32 || !characterLimit(parsedBody.universeName)) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid universe name"));
                return;
            }
            if (parsedBody.universeKey == undefined || typeof parsedBody.universeKey != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid universe key"));
                return;
            }
            if (parsedBody.iv == undefined || typeof parsedBody.iv != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid IV"));
                return;
            }
            const collection = db.collection("users");
            const user = await collection.findOne({ token: parsedBody.token });
            if (user == null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (user.suspended) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is suspended"));
                return;
            }
            collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
            const universesCollection = db.collection("universes");
            const keyCollection = db.collection("universeKeys");
            const membersCollection = db.collection("members");
            const universeId = "&"+ulid();
            universesCollection.insertOne({
                id: universeId,
                name: parsedBody.universeName,
                owner: user.username,
                icon: "",
                createdAt: new Date(),
                deleted: false
            })
            keyCollection.insertOne({
                user: user.username,
                universeId: universeId,
                key: parsedBody.universeKey,
                iv: parsedBody.iv,
                createdAt: new Date()
            })
            membersCollection.insertOne({
                user: user.username,
                target: universeId,
                nick: "",
                role: "owner",
                joinedAt: new Date(),
                accepted: true
            })
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(sendResponse(true, {
                universeId: universeId
            }));
        })
    } else if (clearUrl == "/api/universe/invite" && req.method === 'POST') {
        let body = '';
        req.on('data', async (data) => {
            body += data.toString();
        })
        req.on('end', async () => {
            let parsedBody: any;
            try {
                parsedBody = JSON.parse(body);
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid JSON"));
                return;
            }
            if (parsedBody.protocol != PROT_NAME) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unknown protocol"));
                return
            }
            if (parsedBody.protocolVersion != PROT_VER) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unsupported protocol version"));
                return;
            }
            if (parsedBody.token == undefined || typeof parsedBody.token != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (parsedBody.universeId == undefined || typeof parsedBody.universeId != "string" || !parsedBody.universeId.startsWith("&")) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid universe ID"));
                return;
            }
            if (parsedBody.username == undefined || typeof parsedBody.username != "string" || parsedBody.username.length < 5 || parsedBody.username.length > 32 || !parsedBody.username.startsWith("@")) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid username"));
                return;
            }
            if (parsedBody.key == undefined || typeof parsedBody.key != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid key"));
                return;
            }
            if (parsedBody.iv == undefined || typeof parsedBody.iv != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid IV"));
                return;
            }
            const collection = db.collection("users");
            const user = await collection.findOne({ token: parsedBody.token });
            if (user == null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (user.suspended) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is suspended"));
                return;
            }
            collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
            const targetUser = await collection.findOne({ username: parsedBody.username });
            if (targetUser == null) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User not found"));
                return;
            }
            const universesCollection = db.collection("universes");
            const membersCollection = db.collection("members");
            let universe = await universesCollection.findOne({ id: parsedBody.universeId });
            if (universe == null || universe.deleted) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Universe not found"));
                return;
            }
            const member = await membersCollection.findOne({ user: user.username, target: universe.id });
            if (member == null) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is not member of this universe"));
                return;                    
            }
            const targetMember = await membersCollection.findOne({ user: targetUser.username, target: universe.id });
            if (targetMember != null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is already member of this universe"));
                return;
            }
            const keyCollection = db.collection("universeKeys");
            membersCollection.insertOne({
                user: targetUser.username,
                target: universe.id,
                nick: "",
                role: "member",
                joinedAt: new Date(),
                accepted: false
            })
            keyCollection.insertOne({
                user: targetUser.username,
                universeId: parsedBody.universeId,
                key: parsedBody.key,
                iv: parsedBody.iv,
                createdAt: new Date()
            })
            if (universe.icon == undefined || universe.icon.length == 0) {
                universe.icon = null
            }
            transmitToUser(targetUser.username, JSON.stringify({
                type: "universeInvite",
                universeId: parsedBody.universeId,
                universeName: universe.name,
                icon: universe.icon,
                protocol: PROT_NAME,
                protocolVersion: PROT_VER
            }))
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(sendResponse(true, {
                universeId: parsedBody.universeId,
                username: targetUser.username
            }));
        })
    } else if (clearUrl == "/api/reset" && req.method === 'POST') {
        let body = '';
        req.on('data', async (data) => {
            body += data.toString();
        })
        req.on('end', async () => {
            let parsedBody: any;
            try {
                parsedBody = JSON.parse(body);
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid JSON"));
                return;
            }
            if (parsedBody.protocol != PROT_NAME) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unknown protocol"));
                return;
            }
            if (parsedBody.protocolVersion != PROT_VER) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unsupported protocol version"));
                return;
            }
            if (parsedBody.token == undefined || typeof parsedBody.token != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (parsedBody.privateKey == undefined || typeof parsedBody.privateKey != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid private key"));
                return;
            }
            if (parsedBody.publicKey == undefined || typeof parsedBody.publicKey != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid public key"));
                return;
            }
            const collection = db.collection("users");
            const user = await collection.findOne({ token: parsedBody.token });
            if (user == null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (user.suspended) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is suspended"));
                return;
            }
            collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
            let token: string;
            let check = 0
            while (true) {
                token = generateRandomString(256);
                let existingToken = await collection.findOne({ token: token });
                if (existingToken == null) {
                    break;
                }
                check++;
                if (check > 10) {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "Could not generate token, please try again later..."));
                    return;
                }
            }
            collection.updateOne({ token: user.token }, {
                $set: {
                    lastCommunication: new Date(),
                    lastIP: ip,
                    token: token,
                    privateKey: parsedBody.privateKey,
                    publicKey: parsedBody.publicKey
                }
            })
            const keyCollection = db.collection("roomKeys");
            const membersCollection = db.collection("members");
            const universeKeysCollection = db.collection("universeKeys");
            await membersCollection.deleteMany({ user: user.username });
            await keyCollection.deleteMany({ user: user.username });
            await universeKeysCollection.deleteMany({ user: user.username });
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(sendResponse(true, {
                username: parsedBody.username,
                token: token
            }));
        })
    } else if (clearUrl == "/api/user/info" && req.method == 'GET') {
        if (req.headers["protocol"] != PROT_NAME) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Unknown protocol"));
            return;
        }
        if (req.headers["protocol-version"] != PROT_VER) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Unsupported protocol version"));
            return;
        }
        if (args.username == undefined || typeof args.username != "string" || !args.username.startsWith("@")) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Invalid username"));
            return;
        }
        const collection = db.collection("users");
        const user = await collection.findOne({ token: req.headers["authorization"] });
        if (user == null) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Invalid token"));
            return;
        }
        if (user.suspended) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "User is suspended"));
            return;
        }
        collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
        let targetUser = await collection.findOne({ username: decodeURIComponent(args.username) });
        if (targetUser == null) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "User not found"));
            return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        if (targetUser.icon == undefined || targetUser.icon.length == 0) {
            targetUser.icon = null
        }
        if (targetUser.bio == undefined || targetUser.bio.length == 0) {
            targetUser.bio = null
        }
        res.end(sendResponse(true, {
            username: targetUser.username,
            createdAt: targetUser.createdAt,
            bio: targetUser.bio,
            icon: targetUser.icon,
        }));
    } else if (clearUrl == "/api/user/update" && req.method == 'POST') {
        let body = '';
        req.on('data', async (data) => {
            body += data.toString();
        })
        req.on('end', async () => {
            let parsedBody: any;
            try {
                parsedBody = JSON.parse(body);
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid JSON"));
                return;
            }
            if (parsedBody.protocol != PROT_NAME) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unknown protocol"));
                return;
            }
            if (parsedBody.protocolVersion != PROT_VER) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unsupported protocol version"));
                return;
            }
            if (parsedBody.token == undefined || typeof parsedBody.token != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (parsedBody.bio == undefined || typeof parsedBody.bio != "string" || parsedBody.bio.length > 256) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid bio"));
                return;
            }
            const collection = db.collection("users");
            const user = await collection.findOne({ token: parsedBody.token });
            if (user == null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (user.suspended) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is suspended"));
                return;
            }
            if (parsedBody.icon == undefined || typeof parsedBody.icon != "string" || !parsedBody.icon.startsWith("~")) {
                collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip, bio: parsedBody.bio } })   
            } else {
                collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip, bio: parsedBody.bio, icon: parsedBody.icon } })
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(sendResponse(true, {
                username: user.username,
                createdAt: user.createdAt,
                bio: user.bio,
                icon: user.icon
            }));
        })
    } else if (clearUrl == "/api/room/update" && req.method == 'POST') {
        let body = '';
        req.on('data', async (data) => {
            body += data.toString();
        })
        req.on('end', async () => {
            let parsedBody: any;
            try {
                parsedBody = JSON.parse(body);
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid JSON"));
                return;
            }
            if (parsedBody.protocol != PROT_NAME) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unknown protocol"));
                return;
            }
            if (parsedBody.protocolVersion != PROT_VER) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unsupported protocol version"));
                return;
            }
            if (parsedBody.token == undefined || typeof parsedBody.token != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (parsedBody.roomId == undefined || typeof parsedBody.roomId != "string" || !parsedBody.roomId.startsWith("#")) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid room ID"));
                return;
            }
            if (parsedBody.roomName == undefined || typeof parsedBody.roomName != "string" || parsedBody.roomName.length < 3 || parsedBody.roomName.length > 32 || !characterLimit(parsedBody.roomName)) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid room name"));
                return;
            }
            const collection = db.collection("users");
            const user = await collection.findOne({ token: parsedBody.token });
            if (user == null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (user.suspended) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is suspended"));
                return;
            }
            collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
            const roomsCollection = db.collection("rooms");
            const membersCollection = db.collection("members");
            const room = await roomsCollection.findOne({ id: parsedBody.roomId });
            if (room == null || room.deleted) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Room not found"));
                return;
            }
            if (room.universeId != "&0") {
                const universesCollection = db.collection("universes");
                const universe = await universesCollection.findOne({ id: room.universeId });
                if (universe == null || universe.deleted) {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "Universe not found"));
                    return;
                }
                const member = await membersCollection.findOne({ user: user.username, target: universe.id });
                if (member == null) {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "User is not member of this universe"));
                    return;
                }
                if (member.role != "owner" && member.role != "admin") {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "Permission denied"));
                    return;
                }
            } else {
                const member = await membersCollection.findOne({ user: user.username, target: room.id });
                if (member == null) {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "User is not member of this room"));
                    return;                    
                }
                if (member.role != "owner") {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "Permission denied"));
                    return;
                }
            }
            if (parsedBody.icon == undefined || typeof parsedBody.icon != "string" || !parsedBody.icon.startsWith("~")) {
                roomsCollection.updateOne({ id: room.id }, { $set: { name: parsedBody.roomName } })
            } else {
                roomsCollection.updateOne({ id: room.id }, { $set: { name: parsedBody.roomName, icon: parsedBody.icon } })
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(sendResponse(true, {
                roomId: room.id,
                roomName: room.name,
                icon: room.icon
            }));
            transmitRoomUpdate(room.id, JSON.stringify({
                type: "roomUpdate",
                roomId: room.id,
                roomName: parsedBody.roomName,
                icon: parsedBody.icon || room.icon,
                universeId: room.universeId,
                protocol: PROT_NAME,
                protocolVersion: PROT_VER
            }))
        })
    } else if (clearUrl == "/api/room/delete" && req.method == 'POST') {
        let body = '';
        req.on('data', async (data) => {
            body += data.toString();
        })
        req.on('end', async () => {
            let parsedBody: any;
            try {
                parsedBody = JSON.parse(body);
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid JSON"));
                return;
            }
            if (parsedBody.protocol != PROT_NAME) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unknown protocol"));
                return;
            }
            if (parsedBody.protocolVersion != PROT_VER) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unsupported protocol version"));
                return;
            }
            if (parsedBody.token == undefined || typeof parsedBody.token != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (parsedBody.roomId == undefined || typeof parsedBody.roomId != "string" || !parsedBody.roomId.startsWith("#")) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid room ID"));
                return;
            }
            const collection = db.collection("users");
            const user = await collection.findOne({ token: parsedBody.token });
            if (user == null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (user.suspended) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is suspended"));
                return;
            }
            collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
            const roomsCollection = db.collection("rooms");
            const membersCollection = db.collection("members");
            const room = await roomsCollection.findOne({ id: parsedBody.roomId });
            if (room == null || room.deleted) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Room not found"));
                return;
            }
            if (room.universeId != "&0") {
                const universesCollection = db.collection("universes");
                const universe = await universesCollection.findOne({ id: room.universeId });
                if (universe == null || universe.deleted) {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "Universe not found"));
                    return;
                }
                const member = await membersCollection.findOne({ user: user.username, target: universe.id });
                if (member == null) {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "User is not member of this universe"));
                    return;                    
                }
                if (member.role != "admin" && member.role != "owner") {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "Permission denied"));
                    return;
                }
            } else {
                const member = await membersCollection.findOne({ user: user.username, target: room.id });
                if (member == null) {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "User is not member of this room"));
                    return;                    
                }
                if (member.role != "owner") {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "Permission denied"));
                    return;
                }
            }
            await transmitRoomUpdate(room.id, JSON.stringify({
                type: "roomDelete",
                roomId: room.id,
                universeId: room.universeId,
                protocol: PROT_NAME,
                protocolVersion: PROT_VER
            }))
            const keyCollection = db.collection("roomKeys");
            roomsCollection.updateOne({ id: room.id }, { $set: { deleted: true } })
            if (room.universeId == "&0") {
                keyCollection.deleteMany({ roomId: room.id });
                membersCollection.deleteMany({ target: room.id });
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(sendResponse(true, {
                roomId: room.id
            }));
        })
    } else if (clearUrl == "/api/universe/update" && req.method == 'POST') {
        let body = '';
        req.on('data', async (data) => {
            body += data.toString();
        })
        req.on('end', async () => {
            let parsedBody: any;
            try {
                parsedBody = JSON.parse(body);
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid JSON"));
                return;
            }
            if (parsedBody.protocol != PROT_NAME) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unknown protocol"));
                return;
            }
            if (parsedBody.protocolVersion != PROT_VER) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unsupported protocol version"));
                return;
            }
            if (parsedBody.token == undefined || typeof parsedBody.token != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (parsedBody.universeId == undefined || typeof parsedBody.universeId != "string" || !parsedBody.universeId.startsWith("&")) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid universe ID"));
                return;
            }
            if (parsedBody.universeName == undefined || typeof parsedBody.universeName != "string" || parsedBody.universeName.length < 3 || parsedBody.universeName.length > 32 || !characterLimit(parsedBody.universeName)) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid universe name"));
                return;
            }
            const collection = db.collection("users");
            const user = await collection.findOne({ token: parsedBody.token });
            if (user == null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (user.suspended) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is suspended"));
                return;
            }
            collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
            const universesCollection = db.collection("universes");
            const membersCollection = db.collection("members");
            const universe = await universesCollection.findOne({ id: parsedBody.universeId });
            if (universe == null || universe.deleted) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Universe not found"));
                return;
            }
            const member = await membersCollection.findOne({ user: user.username, target: universe.id });
            if (member == null) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is not member of this universe"));
                return;                    
            }
            if (member.role != "admin" && member.role != "owner") {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Permission denied"));
                return;
            }
            if (parsedBody.icon == undefined || typeof parsedBody.icon != "string" || !parsedBody.icon.startsWith("~")) {
                universesCollection.updateOne({ id: universe.id }, { $set: { name: parsedBody.universeName } })
            } else {
                universesCollection.updateOne({ id: universe.id }, { $set: { name: parsedBody.universeName, icon: parsedBody.icon } })
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(sendResponse(true, {
                universeId: universe.id,
                universeName: universe.name,
                icon: universe.icon
            }));
            transmitUniverseUpdate(universe.id, JSON.stringify({
                type: "universeUpdate",
                universeId: universe.id,
                universeName: parsedBody.universeName,
                icon: parsedBody.icon || universe.icon,
                protocol: PROT_NAME,
                protocolVersion: PROT_VER
            }))
        })
    } else if (clearUrl == "/api/universe/delete" && req.method == 'POST') {
        let body = '';
        req.on('data', async (data) => {
            body += data.toString();
        })
        req.on('end', async () => {
            let parsedBody: any;
            try {
                parsedBody = JSON.parse(body);
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid JSON"));
                return;
            }
            if (parsedBody.protocol != PROT_NAME) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unknown protocol"));
                return;
            }
            if (parsedBody.protocolVersion != PROT_VER) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unsupported protocol version"));
                return;
            }
            if (parsedBody.token == undefined || typeof parsedBody.token != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (parsedBody.universeId == undefined || typeof parsedBody.universeId != "string" || !parsedBody.universeId.startsWith("&")) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid universe ID"));
                return;
            }
            const collection = db.collection("users");
            const user = await collection.findOne({ token: parsedBody.token });
            if (user == null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (user.suspended) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is suspended"));
                return;
            }
            collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
            const universesCollection = db.collection("universes");
            const membersCollection = db.collection("members");
            const universe = await universesCollection.findOne({ id: parsedBody.universeId });
            if (universe == null || universe.deleted) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Universe not found"));
                return;
            }
            const member = await membersCollection.findOne({ user: user.username, target: universe.id });
            if (member == null) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is not member of this universe"));
                return;                    
            }
            if (member.role != "owner") {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Permission denied"));
                return;
            }
            await transmitUniverseUpdate(universe.id, JSON.stringify({
                type: "universeDelete",
                universeId: universe.id,
                protocol: PROT_NAME,
                protocolVersion: PROT_VER
            }))
            const keyCollection = db.collection("universeKeys");
            universesCollection.updateOne({ id: universe.id }, { $set: { deleted: true } })
            keyCollection.deleteMany({ universeId: universe.id });
            membersCollection.deleteMany({ target: universe.id });
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(sendResponse(true, {
                universeId: universe.id
            }));
        })
    } else if (clearUrl == "/api/upload" && req.method == 'POST') {
        const collection = db.collection("users");
        const user = await collection.findOne({ token: req.headers["authorization"] });
        if (user == null) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Invalid token"));
            return;
        }
        if (user.suspended) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "User is suspended"));
            return;
        }
        try {
            let bb = busboy({ headers: req.headers, limits: { fileSize: 10 * 1024 * 1024, files: 1 } });
            let fId = "~"+ulid();

            bb.on('file', (_, file, info) => {
                let { filename } = info;
                let savePath = path.join(__dirname, 'uploads', fId.substring(1) + path.extname(filename));
                const saveTo = fs.createWriteStream(savePath);
                file.pipe(saveTo);
            });

            bb.on('error', (_) => {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Failed to upload file"));
            });
            bb.on('filesLimit', () => {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Too many files uploaded"));
            });
            bb.on('fieldsLimit', () => {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Too many fields"));
            })
            bb.on('partsLimit', () => {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Max filesize is: 10MB"));
            });

            bb.on('finish', () => {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(sendResponse(true, {
                    fileId: fId,
                }));
            });

            req.pipe(bb);
        } catch (e) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Failed to upload file"));
        }
    } else if (clearUrl == "/api/logout" && req.method == 'POST') {
        let body = '';
        req.on('data', async (data) => {
            body += data.toString();
        })
        req.on('end', async () => {
            let parsedBody: any;
            try {
                parsedBody = JSON.parse(body);
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid JSON"));
                return;
            }
            if (parsedBody.protocol != PROT_NAME) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unknown protocol"));
                return;
            }
            if (parsedBody.protocolVersion != PROT_VER) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unsupported protocol version"));
                return;
            }
            if (parsedBody.token == undefined || typeof parsedBody.token != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            const collection = db.collection("users");
            const user = await collection.findOne({ token: parsedBody.token });
            if (user == null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (user.suspended) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is suspended"));
                return;
            }
            let token: string;
            let check = 0
            while (true) {
                token = generateRandomString(256);
                let existingToken = await collection.findOne({ token: token });
                if (existingToken == null) {
                    break;
                }
                check++;
                if (check > 10) {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "Could not generate token, please try again later..."));
                    return;
                }
            }
            collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip, token: token } })
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(sendResponse(true, null));
        })
    } else if (clearUrl == "/api/universe/info" && req.method == 'GET') {
        if (req.headers["protocol"] != PROT_NAME) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Unknown protocol"));
            return;
        }
        if (req.headers["protocol-version"] != PROT_VER) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Unsupported protocol version"));
            return;
        }
        if (args.universeId == undefined || typeof args.universeId != "string" || !args.universeId.startsWith("&")) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Invalid universe ID"));
            return;
        }
        const collection = db.collection("users");
        const user = await collection.findOne({ token: req.headers["authorization"] });
        if (user == null) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Invalid token"));
            return;
        }
        if (user.suspended) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "User is suspended"));
            return;
        }
        collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
        const universesCollection = db.collection("universes");
        const universe = await universesCollection.findOne({ id: decodeURIComponent(args.universeId) });
        if (universe == null || universe.deleted) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Universe not found"));
            return;
        }
        const membersCollection = db.collection("members");
        const member = await membersCollection.findOne({ user: user.username, target: universe.id });
        if (member == null) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "User is not member of this universe"));
            return;
        }
        let inviteAccepted = member.accepted
        let members = await membersCollection.find({ target: universe.id }).toArray();
        let resMembers: any[] = [];
        for (let i = 0; i < members.length; i++) {
            resMembers.push({
                user: members[i].user,
                nick: members[i].nick,
                role: members[i].role,
                joinedAt: members[i].joinedAt
            });
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        if (universe.icon == undefined || universe.icon.length == 0) {
            universe.icon = null
        }
        res.end(sendResponse(true, {
            id: universe.id,
            name: universe.name,
            owner: universe.owner,
            icon: universe.icon,
            createdAt: universe.createdAt,
            members: resMembers,
            inviteAccepted: inviteAccepted,
        }));
    } else if (clearUrl == "/api/acceptInvite" && req.method == 'POST') {
        let body = '';
        req.on('data', async (data) => {
            body += data.toString();
        })
        req.on('end', async () => {
            let parsedBody: any;
            try {
                parsedBody = JSON.parse(body);
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid JSON"));
                return;
            }
            if (parsedBody.protocol != PROT_NAME) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unknown protocol"));
                return
            }
            if (parsedBody.protocolVersion != PROT_VER) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unsupported protocol version"));
                return;
            }
            if (parsedBody.token == undefined || typeof parsedBody.token != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (parsedBody.targetId == undefined || typeof parsedBody.targetId != "string" || (!parsedBody.targetId.startsWith("&") && !parsedBody.targetId.startsWith("#"))) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid target ID"));
                return;
            }
            const collection = db.collection("users");
            const user = await collection.findOne({ token: parsedBody.token });
            if (user == null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (user.suspended) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is suspended"));
                return;
            }
            collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
            const membersCollection = db.collection("members");
            const member = await membersCollection.findOne({ user: user.username, target: parsedBody.targetId });
            if (member == null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "You are not a member of this universe or room"));
                return;
            }
            if (member.accepted) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "You have already accepted this invite"));
                return;                
            }
            membersCollection.updateOne({ user: user.username, target: parsedBody.targetId }, { $set: { accepted: true } });
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(sendResponse(true, {
                targetId: parsedBody.targetId,
                accepted: true
            }));
        })
    } else if (clearUrl == "/api/denyInvite" && req.method == 'POST') {
        let body = '';
        req.on('data', async (data) => {
            body += data.toString();
        })
        req.on('end', async () => {
            let parsedBody: any;
            try {
                parsedBody = JSON.parse(body);
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid JSON"));
                return;
            }
            if (parsedBody.protocol != PROT_NAME) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unknown protocol"));
                return
            }
            if (parsedBody.protocolVersion != PROT_VER) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Unsupported protocol version"));
                return;
            }
            if (parsedBody.token == undefined || typeof parsedBody.token != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (parsedBody.targetId == undefined || typeof parsedBody.targetId != "string" || (!parsedBody.targetId.startsWith("&") && !parsedBody.targetId.startsWith("#"))) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid target ID"));
                return;
            }
            const collection = db.collection("users");
            const user = await collection.findOne({ token: parsedBody.token });
            if (user == null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid token"));
                return;
            }
            if (user.suspended) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is suspended"));
                return;
            }
            collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date(), lastIP: ip } })
            const membersCollection = db.collection("members");
            const unvierseKeys = db.collection("universeKeys");
            const roomKeys = db.collection("roomKeys");
            const member = await membersCollection.findOne({ user: user.username, target: parsedBody.targetId });
            if (member == null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "You are not a member of this universe or room"));
                return;
            }
            if (member.accepted) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "You have already accepted this invite"));
                return;                
            }
            membersCollection.deleteOne({ user: user.username, target: parsedBody.targetId });
            if (parsedBody.targetId.startsWith("&")) {
                unvierseKeys.deleteOne({ universeId: parsedBody.targetId, user: user.username });
            } else if (parsedBody.targetId.startsWith("#")) {
                roomKeys.deleteOne({ roomId: parsedBody.targetId, user: user.username });
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(sendResponse(true, {
                targetId: parsedBody.targetId,
                accepted: false
            }));
        })
    } else {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(sendResponse(false, null, "Not Found"));
    }
});

const wsServer = new WebSocketServer({
    server: httpServer,
    path: '/ws'
})
wsServer.on('connection', (socket) => {
    let id = ulid()
    sockets[id] = {
        ws: socket,
        token: "",
        username: "",
        lastHeartBeat: Date.now()
    }
    console.log(`New socket: ${id}`);
    socket.on('close', () => {
        console.log(`Socket closed: ${id}`);
        delete sockets[id];
    })
    socket.on('message', async (rawdata) => {
        let data
        try {
            data = JSON.parse(rawdata.toString());
        } catch (e) {
            console.error(`Invalid JSON from socket ${id}:`, e);
            return;
        }
        if (data.protocol != PROT_NAME) {
            socket.send(JSON.stringify({
                type: "error",
                error: "Unknown protocol",
                protocol: PROT_NAME,
                protocolVersion: PROT_VER
            }));
        }
        if (data.protocolVersion != PROT_VER) {
            socket.send(JSON.stringify({
                type: "error",
                error: "Unsupported protocol version",
                protocol: PROT_NAME,
                protocolVersion: PROT_VER
            }));
        }
        if (data.type == "auth") {
            if (data.token == undefined || typeof data.token != "string") {
                socket.send(JSON.stringify({
                    type: "error",
                    error: "Invalid token",
                    protocol: PROT_NAME,
                    protocolVersion: PROT_VER
                }));
                socket.close();
                return
            }
            const collection = db.collection("users");
            const user = await collection.findOne({ token: data.token });
            if (user == null) {
                socket.send(JSON.stringify({
                    type: "error",
                    error: "Invalid token",
                    protocol: PROT_NAME,
                    protocolVersion: PROT_VER
                }));
                socket.close();
                return;
            }
            if (user.suspended) {
                socket.send(JSON.stringify({
                    type: "error",
                    error: "User is suspended",
                    protocol: PROT_NAME,
                    protocolVersion: PROT_VER
                }));
                socket.close();
                return;
            }
            collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date() } })
            sockets[id].token = data.token;
            sockets[id].username = user.username;
            socket.send(JSON.stringify({
                type: "auth",
                protocol: PROT_NAME,
                protocolVersion: PROT_VER,
                username: user.username
            }));
        } else if (data.type == "heartbeat") {
            sockets[id].lastHeartBeat = Date.now();
            socket.send(JSON.stringify({
                type: "heartbeat",
                protocol: PROT_NAME,
                protocolVersion: PROT_VER
            }));
        }
    })
})


httpServer.listen(config.port, () => {
    console.log('Server is running on http://localhost:' + config.port);
    console.log(`Secure chats server V${VER}`)
});