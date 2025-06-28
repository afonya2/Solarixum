import http from 'http';
import { WebSocketServer } from 'ws';
import crypto from 'crypto';
import url from 'url'
import fs from 'fs';
import path from 'path';
import { MongoClient } from 'mongodb'
import { ulid } from 'ulid';

const VER = '0.1.0';
const SERV_NAME = 'Solarixum Server';
const PROT_VER = '0.1.0';
const PROT_NAME = 'Solarixum Protocol';
const config = JSON.parse(fs.readFileSync('config.json', 'utf8'));

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

const httpServer = http.createServer(async (req, res) => {
    const clearUrl = req.url?.split('?')[0];
    const args = url.parse(req.url || "", true).query;
    let ip = req.socket.remoteAddress
    if (ip == "::1") {
        ip = "127.0.0.1"
    }
    if (req.headers['x-forwarded-for'] != undefined && config.trustedProxies.includes(ip)) {
        ip = req.headers['x-forwarded-for'] as string;
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
    } else if (clearUrl?.startsWith("/client/")) {
        let pathRemaining = clearUrl.replace("/client/", "");
        let file = `./client/${path.normalize(pathRemaining)}`;
        if (file == "./client/.") {
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
                createdAt: new Date(),
                lastLogin: new Date(),
                lastCommunication: new Date(),
                lastIP: ip,
                token: token,
                suspended: false
            })
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
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(sendResponse(true, {
                username: user.username,
                privateKey: user.privateKey,
                publicKey: user.publicKey
            }));
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
            if (parsedBody.roomName == undefined || typeof parsedBody.roomName != "string" || parsedBody.roomName.length < 3 || parsedBody.roomName.length > 32) {
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
                if (universe == null) {
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
                roomsCollection.insertOne({
                    id: roomId,
                    name: parsedBody.roomName,
                    owner: user.username,
                    createdAt: new Date(),
                    universeId: decodeURIComponent(args.universeId)
                })
                universesCollection.updateOne({ id: decodeURIComponent(args.universeId) }, { $addToSet: { rooms: roomId } })
            } else {
                roomsCollection.insertOne({
                    id: roomId,
                    name: parsedBody.roomName,
                    owner: user.username,
                    createdAt: new Date(),
                    universeId: "&0"
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
                    joinedAt: new Date()
                })
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
        if (room == null) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Room not found"));
            return;
        }
        let key
        if (room.universeId != "&0") {
            const universesCollection = db.collection("universes");
            const universe = await universesCollection.findOne({ id: room.universeId });
            if (universe == null) {
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
            if (room == null) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Room not found"));
                return;
            }
            if (room.universeId != "&0") {
                const universesCollection = db.collection("universes");
                const universe = await universesCollection.findOne({ id: room.universeId });
                if (universe == null) {
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
            if (room == null) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Room not found"));
                return;
            }
            if (room.universeId != "&0") {
                const universesCollection = db.collection("universes");
                const universe = await universesCollection.findOne({ id: room.universeId });
                if (universe == null) {
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
            const message = await messagesCollection.findOne({ id: parsedBody.messageId, roomId: parsedBody.roomId });
            if (message == null) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Message not found"));
                return;
            }
            if (message.user != user.username) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is not owner of this message"));
                return;
            }
            messagesCollection.updateOne({ id: message.id }, { $set: { message: parsedBody.message }, $addToSet: { edits: message.message } })
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
            if (room == null) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Room not found"));
                return;
            }
            if (room.universeId != "&0") {
                const universesCollection = db.collection("universes");
                const universe = await universesCollection.findOne({ id: room.universeId });
                if (universe == null) {
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
            const message = await messagesCollection.findOne({ id: parsedBody.messageId, roomId: parsedBody.roomId });
            if (message == null) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Message not found"));
                return;
            }
            if (message.user != user.username) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is not owner of this message"));
                return;
            }
            messagesCollection.updateOne({ id: message.id }, { $set: { deleted: true } })
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
        if (room == null) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Room not found"));
            return;
        }
        if (room.universeId != "&0") {
            const universesCollection = db.collection("universes");
            const universe = await universesCollection.findOne({ id: room.universeId });
            if (universe == null) {
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
                edits: messages[i].edits
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
            const room = await roomsCollection.findOne({ id: parsedBody.roomId });
            if (room == null) {
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
                joinedAt: new Date()
            })
            const keyCollection = db.collection("roomKeys");
            keyCollection.insertOne({
                user: targetUser.username,
                roomId: parsedBody.roomId,
                key: parsedBody.key,
                iv: parsedBody.iv,
                createdAt: new Date()
            })
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
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(sendResponse(true, {
            username: user.username,
            createdAt: user.createdAt
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
            rooms = await roomsCollection.find({ universeId: decodeURIComponent(args.universeId) }).toArray();
        } else {
            const roomIds = await membersCollection.find({ user: user.username }).toArray();
            rooms = []
            for (let i = 0; i < roomIds.length; i++) {
                if (roomIds[i].target.startsWith("#")) {
                    const room = await roomsCollection.findOne({ id: roomIds[i].target });
                    if (room != null) {
                        rooms.push(room);
                    }
                }
            }
        }
        let resRooms: any[] = [];
        for (let i = 0; i < rooms.length; i++) {
            resRooms.push({
                id: rooms[i].id,
                name: rooms[i].name,
                owner: rooms[i].owner,
                createdAt: rooms[i].createdAt
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
        const room = await roomsCollection.findOne({ id: decodeURIComponent(args.roomId) });
        if (room == null) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Room not found"));
            return;
        }
        let members
        if (room.universeId != "&0") {
            const universesCollection = db.collection("universes");
            const universe = await universesCollection.findOne({ id: room.universeId });
            if (universe == null) {
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
            members = await membersCollection.find({ target: universe.id }).toArray();
        } else {
            const member = await membersCollection.findOne({ user: user.username, target: room.id });
            if (member == null) {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "User is not member of this room"));
                return;                    
            }
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
        res.end(sendResponse(true, {
            id: room.id,
            name: room.name,
            owner: room.owner,
            createdAt: room.createdAt,
            universeId: room.universeId,
            members: resMembers
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
                const universe = await universesCollection.findOne({ id: universeIds[i].target });
                if (universe != null) {
                    universes.push(universe);
                }
            }
        }
        let resUniverses: any[] = [];
        for (let i = 0; i < universes.length; i++) {
            resUniverses.push({
                id: universes[i].id,
                name: universes[i].name,
                owner: universes[i].owner,
                createdAt: universes[i].createdAt
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
            if (parsedBody.universeName == undefined || typeof parsedBody.universeName != "string" || parsedBody.universeName.length < 3 || parsedBody.universeName.length > 32) {
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
                createdAt: new Date()
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
                joinedAt: new Date()
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
            const universe = await universesCollection.findOne({ id: parsedBody.universeId });
            if (universe == null) {
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
                joinedAt: new Date()
            })
            keyCollection.insertOne({
                user: targetUser.username,
                universeId: parsedBody.universeId,
                key: parsedBody.key,
                iv: parsedBody.iv,
                createdAt: new Date()
            })
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
        const targetUser = await collection.findOne({ username: decodeURIComponent(args.username) });
        if (targetUser == null) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "User not found"));
            return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(sendResponse(true, {
            username: targetUser.username,
            createdAt: targetUser.createdAt
        }));
    } else {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(sendResponse(false, null, "Not Found"));
    }
});

const wsServer = new WebSocketServer({
    server: httpServer,
    path: '/ws'
})


httpServer.listen(config.port, () => {
    console.log('Server is running on http://localhost:' + config.port);
    console.log(`Secure chats server V${VER}`)
});