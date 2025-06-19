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

const httpServer = http.createServer((req, res) => {
    const clearUrl = req.url?.split('?')[0];
    const args = url.parse(req.url || "", true).query;
    let ip = req.socket.remoteAddress
    if (ip == "::1") {
        ip = "127.0.0.1"
    }
    if (req.headers['x-forwarded-for'] != undefined && config.trustedProxies.includes(ip)) {
        ip = req.headers['x-forwarded-for'] as string;
    }
    if (clearUrl == "/version") {
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
        let content = fs.readFileSync(file, 'utf8');
        if (file.endsWith(".html")) {
            res.writeHead(200, { 'Content-Type': 'text/html', 'cache-control': 'max-age=86400' });
            res.end(content);
        } else if (file.endsWith(".js")) {
            res.writeHead(200, { 'Content-Type': 'application/javascript', 'cache-control': 'max-age=86400' });
            res.end(content);
        } else if (file.endsWith(".css")) {
            res.writeHead(200, { 'Content-Type': 'text/css', 'cache-control': 'max-age=86400' });
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
            let existingUser = await collection.findOne({ username: parsedBody.username });
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
                username: parsedBody.username,
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
            collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date() } })
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
            const user = await collection.findOne({ username: parsedBody.username, password: hashedPassword });
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
            collection.updateOne({ token: user.token }, { $set: { lastCommunication: new Date() } })
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
            const roomId = "#"+ulid();
            roomsCollection.insertOne({
                id: roomId,
                name: parsedBody.roomName,
                owner: user.username,
                createdAt: new Date(),
                members: [user.username]
            })
            keyCollection.insertOne({
                user: user.username,
                roomId: roomId,
                key: parsedBody.roomKey,
                createdAt: new Date()
            })
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(sendResponse(true, {
                roomId: roomId
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


httpServer.listen(config.port, () => {
    console.log('Server is running on http://localhost:' + config.port);
    console.log(`Secure chats server V${VER}`)
});