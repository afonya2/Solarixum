# Solarixum
An end-to-end encrypted chat platform.

[Demo](https://solarixum.afonyanet.hu) | [Source Code](https://github.com/afonya2/Solarixum)

## Setting Up Your Own Server

### Requirements
- Node.js with npm installed
- A MongoDB server

### Database setup
- Collections inside a DB:
  - inviteLinks
  - members
  - messages
  - roomKeys
  - rooms
  - universeKeys
  - universes
  - users

### Instructions
1. Download the ZIP file and extract it.
2. Rename `example-config.json` to `config.json`.
3. Fill in the appropriate values:
```jsonc
{
    "port": 1010, // Port for the server to listen on
    "db": {
        "host": "127.0.0.1",      // MongoDB host
        "port": 27017,            // MongoDB port
        "database": "solarixum",  // Name of the MongoDB database
        "user": "solarixum",      // MongoDB username
        "password": "solarixum"   // MongoDB password
    },
    "trustedProxies": ["127.0.0.1"], // IP addresses of trusted proxies (e.g., reverse proxy like NGINX)
    "limits": {
        "maxFileSize": 10485760,           // Maximum upload size for files (in bytes)
        "maxRequestsPerHour": 10000,       // Maximum number of requests allowed per IP per hour
        "maxRegistrationsPerHour": 2,      // Maximum number of registrations allowed per IP per hour
        "loginTriesPerHour": 10,           // Maximum number of login attempts per IP per hour
        "messagesPerHour": 1000            // Maximum number of messages per IP per hour
    },
    "welcomeRoom": "",      // Optional: ID of the room to auto-add users upon registration
    "welcomeRoomKey": "",   // Optional: Decrypted encryption key for the welcome room
    "welcomeRoomIv": ""     // Optional: Decrypted IV for the welcome room
}
```
4. Install the dependencies using `npm install`.
5. Start the server using `npm start`.

### Found a Bug?
- Report it by creating an issue.
- Pull requests are welcome!