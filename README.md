# Clipboard Server

The project builds into a client and a server executable. On connection with a client, the server sends the content of the server machine's clipboard to the client.

The content is encrypted using **AES GCM** before sending to the client. The client must use the same key as the server to decrypt the content.

## Compilation

### Server Compilation

```bash
cargo build --release --bin server
```

### Client Compilation

```bash
cargo build --release --bin client
```

## Environment File

The server and the client expects a ***.env*** file present at the ***$PWD***.

### Server Env

```bash
PORT = 3001 # TCP port to listen to
KEY = password # Encryption key
ENC_BLOCK_SIZE = 1024 # AES encryption block size (Optional, default to 1024)
```

### Client Env

```bash
TARGET = "127.0.0.1:3001" # Target Server IP address and Port
KEY = password # Encryption key
```