// Configuration and constants for the decoder
// Example strings that demonstrate different encoding types
const examples = [
    { text: "V3JpdGUtSG9zdCAiTWFsaWNpb3VzIGNvZGUgZGV0ZWN0ZWQi", cipher: "base64" },
    { text: "49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74", cipher: "hex" },
    { text: "cmd.exe%20%2Fc%20%22whoami%22", cipher: "url" },
    { text: "01001000 01100001 01100011 01101011", cipher: "binary" }
