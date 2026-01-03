// Complete cipher implementations for encoding and decoding
// All 100+ cipher methods organized by category

const CipherRegistry = {
    // Master list of all available ciphers with metadata
    ciphers: [
        // Base Encodings
        { id: 'base64', name: 'Base64', category: 'Base Encodings', bidirectional: true },
        { id: 'base32', name: 'Base32', category: 'Base Encodings', bidirectional: true },
        { id: 'base16', name: 'Base16 (Hex)', category: 'Base Encodings', bidirectional: true },
        { id: 'base85', name: 'Base85 (Ascii85)', category: 'Base Encodings', bidirectional: true },
        { id: 'base58', name: 'Base58 (Bitcoin)', category: 'Base Encodings', bidirectional: true },
        { id: 'base91', name: 'Base91', category: 'Base Encodings', bidirectional: true },
        { id: 'base62', name: 'Base62', category: 'Base Encodings', bidirectional: true },
        { id: 'base45', name: 'Base45', category: 'Base Encodings', bidirectional: true },
        { id: 'base36', name: 'Base36', category: 'Base Encodings', bidirectional: true },
