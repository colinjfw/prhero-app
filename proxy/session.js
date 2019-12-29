class SigningError extends Error {
  status = "SigningFailed";
}

class Encryption {
  _encryptionKey = null;
  _signingKey = null;

  constructor(signingSecret, encryptionSecret) {
    this.signingSecret = signingSecret;
    this.encryptionSecret = encryptionSecret;
  }

  generateSigningSecret() {
    return crypto.subtle.generateKey(
        { name: "HMAC", hash: {name: "SHA-256"} },
        true,
        ["sign", "verify"],
      )
      .then(key => crypto.subtle.exportKey("raw", key))
      .then(buf => this.base64Encode(buf))
  }

  generateEncryptionSecret() {
    return crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"],
      )
      .then(key => crypto.subtle.exportKey("raw", key))
      .then(buf => this.base64Encode(buf))
  }

  /**
   * Returns a signing key.
   * @returns {Promise<CryptoKey>}
   */
  async signingKey() {
    if (this._signingKey) {
      return this._signingKey;
    }

    const key = crypto.subtle.importKey(
      "raw",
      this.base64Decode(this.signingSecret),
      {
        name: "HMAC",
        hash: { name: "SHA-256" },
      },
      false,
      ["sign", "verify"]
    )
    this._signingKey = key;
    return key;
  }

  /**
   * Returns an encryption key.
   * @returns {Promise<CryptoKey>}
   */
  async encryptionKey() {
    if (this._encryptionKey) {
      return this._encryptionKey;
    }
    const key = await crypto.subtle.importKey(
      "raw",
      this.base64Decode(this.encryptionSecret),
      {
        name: "AES-GCM",
      },
      false,
      ["encrypt", "decrypt"]
    )
    this._encryptionKey = key;
    return key;
  }

  /**
   * Encrypt a string.
   * @param {string} input
   * @returns {Promise<string>}
   */
  async encrypt(input) {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const buf = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      await this.encryptionKey(),
      data,
    );
    return this.base64Encode(iv) + "_" + this.base64Encode(buf);
  }

  /**
   * Decrypt a string.
   * @param {string} encrypted
   * @returns {Promise<string>}
   */
  async decrypt(encrypted) {
    const [ivRaw, dataRaw] = encrypted.split("_");
    const iv = this.base64Decode(ivRaw);
    const data = this.base64Decode(dataRaw);
    const buf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      await this.encryptionKey(),
      data
    )
    return String.fromCharCode.apply(null, new Uint8Array(buf))
  }

  /**
   * Signs a string and returns a string with the signature concatenated using
   * the '.' character.
   * @param {string} input
   * @returns {Promise<string>}
   */
  async sign(input) {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const buf = await crypto.subtle.sign("HMAC", await this.signingKey(), data);
    const signed = this.base64Encode(buf);
    return `${input}.${signed}`;
  }

  /**
   * Verifies a signed string and returns the original signed value.
   * @param {string} signed
   * @returns {Promise<string>}
   */
  async verify(signed) {
    if (!signed) {
      throw new SigningError("Invalid signature");
    }
    const encoder = new TextEncoder();
    const [value, signature] = signed.split(".");
    if (!value || !signature) {
      throw new SigningError("Invalid signature");
    }
    const verified = await crypto.subtle.verify(
      "HMAC",
      await this.signingKey(),
      this.base64Decode(signature),
      encoder.encode(value)
    );
    if (!verified) {
      throw new SigningError("Invalid signature");
    }
    return value;
  }

  /**
   * Take base64 and return an array buffer.
   *
   * @param {string} base64
   * @returns {ArrayBuffer}
   */
  base64Decode(base64) {
    const str = atob(base64);
    const len = str.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = str.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Encode an array buffer to a string.
   *
   * @param {ArrayBuffer} buffer
   * @returns {string}
   */
  base64Encode(buffer) {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
}

class SessionError {
  status = "SessionInvalid";
}

class Session {
  /**
   * @param {Encryption} encryption
   * @param {string} audience
   * @param {number} expiresInHours
   */
  constructor(encryption, audience, expiresInHours) {
    this.encryption = encryption;
    this.audience = audience;
    this.expiresInHours = expiresInHours;
  }

  /**
   * Create will create a session string.
   * @param {Object} session
   */
  async create(session) {
    const obj = {
      val: session,
      aud: this.audience,
      exp: Date.now() + (this.expiresInHours * 60 * 60 * 1000),
    };
    const str = JSON.stringify(obj);
    return await this.encryption.sign(
      await this.encryption.encrypt(str)
    );
  }

  /**
   * Read will read a raw session string and return the original object if it's
   * valid.
   * @param {string} raw
   * @returns {Promise<Object>}
   */
  async read(raw) {
    const sessionStr = await this.encryption.decrypt(
      await this.encryption.verify(raw)
    );
    const sess = JSON.parse(sessionStr);
    if (Date.now() > sess.exp) {
      throw new SessionError("Session expired");
    }
    if (sess.aud !== this.audience) {
      throw new SessionError("Invalid audience");
    }
    return sess.val;
  }
}
