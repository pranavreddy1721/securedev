const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 100 },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, 'Invalid email format'],
    },
    passwordHash: { type: String, required: true, select: false },

    // GitHub OAuth — token is encrypted at rest (see utils/crypto.js), never stored plaintext.
    github: {
      id: { type: String, default: null },
      username: { type: String, default: null },
      accessTokenEncrypted: { type: String, default: null, select: false },
      scope: { type: String, default: null },
      connectedAt: { type: Date, default: null },
    },

    refreshTokenHash: { type: String, default: null, select: false },
  },
  { timestamps: true }
);

userSchema.methods.comparePassword = async function comparePassword(candidate) {
  return bcrypt.compare(candidate, this.passwordHash);
};

userSchema.methods.toSafeJSON = function toSafeJSON() {
  return {
    id: this._id,
    name: this.name,
    email: this.email,
    githubConnected: Boolean(this.github?.id),
    githubUsername: this.github?.username || null,
    createdAt: this.createdAt,
  };
};

module.exports = mongoose.model('User', userSchema);
