const mongoose = require('mongoose');

/**
 * Connects to MongoDB using the URI in the environment.
 * Fails fast on startup if the connection can't be established,
 * rather than letting the app boot into a broken state.
 */
async function connectDB() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    throw new Error('MONGODB_URI is not set in the environment');
  }

  mongoose.set('strictQuery', true);

  await mongoose.connect(uri, {
    // Modern mongoose (8.x) no longer needs useNewUrlParser/useUnifiedTopology,
    // they're defaults now — kept out intentionally to avoid deprecation warnings.
  });

  console.log(`[db] connected to MongoDB (${mongoose.connection.name})`);

  mongoose.connection.on('error', (err) => {
    console.error('[db] connection error:', err.message);
  });

  mongoose.connection.on('disconnected', () => {
    console.warn('[db] disconnected from MongoDB');
  });
}

module.exports = { connectDB };
