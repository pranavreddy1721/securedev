const mongoose = require('mongoose');

/**
 * Validate MongoDB ObjectId route parameters before they reach Mongoose.
 * This only rejects malformed IDs; valid existing requests are unchanged.
 */
function validateObjectId(paramName) {
  return (req, res, next) => {
    const value = req.params[paramName];
    if (!mongoose.isValidObjectId(value)) {
      return res.status(400).json({ error: `Invalid ${paramName}` });
    }
    return next();
  };
}

module.exports = { validateObjectId };
