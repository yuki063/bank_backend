/** @format */

import mongoose from 'mongoose';

const userSchema = mongoose.Schema({
	firstName: { type: String, required: true },
	lastName: { type: String, required: true },
	company: { type: String, required: false },
	phoneNumber: { type: String, required: false },
	address: { type: String, required: false },
	postalCode: { type: String, required: false },
	city: { type: String, required: false },
	email: { type: String, required: true },
	passwordHash: { type: String, required: true },
	role: { type: String, required: false },
	allow: { type: String, required: false },
});

export const User = mongoose.model('users', userSchema);
