/** @format */

import Router from 'express';
import { User } from '../models/userModel.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import 'dotenv/config';
import nodemailer from 'nodemailer';
import Twilio from 'twilio';
//google login
import { google } from 'googleapis';

const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const twilioNumber = process.env.TWILIO_PHONE_NUMBER;

const client = new Twilio(accountSid, authToken);
const router = Router();
const verifycodeList = {};
//google login
const oauth2Client = new google.auth.OAuth2();
// Endpoint for Login
router.post('/login', async (req, res) => {
	const { type, email, password } = req.body;
	const clientIp = req.clientIp;
	console.log(email, 'email');
	console.log(type, email, password, clientIp);
	try {
		if (!email || !password) {
			return res.status(200).json({ msg: type + ' or Password is missing' });
		}
		const matchUser = await User.findOne({ email });
		if (matchUser) {
			const matchPassword = await bcrypt.compare(
				password,
				matchUser.passwordHash
			);

			if (!matchPassword) {
				return res.status(200).json({ msg: type + ' or Password is invalid!' });
			}

			if (matchUser.allow == 0)
				return res.send({ msg: 'Please wait allow of Administrator' });

			const token = jwt.sign(
				{
					userId: matchUser._id,
					emailConfirmed: matchUser.emailConfirmed,
				},
				process.env['JWT_SECRET'],
				{
					expiresIn: process.env['TOKEN_EXPIRATION_TIME'],
				}
			);

			res.send({
				token: token,
			});
		} else {
			res.send({ msg: 'Email is invalid' });
		}
	} catch (err) {
		console.log(err);
		return res.status(200).json({ msg: ' Server Error' });
	}
});

router.post('/register', (req, res) => {
	const { email, type } = req.body;
	console.log(req.body);
	var code = Math.floor(Math.random() * 10000000) % 1000000;
	if (code < 100000) code = code * 10;
	verifycodeList[email] = code;
	console.log(verifycodeList);
	try {
		if (type == 'email') {
			var transporter = nodemailer.createTransport({
				service: 'gmail',
				auth: {
					user: 'ruka0430petri@gmail.com',
					pass: 'nnkkclzckscepylm',
				},
			});
			var mailOptions = {
				from: 'ruka0430petri@gmail.com',
				to: email,
				subject: 'Verify Code',
				html: '<html><p>Verification code is ' + code + ' </p></html>',
			};
			transporter.sendMail(mailOptions, function (error, info) {
				if (error) {
					console.log(error, 'mail send error');
					res.status(200).json({ msg: 'failed' });
				} else {
					console.log('Email sent: ' + info.response);
					res.status(200).json({ msg: 'success' });
				}
			});
		} else {
			console.log('sending sms code to ' + email);
			client.messages
				.create({
					from: twilioNumber,
					to: email,
					body: code,
				})
				.then((message) => console.log('sms sent: ' + message.sid));
		}
	} catch (err) {
		console.log(err);
		res.status(200).json({ msg: 'failed' });
	}
});

router.post('/verifycode', async (req, res) => {
	const { firstName, lastName, code, email, password } = req.body;
	if (!code || !email)
		return res.status(200).json({ msg: 'Verify Code is not correct!' });

	if (verifycodeList[email] == '' || verifycodeList[email] == undefined) {
		return res.status(200).json({ msg: 'Verify Code is not correct!' });
	} else {
		if (verifycodeList[email] == code) {
			const existingUser = await User.findOne({ email });
			if (existingUser) {
				return res.status(200).json({ msg: 'User Already Exists!' });
			}

			const saltRounds = 10;
			const passwordHash = await bcrypt.hash(password, saltRounds);

			//-------------------------Create Account----------------------------------

			const address = '';
			let role = '3';
			const allow = '1';
			const phoneNumber = '';
			const company = '';
			const postalcode = '';
			const city = '';
			const newUser = new User({
				firstName,
				lastName,
				company,
				phoneNumber,
				address,
				postalcode,
				city,
				email,
				passwordHash,
				role,
				allow,
			});

			const savedUser = await newUser.save();
			console.log('successed creating account');

			const role_token = jwt.sign(
				{
					userId: savedUser._id,
					role: savedUser.role,
				},
				process.env['JWT_SECRET'],
				{
					expiresIn: process.env['TOKEN_EXPIRATION_TIME'],
				}
			);

			var role_data = '';

			for (var i = 0; i < role_token.length; i++) {
				role_data += role_token[i];
				if (i == 10) role_data += savedUser.role;
			}

			res.send({
				msg: 'success',
			});
		} else {
			return res.status(200).json({ msg: 'Verify Code is not correct!' });
		}
	}
});

router.post('/registerByGoogle', async (req, res) => {
	console.log(req.body);
	let { tokenId } = req.body;
	oauth2Client.setCredentials({
		access_token: tokenId.access_token,
	});
	let oauth2 = google.oauth2({
		auth: oauth2Client,
		version: 'v2',
	});
	let result = await oauth2.userinfo.get();
	let { email, given_name, family_name } = result.data;
	// console.log(`google data::`, data);
	const existingUser = await User.findOne({ email });
	if (existingUser) {
		return res.status(200).json({ msg: 'User Already Exists!' });
	}
	const newUser = new User({
		data,
	});
	res.send({
		msg: 'success',
	});
});

router.post('/loginByGoogle', async (req, res) => {
	console.log(req.body);
	let { tokenId } = req.body;
	oauth2Client.setCredentials({
		access_token: tokenId.access_token,
	});
	let oauth2 = google.oauth2({
		auth: oauth2Client,
		version: 'v2',
	});
	let result = await oauth2.userinfo.get();
	let { email } = result.data;
	// console.log(`google data::`, data);
	const existingUser = await User.findOne({ email });
	if (!existingUser) {
		return res.status(200).json({ msg: 'User Already Exists!' });
	} else {
		res.send({
			msg: 'success',
		});
	}
});

router.post('/resendCode', (req, res) => {
	const { email } = req.body;
	console.log(req.body);
	var code = Math.floor(Math.random() * 10000000) % 1000000;
	if (code < 100000) code = code * 10;
	verifycodeList[email] = code;
	console.log(verifycodeList);

	var transporter = nodemailer.createTransport({
		service: 'gmail',
		auth: {
			user: 'ruka0430petri@gmail.com',
			pass: 'nnkkclzckscepylm',
		},
	});
	var mailOptions = {
		from: 'ruka0430petri@gmail.com',
		to: email,
		subject: 'Verify Code',
		html: '<html><p>Verification code is ' + code + ' </p></html>',
	};
	transporter.resendMail(mailOptions, function (error, info) {
		if (error) {
			console.log(error, 'mail resend error');
			res.status(200).json({ msg: 'failed' });
		} else {
			console.log('Email sent: ' + info.response);
			res.status(200).json({ msg: 'success' });
		}
	});
});

router.post('/resetPassword', (req, res) => {
	let { token, newPassword, oldPassword } = req.body;
	console.log(token, newPassword, oldPassword);
	if (!token || !newPassword)
		return res.status(201).json({ msg: 'Invalid Reset Token' });

	jwt.verify(token, process.env['JWT_SECRET'], async (error, decoded) => {
		if (error) {
			return res.status(201).json({ msg: 'Invalid Reset Token' });
		} else {
			const saltRounds = 10;
			const passwordHash = await bcrypt.hash(newPassword, saltRounds);
			console.log(decoded.userId, passwordHash, newPassword);

			const user = await User.findById(decoded.userId);
			const matchPassword = await bcrypt.compare(
				oldPassword,
				user.passwordHash
			);
			if (matchPassword == false)
				return res.status(201).json({ msg: 'Old Password is wrong' });

			User.findByIdAndUpdate(decoded.userId, {
				passwordHash: passwordHash,
				emailConfirmed: true,
			})
				.then((user) => {
					const newToken = jwt.sign(
						{
							userId: user._id,
							emailConfirmed: true,
						},
						process.env['JWT_SECRET'],
						{
							expiresIn: process.env['TOKEN_EXPIRATION_TIME'],
						}
					);
					return res.json({ user: newToken });
				})
				.catch((error) => {
					return res.status(201).json({ msg: 'New Email Save Error!' });
				});
		}
	});
});
export default router;
