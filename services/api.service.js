"use strict";

const ApiGateway = require("moleculer-web");
const { UnAuthorizedError } = ApiGateway.Errors;
const _ = require("lodash");
const history = require("connect-history-api-fallback");
const cookie = require("cookie");

//const PassportMixin = require("../../mixins/passport.mixin");
const SocketIOMixin = require("moleculer-io");

module.exports = {
	name: "api",
	version: 1,
	mixins: [
		// Gateway
		ApiGateway,

		// Passport
		// PassportMixin({
		// 	routePath: "/auth",
		// 	localAuthAlias: "v1.accounts.login",
		// 	successRedirect: "/",
		// 	providers: {
		// 		google: false,//process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET,
		// 		facebook: false,// process.env.FACEBOOK_CLIENT_ID && process.env.FACEBOOK_CLIENT_SECRET,
		// 		github: false,//process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET,
		// 		twitter: false
		// 	}
		// }),


		// Socket.IO handler
		SocketIOMixin
	],

	metadata: {},

	// More info about settings: https://moleculer.services/docs/0.13/moleculer-web.html
	settings: {
		port: process.env.PORT || 4000,
		ip: process.env.ADDRESS || '0.0.0.0',
		log4XXResponses: true,
		logRequestParams: "debug",
		// Logging the response data. Set to any log level to enable it. E.g. "info"
		logResponseData: "debug",
		debounceTime: 5000,
		use: [

		],

		cors: {
			// Configures the Access-Control-Allow-Origin CORS header.
			origin: "*",
			// Configures the Access-Control-Allow-Methods CORS header. 
			methods: '*',
			// Configures the Access-Control-Allow-Headers CORS header.
			allowedHeaders: '*',
			// Configures the Access-Control-Expose-Headers CORS header.
			//exposedHeaders: '*',
			// Configures the Access-Control-Allow-Credentials CORS header.
			credentials: false,
			// Configures the Access-Control-Max-Age CORS header.
			maxAge: 3600
		},
		routes: [
			/**
			 * API routes
			 */
			{
				path: "/api",

				whitelist: [
					"**"
				],


				etag: true,

				camelCaseNames: true,

				authentication: true,
				//authorization: true,

				autoAliases: true, mergeParams: true,

				aliases: {},

				// Disable to call not-mapped actions
				//mappingPolicy: "restrict",

				// Use bodyparser modules
				bodyParsers: {
					json: { limit: "2MB" },
					urlencoded: { extended: true, limit: "2MB" }
				}
			},


			/**
			 * Static routes
			 */
			{
				path: "/",
				use: [history(), ApiGateway.serveStatic("public", {})],

				mappingPolicy: "restrict"
				//logging: false
			}
		],

	},

	methods: {
		/**
		 * Authenticate from request
		 *
		 * @param {Context} ctx
		 * @param {Object} route
		 * @param {IncomingRequest} req
		 * @returns {Promise}
		 */
		async authenticate(ctx, route, req) {
			let token;

			// Get JWT token from Authorization header
			const auth = req.headers["authorization"];
			if (auth && auth.startsWith("Bearer ")) token = auth.slice(7);

			// Get JWT token from cookie
			if (!token && req.headers.cookie) {
				const cookies = cookie.parse(req.headers.cookie);
				token = cookies["jwt-token"];
			}

			ctx.meta.roles = ["$everyone"];
			ctx.meta.roles = [];

			// Verify JWT token
			const user = await this.validateUserToken(ctx, token)

			if (!req.$endpoint) {
				return user
			}

			

			const { permissions = [], needEntity = false, name } = req.$endpoint.action;

			let res = false;
			if (permissions.length > 0) {
				res = await ctx.call("v1.roles.hasAccess", { roles: ctx.meta.roles, permissions: permissions });
			} else {
				res = true;
			}
			
			if (res !== true)
				throw new UnAuthorizedError("You have no right for this operation!", 401, "ERR_HAS_NO_ACCESS", { roles: ctx.meta.roles });


			return user
		},
		async validateUserToken(ctx, token) {
			if (token) {
				const user = await ctx.call("v1.accounts.resolveToken", { token });
				if (user) {
					this.logger.debug("User authenticated via JWT.", {
						username: user.username,
						email: user.email,
						id: user.id
					});

					ctx.meta.roles.push("$authenticated");
					if (Array.isArray(user.roles)) ctx.meta.roles.push(...user.roles);
					ctx.meta.token = token;
					ctx.meta.userID = user.id;
					// Reduce user fields (it will be transferred to other nodes)
					return _.pick(user, ["id", "email", "username", "fullName", "avatar"]);
				}
			}
			return null;
		},

		async signInSocialUser(params, cb) {
			try {
				cb(null, await this.broker.call("v1.accounts.socialLogin", params));
			} catch (err) {
				cb(err);
			}
		}
	},


	/**
	 * Service created lifecycle event handler
	 */
	created() { },

	/**
	 * Service started lifecycle event handler
	 */
	async started() {
		const port = process.env.PORT || 4000
		const address = process.env.ADDRESS || '0.0.0.0'
	
		// this.broker.waitForServices(["v1.noc"]).then(async () => {

		// 	this.host = await this.broker.call('v1.noc.httpRouteRegister', {
		// 		vHost: '',
		// 		address,
		// 		port,
		// 	})
		// 	console.log(this.host)
		// });
	},

	/**
	 * Service stopped lifecycle event handler
	 */
	async stopped() {
		const port = process.env.PORT || 4000
		const address = process.env.ADDRESS || '0.0.0.0'
		
		// console.log(await this.broker.call('v1.noc.httpRouteUnregister', {
		// 	vHost: '',
		// 	address,
		// 	port,
		// }))
	}



};