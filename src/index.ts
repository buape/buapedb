import { Database } from "bun:sqlite"
import { randomBytes, timingSafeEqual } from "node:crypto"
import {
	chmodSync,
	closeSync,
	constants,
	fchmodSync,
	fstatSync,
	lstatSync,
	mkdirSync,
	openSync,
	readFileSync,
} from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"
import { parseArgs } from "node:util"
import { z } from "zod"
import { version } from "../package.json"

const leaseRow = z.object({
	id: z.string(),
	database: z.string(),
	issued_at: z.number(),
	expires_at: z.number().nullable(),
})
const leaseResponse = z.object({
	lease_id: z.string().min(1),
	lease_duration: z.number().nonnegative(),
	renewable: z.boolean(),
})
const authResponse = z.object({
	auth: z.object({
		client_token: z.string().min(1),
		lease_duration: z.number().positive(),
	}),
})
let db: Database | undefined
let address = ""
let token = process.env.BAO_TOKEN || ""

class ApiError extends Error {
	constructor(
		readonly status: number,
		message: string,
	) {
		super(message)
	}
}

function state() {
	if (db) return db
	const directory = join(homedir(), ".buapedb")
	mkdirSync(directory, { recursive: true, mode: 0o700 })
	const directoryInfo = lstatSync(directory)
	if (
		!directoryInfo.isDirectory() ||
		directoryInfo.uid !== process.getuid?.()
	) {
		throw new Error(`${directory} must be a directory owned by you`)
	}
	chmodSync(directory, 0o700)
	const path = join(directory, "state.sqlite")
	const fd = openSync(
		path,
		constants.O_CREAT | constants.O_RDWR | constants.O_NOFOLLOW,
		0o600,
	)
	try {
		if (fstatSync(fd).uid !== process.getuid?.())
			throw new Error(`${path} must be owned by you`)
		fchmodSync(fd, 0o600)
	} finally {
		closeSync(fd)
	}
	db = new Database(path, { strict: true })
	db.exec(`
		PRAGMA busy_timeout = 5000;
		PRAGMA secure_delete = ON;
		CREATE TABLE IF NOT EXISTS sessions (
			address TEXT PRIMARY KEY, token TEXT NOT NULL, expires_at INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS leases (
			address TEXT NOT NULL, id TEXT NOT NULL, database TEXT NOT NULL,
			issued_at INTEGER NOT NULL, expires_at INTEGER,
			PRIMARY KEY (address, id)
		);
	`)
	const schema = z
		.object({ user_version: z.number() })
		.parse(db.query("PRAGMA user_version").get())
	if (schema.user_version === 0) {
		let legacy = ""
		try {
			legacy = readFileSync(join(directory, "leases"), "utf8")
		} catch (error) {
			if (
				!(error instanceof Error && "code" in error && error.code === "ENOENT")
			)
				throw error
		}
		const connection = db
		connection.transaction(() => {
			for (const line of legacy.split("\n").filter(Boolean)) {
				const old = z
					.object({ lease_id: z.string(), issued_at: z.number() })
					.parse(JSON.parse(line))
				const database = old.lease_id.split("/")[0]?.replace(/-db$/, "")
				if (!database) throw new Error("Invalid locally tracked lease")
				connection
					.query("INSERT OR IGNORE INTO leases VALUES (?, ?, ?, ?, NULL)")
					.run(address, old.lease_id, database, old.issued_at * 1000)
			}
			connection.exec("PRAGMA user_version = 1")
		})()
	}
	return db
}

async function api(
	path: string,
	method = "GET",
	body?: unknown,
	credential: string | null = token || null,
) {
	const headers = new Headers({ Accept: "application/json" })
	if (credential) headers.set("X-Vault-Token", credential)
	if (body !== undefined) headers.set("Content-Type", "application/json")
	const response = await fetch(`${address}/v1/${path}`, {
		method,
		headers,
		body: body === undefined ? undefined : JSON.stringify(body),
		redirect: "error",
		signal: AbortSignal.timeout(30_000),
	})
	const text = await response.text()
	if (!response.ok) {
		let detail = response.statusText
		try {
			detail = z
				.object({ errors: z.array(z.string()) })
				.parse(JSON.parse(text))
				.errors.join("; ")
		} catch {
			// A proxy's HTML error page is not a useful CLI diagnostic.
		}
		if (credential) detail = detail.replaceAll(credential, "[redacted]")
		throw new ApiError(
			response.status,
			`Request failed (${response.status}): ${detail.slice(0, 500)}`,
		)
	}
	return text ? (JSON.parse(text) as unknown) : null
}

async function authenticate() {
	if (!token) {
		const cached = z
			.object({ token: z.string(), expires_at: z.number() })
			.nullable()
			.parse(
				state()
					.query("SELECT token, expires_at FROM sessions WHERE address = ?")
					.get(address),
			)
		if (cached && cached.expires_at > Date.now() + 15_000) token = cached.token
	}
	if (token) {
		try {
			const lookup = z
				.object({ data: z.object({ ttl: z.number() }) })
				.parse(await api("auth/token/lookup-self"))
			if (lookup.data.ttl === 0 || lookup.data.ttl > 15) return
		} catch (error) {
			if (!(error instanceof ApiError && [400, 403].includes(error.status)))
				throw error
		}
		if (process.env.BAO_TOKEN)
			throw new Error("BAO_TOKEN is invalid or expiring; unset it to sign in")
	}
	token = ""
	state().query("DELETE FROM sessions WHERE address = ?").run(address)
	console.error("Signing in…")
	const clientNonce = randomBytes(32).toString("base64url")
	let expectedState = ""
	let completing = false
	const completed = Promise.withResolvers<z.infer<typeof authResponse>>()
	const server = Bun.serve({
		hostname: "127.0.0.1",
		port: 8250,
		async fetch(request) {
			const url = new URL(request.url)
			if (
				request.method !== "GET" ||
				url.pathname !== "/oidc/callback" ||
				request.headers.get("host") !== "localhost:8250"
			) {
				return new Response("Not found", { status: 404 })
			}
			const incomingState = url.searchParams.get("state") || ""
			if (
				!expectedState ||
				url.searchParams.getAll("state").length !== 1 ||
				Buffer.byteLength(incomingState) !== Buffer.byteLength(expectedState) ||
				!timingSafeEqual(Buffer.from(incomingState), Buffer.from(expectedState))
			) {
				return new Response("Invalid login state", { status: 400 })
			}
			if (completing)
				return new Response("Login already completing", { status: 409 })
			completing = true
			try {
				if (url.searchParams.has("error"))
					throw new Error("Sign-in was canceled or denied")
				if (
					url.searchParams.getAll("code").length !== 1 ||
					!url.searchParams.get("code")
				)
					throw new Error("Sign-in could not be completed")
				const query = new URLSearchParams({
					state: incomingState,
					code: url.searchParams.get("code") || "",
					client_nonce: clientNonce,
				})
				const result = authResponse.parse(
					await api(`auth/oidc/oidc/callback?${query}`, "GET", undefined, null),
				)
				completed.resolve(result)
				return new Response("Signed in. You can close this tab.", {
					headers: {
						"Cache-Control": "no-store",
						"Referrer-Policy": "no-referrer",
						"X-Content-Type-Options": "nosniff",
					},
				})
			} catch (error) {
				completed.reject(error)
				return new Response(
					"Login failed. See buapedb in your terminal for details.",
					{ status: 400, headers: { "Cache-Control": "no-store" } },
				)
			}
		},
	})
	const timeout = setTimeout(
		() => completed.reject(new Error("Sign-in timed out; run buapedb again")),
		300_000,
	)
	try {
		const result = z.object({ data: z.object({ auth_url: z.url() }) }).parse(
			await api(
				"auth/oidc/oidc/auth_url",
				"POST",
				{
					role: "default",
					redirect_uri: "http://localhost:8250/oidc/callback",
					client_nonce: clientNonce,
				},
				null,
			),
		)
		const url = new URL(result.data.auth_url)
		if (
			url.protocol !== "https:" &&
			!(
				url.protocol === "http:" &&
				["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
			)
		)
			throw new Error("Could not start sign-in securely")
		expectedState = url.searchParams.get("state") || ""
		if (!expectedState) throw new Error("Could not start sign-in")
		if (process.env.BROWSER === "none") console.error(url.href)
		else {
			const browser =
				process.env.BROWSER ||
				(process.platform === "darwin" ? "/usr/bin/open" : "/usr/bin/xdg-open")
			try {
				const child = Bun.spawn([browser, url.href], {
					stdout: "ignore",
					stderr: "ignore",
				})
				child.unref()
				void child.exited.then((code) => {
					if (code) console.error(`Open this link to sign in:\n${url.href}`)
				})
			} catch {
				console.error(`Open this link to sign in:\n${url.href}`)
			}
		}
		const login = await completed.promise
		token = login.auth.client_token
		state()
			.query(
				"INSERT INTO sessions VALUES (?, ?, ?) ON CONFLICT(address) DO UPDATE SET token = excluded.token, expires_at = excluded.expires_at",
			)
			.run(address, token, Date.now() + login.auth.lease_duration * 1000)
	} finally {
		clearTimeout(timeout)
		await server.stop()
	}
}

async function discover() {
	const mounts = z
		.object({
			data: z.record(
				z.string(),
				z.object({ type: z.string(), description: z.string().default("") }),
			),
		})
		.parse(await api("sys/mounts"))
	const entries = []
	for (const [mount, info] of Object.entries(mounts.data)) {
		if (info.type !== "database") continue
		let roles: string[]
		try {
			roles = z
				.object({ data: z.object({ keys: z.array(z.string()) }) })
				.parse(await api(`${mount}roles?list=true`)).data.keys
		} catch (error) {
			if (error instanceof ApiError && error.status === 403) continue
			throw error
		}
		for (const role of roles)
			entries.push({
				database: mount.replace(/\/$/, "").replace(/-db$/, ""),
				role,
				url: info.description,
				path: `${mount}creds/${encodeURIComponent(role)}`,
			})
	}
	if (!entries.length) throw new Error("No databases available")
	const capabilities = z
		.object({ data: z.record(z.string(), z.array(z.string())) })
		.parse(
			await api("sys/capabilities-self", "POST", {
				paths: entries.map((entry) => entry.path),
			}),
		)
	const allowed = entries.filter((entry) =>
		(
			capabilities.data[entry.path] ||
			capabilities.data.capabilities ||
			[]
		).some((capability) => capability === "read" || capability === "root"),
	)
	if (!allowed.length)
		throw new Error("You do not have access to any databases")
	return allowed.sort(
		(a, b) =>
			a.database.localeCompare(b.database) || a.role.localeCompare(b.role),
	)
}

async function main() {
	const { values, positionals } = parseArgs({
		args: process.argv.slice(2),
		allowPositionals: true,
		options: {
			write: { type: "boolean", short: "w" },
			renew: { type: "string" },
			end: { type: "boolean" },
			json: { type: "boolean" },
			help: { type: "boolean", short: "h" },
			version: { type: "boolean", short: "v" },
		},
	})
	if (values.version) {
		console.log(`buapedb ${version}`)
		return
	}
	if (values.help || (!positionals.length && !values.renew && !values.end)) {
		console.log(
			`Usage:\n  buapedb <database> [--write] [--json]\n  buapedb list [--json]\n  buapedb <database> --renew <id>\n  buapedb <database> --end`,
		)
		return
	}
	if (
		positionals.length > 1 ||
		(values.renew && values.end) ||
		(values.write && (values.renew || values.end || positionals[0] === "list"))
	)
		throw new Error("Invalid arguments; see buapedb --help")
	const url = new URL(process.env.BAO_ADDR || "https://bao.b1.buape.com")
	if (
		url.username ||
		url.password ||
		url.search ||
		url.hash ||
		(url.protocol !== "https:" &&
			!(
				url.protocol === "http:" &&
				["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
			))
	)
		throw new Error(
			"BAO_ADDR must be an HTTPS URL (HTTP is allowed only on loopback)",
		)
	address = url.href.replace(/\/+$/, "")
	const requested = positionals[0]
	const database = requested?.replace(/-(ro|rw)$/, "").replace(/-db$/, "")

	if (values.end || values.renew) {
		const leases = leaseRow
			.array()
			.parse(
				state()
					.query("SELECT * FROM leases WHERE address = ? ORDER BY issued_at")
					.all(address),
			)
			.filter((lease) => !database || lease.database === database)
		if (values.renew) {
			const id = values.renew
			const matches = leases.filter(
				(lease) => lease.id === id || lease.id.split("/").at(-1) === id,
			)
			const target = matches[0]
			if (matches.length !== 1 || !target)
				throw new Error(
					"Lease is not uniquely tracked on this machine for that database",
				)
			await authenticate()
			const renewed = leaseResponse.parse(
				await api("sys/leases/renew", "POST", { lease_id: target.id }),
			)
			const expires = Date.now() + renewed.lease_duration * 1000
			state()
				.query("UPDATE leases SET expires_at = ? WHERE address = ? AND id = ?")
				.run(expires, address, target.id)
			console.log(
				values.json
					? JSON.stringify({
							lease_id: target.id,
							expires_at: new Date(expires).toISOString(),
						})
					: `Renewed until ${new Date(expires).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "long" })}`,
			)
			return
		}
		if (!leases.length) {
			console.log(
				values.json ? '{"ended":0}' : "No locally tracked credentials to end",
			)
			return
		}
		await authenticate()
		let ended = 0
		for (const lease of leases) {
			try {
				await api("sys/leases/revoke", "POST", { lease_id: lease.id })
				state()
					.query("DELETE FROM leases WHERE address = ? AND id = ?")
					.run(address, lease.id)
				ended++
				if (!values.json) console.log(`Ended ${lease.id}`)
			} catch (error) {
				console.error(
					`Could not end ${lease.id}; retained for retry: ${error instanceof Error ? error.message : "unknown error"}`,
				)
				process.exitCode = 1
			}
		}
		if (values.json)
			console.log(JSON.stringify({ ended, failed: leases.length - ended }))
		return
	}

	await authenticate()
	const entries = await discover()
	if (requested === "list") {
		if (values.json) {
			console.log(JSON.stringify(entries))
			return
		}
		for (const name of new Set(entries.map((entry) => entry.database)))
			console.log(
				`${name}: ${entries
					.filter((entry) => entry.database === name)
					.map((entry) => entry.role)
					.join(", ")}`,
			)
		return
	}
	if (!requested || !database)
		throw new Error("Choose a database; see buapedb list")
	const role = `${database}-${values.write ? "rw" : "ro"}`
	const matches = entries.filter(
		(entry) =>
			(entry.database === database && entry.role === role) ||
			entry.role === role,
	)
	const target = matches[0]
	if (matches.length !== 1 || !target)
		throw new Error(
			`No ${values.write ? "read-write" : "read-only"} access for '${database}'; see buapedb list`,
		)
	let connection: URL
	try {
		connection = new URL(target.url)
		if (
			!["postgres:", "postgresql:"].includes(connection.protocol) ||
			!connection.hostname ||
			!connection.pathname.replace(/^\//, "") ||
			connection.username ||
			connection.password ||
			connection.hash
		)
			throw new Error("Invalid connection URL")
	} catch {
		throw new Error(`Connection details are missing for '${target.database}'`)
	}
	const credentials = leaseResponse
		.extend({
			data: z.object({
				username: z.string().min(1),
				password: z.string().min(1),
			}),
		})
		.parse(await api(target.path))
	const expires = Date.now() + credentials.lease_duration * 1000
	connection.username = credentials.data.username
	connection.password = credentials.data.password
	try {
		state()
			.query("INSERT INTO leases VALUES (?, ?, ?, ?, ?)")
			.run(address, credentials.lease_id, target.database, Date.now(), expires)
		if (values.json) {
			console.log(
				JSON.stringify({
					username: credentials.data.username,
					password: credentials.data.password,
					url: connection.href,
					lease_id: credentials.lease_id,
					expires_at: new Date(expires).toISOString(),
					renewable: credentials.renewable,
				}),
			)
			return
		}
	} catch (error) {
		try {
			await api("sys/leases/revoke", "POST", { lease_id: credentials.lease_id })
			state()
				.query("DELETE FROM leases WHERE address = ? AND id = ?")
				.run(address, credentials.lease_id)
		} catch {
			console.error(
				`Cleanup could not revoke ${credentials.lease_id}; end it with buapedb ${target.database} --end`,
			)
		}
		throw error
	}
	let copied = false
	try {
		const command =
			process.platform === "darwin"
				? ["/usr/bin/pbcopy"]
				: process.env.WAYLAND_DISPLAY && Bun.which("wl-copy")
					? ["wl-copy"]
					: process.env.DISPLAY && Bun.which("xclip")
						? ["xclip", "-selection", "clipboard"]
						: null
		if (command) {
			const copy = Bun.spawn(command, {
				stdin: new Blob([connection.href]),
				stdout: "ignore",
				stderr: "ignore",
				signal: AbortSignal.timeout(5000),
			})
			copied = (await copy.exited) === 0
		}
	} catch {
		// A missing or unavailable clipboard must not hide the credentials.
	}
	console.log(`  username: ${credentials.data.username}`)
	console.log(`  password: ${copied ? "***" : credentials.data.password}`)
	console.log(
		copied
			? "  url:      copied to clipboard (paste in your database tool)"
			: `  url:      ${connection.href}`,
	)
	console.log(
		`  expires:  ${new Date(expires).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "long" })}`,
	)
	if (credentials.renewable)
		console.log(
			`  renew:    buapedb ${target.database} --renew ${credentials.lease_id}`,
		)
	console.log(`  end:      buapedb ${target.database} --end`)
}

try {
	await main()
} catch (error) {
	let message =
		error instanceof z.ZodError
			? "Invalid server response or local state"
			: error instanceof Error
				? error.message
				: "Unknown error"
	if (token) message = message.replaceAll(token, "[redacted]")
	console.error(`buapedb: ${message}`)
	process.exitCode = 1
} finally {
	db?.close()
}
